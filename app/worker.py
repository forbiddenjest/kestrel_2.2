"""Database-backed queue worker. Only a single service instance should run."""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import timedelta
from sqlalchemy import update
from app.config import settings
from app.db import SessionLocal
from app.models import AuditLog, Cluster, ClusterIP, Image, Job, LoginAttempt, Machine, MetricSample, Session as LoginSession, utcnow
from app.security import decrypt_node_key, encrypt_node_key
from app.services import libvirt as hv
from app.services.clusters import cluster_rules, secondary_private_ips
from app.services.libvirt import domain_status, power_action
from app.services.machines import allocate_ip, guest_gateway
from app.services.metrics import collect_machine_metrics, purge_metrics
from app.services.traffic import record_traffic, rollover

log = logging.getLogger("kestrel.worker")
JOB_TIMEOUT = 1800
# A node-to-node transfer copies a whole disk; give it far longer than ordinary jobs.
JOB_TIMEOUTS = {"transfer": 6 * 3600, "sync-image": 3600, "provision": 3600, "rebuild": 3600}
MAX_JOB_TIMEOUT = max([JOB_TIMEOUT, *JOB_TIMEOUTS.values()])
# Jobs this process is executing right now; never requeued as "stale".
_RUNNING: set[int] = set()
# Rule pushes for one node are serialized and computed inside the lock, so an older
# snapshot can never overwrite a newer one.
_RULE_LOCKS: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)


def seal(data: dict) -> str:
    """Job payloads may carry a guest password; keep them encrypted at rest."""
    return json.dumps({"sealed": encrypt_node_key(json.dumps(data))})


def unseal(payload: str) -> dict:
    raw = json.loads(payload or "{}")
    return json.loads(decrypt_node_key(raw["sealed"])) if "sealed" in raw else raw


def job_timeout(kind: str) -> int:
    return JOB_TIMEOUTS.get(kind, JOB_TIMEOUT)


def machine_spec(machine) -> dict:
    ip = machine.cluster_ip
    if not ip: raise RuntimeError("Machine has no assigned address")
    return {"vm_name": machine.vm_name, "hostname": machine.id, "vcpu": machine.vcpu, "memory_mb": machine.memory_mb,
            "disk_gb": machine.disk_gb, "image_id": machine.image_id, "guest_ip": ip.guest_ipv4,
            "guest_subnet": machine.cluster.guest_subnet, "gateway": guest_gateway(machine.cluster.guest_subnet),
            "iso_image_id": machine.iso_image_id, "boot_device": machine.boot_device,
            "speed_in_mbps": machine.speed_in_mbps, "speed_out_mbps": machine.speed_out_mbps}


async def push_cluster_rules(cluster_id: int):
    """Compute the full rule set from committed state in a fresh session, then apply it."""
    async with _RULE_LOCKS[int(cluster_id)]:
        db = SessionLocal()
        try:
            cluster = db.get(Cluster, int(cluster_id))
            if not cluster:
                return
            rules, private_ips = cluster_rules(db, cluster), secondary_private_ips(db, cluster)
        finally:
            db.close()
        await hv.push_rules(cluster, rules, private_ips)


def _queue_rule_push(db, cluster_id: int, actor_id=None):
    db.add(Job(kind="push-rules", actor_id=actor_id, state="queued", payload=json.dumps({"cluster_id": int(cluster_id)})))


async def _execute(db, job, machine, data):
    kind = job.kind
    if kind in {"start", "stop", "restart", "force-stop"} and machine:
        db.refresh(machine)
        # Suspended in the meantime: never boot it; a force-stop is still honoured.
        if machine.state == "suspended" and kind != "force-stop":
            return "Skipped: machine is suspended"
        result = await asyncio.to_thread(power_action, machine.cluster, machine.vm_name, kind)
        db.refresh(machine)  # an admin may have suspended it while the action ran
        if machine.state != "suspended":
            machine.set_power_state(result)
        return "Machine action completed"
    if kind in {"provision", "rebuild"} and machine:
        if kind == "rebuild":
            machine.image_id = int(data["image_id"]); db.flush(); db.refresh(machine)
        if not machine.image or machine.image.kind != "cloud" or not machine.image.active:
            raise RuntimeError("Machine image is not an active cloud image")
        action = hv.provision if kind == "provision" else hv.rebuild
        machine.guest_host_key = await action(machine.cluster, machine_spec(machine), data["password"])
        machine.set_power_state("running")
        cluster_id = machine.cluster_id
        db.commit()  # the guest exists and runs: never mark it failed after this point
        try:
            await push_cluster_rules(cluster_id)
        except Exception:
            _queue_rule_push(db, cluster_id, job.actor_id)
            return ("Machine built" if kind == "provision" else "Machine rebuilt") + "; node rules will be retried"
        return "Machine built" if kind == "provision" else "Machine rebuilt"
    if kind == "delete" and machine:
        cluster_id, vm_name, machine_id = machine.cluster_id, machine.vm_name, machine.id
        await hv.delete(machine.cluster, vm_name)
        db.query(ClusterIP).filter(ClusterIP.machine_id == machine_id).update({ClusterIP.machine_id: None}, synchronize_session=False)
        job.machine_id = None
        db.delete(machine)
        db.commit()  # the guest is gone: record that before anything else can fail
        try:
            await push_cluster_rules(cluster_id)
        except Exception:
            log.warning("Rule push after deleting %s failed; queued a retry", machine_id)
            _queue_rule_push(db, cluster_id, job.actor_id)
        return f"Machine {machine_id} deleted"
    if kind == "password" and machine:
        await asyncio.to_thread(hv.set_guest_password, machine.cluster, machine.vm_name, data["password"])
        return "Guest password updated"
    if kind == "media" and machine:
        await asyncio.to_thread(hv.set_media, machine.cluster, machine_spec(machine))
        return "Media updated"
    if kind == "firewall" and machine:
        await push_cluster_rules(machine.cluster_id)
        return "Firewall rules applied"
    if kind == "repin-host-key" and machine:
        if not machine.cluster_ip: raise RuntimeError("Machine has no assigned address")
        machine.guest_host_key = await hv.fetch_guest_host_key(machine.cluster, machine.cluster_ip.guest_ipv4)
        return "Guest host key re-pinned"
    if kind == "resize" and machine:
        # Specs were written (quota-checked) by the request; apply them to the hypervisor.
        grow = int(data.get("grow_disk_gb") or 0)
        if grow:
            await hv.grow_disk(machine.cluster, machine.vm_name, grow)
            data["disk_grown"] = True  # a later failure must not pretend the disk is small again
        await asyncio.to_thread(hv.redefine, machine.cluster, machine_spec(machine))
        return "Machine resources updated (vCPU/memory apply on next boot if it was running)"
    if kind == "transfer" and machine:
        return await _transfer(db, job, machine, data)
    if kind == "push-rules":
        await push_cluster_rules(int(data["cluster_id"]))
        return "Node rules applied"
    if kind == "sync-image":
        image, cluster = db.get(Image, int(data["image_id"])), db.get(Cluster, int(data["cluster_id"]))
        if not image or not cluster:
            return "Skipped: image or cluster no longer exists"
        await hv.sync_image(cluster, image)
        return "Image synced"
    raise RuntimeError("Unsupported operation")


async def _transfer(db, job, machine, data):
    """Move a machine to another node with a new address, keeping its disk byte-for-byte.

    1. stop + flatten + stream + SHA-256 verify (source untouched)
    2. swap address and cluster in one short committed transaction
    3. new seed + define + boot on the target, rules on both nodes
    4. only then delete the source copy. Any failure in 1-3 reverts to the source."""
    db.refresh(machine)
    if machine.state not in {"running", "stopped"}:
        raise RuntimeError(f"Machine is {machine.state}; transfer cancelled")
    source = machine.cluster
    source_id = source.id
    target = db.get(Cluster, int(data["target_cluster_id"]))
    if not target or target.state != "active" or target.id == source_id:
        raise RuntimeError("Target cluster is not active")
    machine.set_power_state("transferring"); db.commit()
    try:
        await hv.copy_disk(source, target, machine.vm_name)
    except BaseException:
        await _discard_quietly(target, machine.vm_name)
        raise
    old_ip = db.query(ClusterIP).filter(ClusterIP.machine_id == machine.id).first()
    old_ip_id = old_ip.id if old_ip else None
    try:
        if old_ip: old_ip.machine_id = None
        db.flush()
        allocate_ip(db, target.id, machine.id)
        machine.cluster_id = target.id
        machine.traffic_epoch = ""  # new QEMU process on another node
        db.commit(); db.refresh(machine)
        machine.guest_host_key = await hv.boot_transferred(target, machine_spec(machine))
        db.commit()
        await push_cluster_rules(target.id)
    except BaseException:
        db.rollback()
        machine = db.get(Machine, machine.id)
        db.query(ClusterIP).filter(ClusterIP.machine_id == machine.id).update({ClusterIP.machine_id: None}, synchronize_session=False)
        db.flush()
        if old_ip_id:
            db.query(ClusterIP).filter(ClusterIP.id == old_ip_id, ClusterIP.machine_id.is_(None)).update({ClusterIP.machine_id: machine.id}, synchronize_session=False)
        machine.cluster_id = source_id; machine.set_power_state("stopped"); db.commit()
        await _discard_quietly(target, machine.vm_name)
        raise
    machine.set_power_state("running"); db.commit()
    try:
        await hv.delete(source, machine.vm_name)
        await push_cluster_rules(source_id)
    except Exception:
        db.add(AuditLog(action="machine.transfer_cleanup", target=machine.id, result="failed"))
        _queue_rule_push(db, source_id, job.actor_id)
    return f"Machine moved from {source.name} to {target.name}"


async def _discard_quietly(cluster, vm_name):
    try:
        await hv.discard_copy(cluster, vm_name)
    except Exception:
        log.warning("Could not remove the partial copy of %s on %s; remove it manually", vm_name, cluster.name)


def _record_failure(db, job, data, exc):
    job.state = "failed"; job.payload = "{}"
    job.result = (str(exc) or type(exc).__name__)[:500]
    failed_machine = db.get(Machine, job.machine_id) if job.machine_id else None
    if failed_machine and job.kind in {"provision", "rebuild"}:
        failed_machine.set_power_state("failed")
    elif failed_machine and job.kind == "resize" and data.get("previous"):
        # Hypervisor never got the new size: put the record back so quotas stay true.
        for key, value in data["previous"].items():
            if key == "disk_gb" and data.get("disk_grown"):
                continue  # the disk really is larger now
            if key in {"vcpu", "memory_mb", "disk_gb", "speed_in_mbps", "speed_out_mbps"}:
                setattr(failed_machine, key, int(value))
    elif failed_machine and job.kind == "transfer" and failed_machine.state == "transferring":
        failed_machine.set_power_state("stopped")
    elif failed_machine and job.kind in {"start", "stop", "restart", "force-stop"} and failed_machine.state != "suspended":
        failed_machine.set_power_state("unknown")
    elif failed_machine and job.kind == "delete" and failed_machine.state == "deleting":
        pass  # stays "deleting"; an administrator can retry the delete
    db.add(AuditLog(actor_id=job.actor_id, action=f"job.{job.kind}", target=job.machine_id or str(job.id), result="failed"))


async def _run_job(job_id: int):
    db = SessionLocal()
    job_data: dict = {}
    _RUNNING.add(job_id)
    try:
        job = db.get(Job, job_id)
        if not job:
            return
        machine = db.get(Machine, job.machine_id) if job.machine_id else None
        try:
            job_data = unseal(job.payload)
            result = await asyncio.wait_for(_execute(db, job, machine, job_data), timeout=job_timeout(job.kind))
        except (Exception, asyncio.CancelledError) as exc:
            db.rollback()
            job = db.get(Job, job_id)
            if job:
                _record_failure(db, job, job_data, RuntimeError("Timed out") if isinstance(exc, asyncio.TimeoutError) else exc)
                job.updated_at = utcnow()
            db.commit()
            if isinstance(exc, asyncio.CancelledError):
                raise
            return
        job = db.get(Job, job_id)
        job.result = result
        job.state = "complete"; job.payload = "{}"; job.updated_at = utcnow()
        db.add(AuditLog(actor_id=job.actor_id, action=f"job.{job.kind}", target=job.machine_id or str(job_id), result="ok"))
        db.commit()
    finally:
        _RUNNING.discard(job_id)
        db.close()


def _claim_next(db, busy_machines: set):
    """Claim the oldest queued job whose machine has no other job in flight."""
    now = utcnow()
    in_flight = db.query(Job.machine_id).filter(Job.state == "running", Job.machine_id.isnot(None))
    query = db.query(Job.id, Job.machine_id).filter(Job.state == "queued").filter(
        (Job.machine_id.is_(None)) | (Job.machine_id.notin_(in_flight)))
    if busy_machines:
        query = query.filter((Job.machine_id.is_(None)) | (Job.machine_id.notin_(busy_machines)))
    candidate = query.order_by(Job.created_at, Job.id).first()
    if not candidate:
        return None, None
    job_id, machine_id = candidate
    changed = db.execute(update(Job).where(Job.id == job_id, Job.state == "queued").values(state="running", updated_at=now)).rowcount
    db.commit()
    return (job_id, machine_id) if changed == 1 else (None, None)


def recover_interrupted(db):
    """Worker start: anything still 'running' was interrupted by a restart or crash."""
    db.query(Job).filter(Job.state == "running").update({Job.state: "queued", Job.updated_at: utcnow()}, synchronize_session=False)


def _requeue_stale(db):
    cutoff = utcnow() - timedelta(seconds=MAX_JOB_TIMEOUT + 60)
    query = db.query(Job).filter(Job.state == "running", Job.updated_at < cutoff)
    if _RUNNING:
        query = query.filter(Job.id.notin_(list(_RUNNING)))
    query.update({Job.state: "queued", Job.updated_at: utcnow()}, synchronize_session=False)


def _by_cluster(machines):
    groups: dict[int, list] = {}
    for machine in machines:
        groups.setdefault(machine.cluster_id, []).append(machine)
    return groups


def _collect_cluster(cluster, items):
    """One libvirt connection per node per cycle instead of one per machine."""
    results = {}
    try:
        conn = hv.open_connection(cluster)
    except Exception:
        log.warning("Metrics: node %s unreachable", cluster.name)
        return results
    try:
        for machine, previous in items:
            try:
                results[machine.id] = collect_machine_metrics(cluster, machine.vm_name, previous, connection=conn)
            except Exception:
                log.debug("Metrics: no sample for %s", machine.id)
    finally:
        conn.close()
    return results


async def _poll_metrics():
    db = SessionLocal()
    try:
        running = db.query(Machine).filter(Machine.state == "running").all()
        for machines in _by_cluster(running).values():
            items = [(m, db.query(MetricSample).filter(MetricSample.machine_id == m.id).order_by(MetricSample.sampled_at.desc()).first()) for m in machines]
            results = await asyncio.to_thread(_collect_cluster, machines[0].cluster, items)
            by_id = {m.id: m for m in machines}
            for machine_id, values in results.items():
                if values:
                    epoch = values.pop("epoch", None)
                    db.add(MetricSample(machine_id=machine_id, **values))
                    machine = by_id[machine_id]
                    db.refresh(machine)
                    if machine.state == "running":
                        record_traffic(db, machine, values["network_rx_bytes"], values["network_tx_bytes"], epoch=epoch)
        rollover(db)
        db.commit()
        purge_metrics(db)
        db.commit()
    finally:
        db.close()


def housekeeping(db):
    """Expired sessions, old sign-in attempts and audit rows beyond retention."""
    now = utcnow()
    db.query(LoginSession).filter(LoginSession.expires_at < now).delete(synchronize_session=False)
    db.query(LoginAttempt).filter(LoginAttempt.attempted_at < now - timedelta(days=2)).delete(synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.created_at < now - timedelta(days=settings.audit_retention_days)).delete(synchronize_session=False)
    db.query(Job).filter(Job.state.in_(["complete", "failed"]), Job.updated_at < now - timedelta(days=settings.audit_retention_days)).delete(synchronize_session=False)


async def _housekeeping():
    db = SessionLocal()
    try:
        housekeeping(db); db.commit()
    finally:
        db.close()


TRANSITION_GRACE = 180  # seconds a guest gets to finish an ACPI shutdown/reboot


def _statuses(cluster, machines):
    try:
        conn = hv.open_connection(cluster)
    except Exception:
        log.warning("Reconcile: node %s unreachable", cluster.name)
        return {}
    try:
        return {m.id: domain_status(cluster, m.vm_name, conn=conn) for m in machines}
    finally:
        conn.close()


def next_power_state(stored: str, observed: str, seconds_since_request: float | None) -> str | None:
    """Decide what reconcile should write. None = leave the row alone.

    stopping: only `stopped` confirms it; while the guest is still running inside the
    grace window we keep `stopping` so the UI does not flap back to running.
    restarting: the domain stays running across a reboot, so running confirms it.
    crashed: shown as stopped (the crash itself is written to the activity log).
    """
    if observed == "crashed":
        observed = "stopped"
    if observed not in {"running", "stopped"} or stored == "suspended":
        return None
    if stored == "stopping" and observed == "running":
        if seconds_since_request is not None and seconds_since_request < TRANSITION_GRACE:
            return None
        return "running"  # guest ignored ACPI shutdown; show the truth
    if stored in {"running", "stopped", "starting", "stopping", "restarting", "unknown"} and stored != observed:
        return observed
    return None


async def _reconcile():
    db = SessionLocal()
    try:
        machines = db.query(Machine).filter(Machine.state.notin_(["provisioning", "rebuilding", "deleting", "failed", "suspended", "transferring"])).all()
        for group in _by_cluster(machines).values():
            statuses = await asyncio.to_thread(_statuses, group[0].cluster, group)
            for machine in group:
                try:
                    db.refresh(machine)
                    if machine.state in {"provisioning", "rebuilding", "deleting", "failed", "suspended", "transferring"}:
                        continue  # changed while we were asking the node
                    if db.query(Job.id).filter(Job.machine_id == machine.id, Job.state.in_(["queued", "running"])).first():
                        continue  # a job owns the state right now
                    last = db.query(Job.updated_at).filter(Job.machine_id == machine.id, Job.kind.in_(["stop", "restart"])).order_by(Job.updated_at.desc()).first()
                    since = None
                    if last and last[0]:
                        stamp = last[0] if last[0].tzinfo else last[0].replace(tzinfo=utcnow().tzinfo)
                        since = (utcnow() - stamp).total_seconds()
                    observed = statuses.get(machine.id, "unknown")
                    if observed == "crashed" and machine.state != "stopped":
                        db.add(AuditLog(action="machine.crashed", target=machine.id, result="failed"))
                    target = next_power_state(machine.state, observed, since)
                    if target:
                        machine.set_power_state(target)
                except Exception:
                    log.exception("Reconcile failed for %s", machine.id)
        db.commit()
    finally:
        db.close()


async def _periodic(fn, interval_fn):
    """Run fn forever on its own schedule so a slow pass never blocks job dispatch."""
    while True:
        try:
            await fn()
        except Exception:
            log.exception("Background task %s failed; retrying next cycle", getattr(fn, "__name__", fn))
        await asyncio.sleep(interval_fn())


async def worker_loop():
    """Dispatch up to worker_concurrency jobs at once, never two for the same machine."""
    db = SessionLocal()
    try:
        recover_interrupted(db); db.commit()
    finally:
        db.close()
    slots = asyncio.Semaphore(settings.worker_concurrency)
    busy_machines: set[str] = set()
    tasks: set[asyncio.Task] = set()
    background = [
        asyncio.create_task(_periodic(_poll_metrics, lambda: settings.metrics_interval_seconds)),
        asyncio.create_task(_periodic(_reconcile, lambda: 30)),
        asyncio.create_task(_periodic(_housekeeping, lambda: 3600)),
    ]

    async def run(job_id, machine_id):
        try:
            await _run_job(job_id)
        finally:
            if machine_id: busy_machines.discard(machine_id)
            slots.release()

    try:
        while True:
            await slots.acquire()
            db = SessionLocal()
            try:
                _requeue_stale(db); db.commit()
                job_id, machine_id = _claim_next(db, busy_machines)
            except Exception:
                job_id, machine_id = None, None
            finally:
                db.close()
            if job_id is None:
                slots.release()
                await asyncio.sleep(settings.worker_interval_seconds)
                continue
            if machine_id: busy_machines.add(machine_id)
            task = asyncio.create_task(run(job_id, machine_id))
            tasks.add(task); task.add_done_callback(tasks.discard)
    finally:
        for task in background: task.cancel()
        for task in tasks: task.cancel()
