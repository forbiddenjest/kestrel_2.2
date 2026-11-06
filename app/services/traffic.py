"""Monthly transfer accounting, caps and auto-suspend.

Raw counters come from libvirt's interfaceStats for the guest's tap device, already
from the guest's point of view (rx = inbound to the guest). They restart from zero
whenever QEMU restarts, so every sample carries an "epoch" (cluster + libvirt domain
id); a new epoch means the counters started again from zero.
"""
from datetime import datetime, timedelta
from app.models import AuditLog, Job, Machine, TrafficDaily, utcnow

GB = 1024 ** 3
SPEED_MAX_MBPS = 100_000
BANDWIDTH_MAX_GB = 10_000_000
# Never suspend for bandwidth while one of these is in progress; it would race the job.
NO_SUSPEND_STATES = {"suspended", "deleting", "provisioning", "rebuilding", "transferring", "failed"}


def period(now: datetime | None = None) -> str:
    return (now or utcnow()).strftime("%Y-%m")


def counter_delta(current: int, last: int) -> int:
    """Bytes since the previous sample of the same counter; a counter that went
    backwards was reset, so everything it shows now is new traffic."""
    current, last = max(0, int(current)), max(0, int(last))
    return current - last if current >= last else current


def _roll_period(machine, now):
    if machine.traffic_period != period(now):
        machine.traffic_period = period(now)
        machine.traffic_rx_bytes = 0
        machine.traffic_tx_bytes = 0


def record_traffic(db, machine: Machine, rx_counter: int, tx_counter: int, now: datetime | None = None, epoch: str | None = None) -> bool:
    """Add the delta since the last sample. Returns True when the machine was just suspended."""
    now = now or utcnow()
    _roll_period(machine, now)
    if epoch is not None and epoch != (machine.traffic_epoch or ""):
        last_rx = last_tx = 0  # new QEMU process: its counters began at zero
        machine.traffic_epoch = epoch
    else:
        last_rx, last_tx = machine.traffic_last_rx or 0, machine.traffic_last_tx or 0
    rx = counter_delta(rx_counter, last_rx)
    tx = counter_delta(tx_counter, last_tx)
    machine.traffic_last_rx, machine.traffic_last_tx = max(0, int(rx_counter)), max(0, int(tx_counter))
    if rx or tx:
        machine.traffic_rx_bytes = int(machine.traffic_rx_bytes or 0) + rx
        machine.traffic_tx_bytes = int(machine.traffic_tx_bytes or 0) + tx
        day = now.strftime("%Y-%m-%d")
        row = db.query(TrafficDaily).filter(TrafficDaily.machine_id == machine.id, TrafficDaily.day == day).first()
        if row is None:
            row = TrafficDaily(machine_id=machine.id, day=day, rx_bytes=0, tx_bytes=0)
            db.add(row)
            db.flush()
        row.rx_bytes = int(row.rx_bytes or 0) + rx
        row.tx_bytes = int(row.tx_bytes or 0) + tx
    return enforce_cap(db, machine)


def over_cap(machine: Machine) -> bool:
    return bool(machine.bandwidth_limit_gb) and machine.traffic_used_bytes() >= machine.bandwidth_limit_gb * GB


def enforce_cap(db, machine: Machine) -> bool:
    if not over_cap(machine) or machine.state in NO_SUSPEND_STATES:
        return False
    machine.set_power_state("suspended")
    machine.suspend_reason = "bandwidth"
    db.add(Job(kind="force-stop", machine_id=machine.id, state="queued"))
    db.add(AuditLog(action="machine.bandwidth_suspend", target=machine.id, result="ok"))
    return True


def reset_traffic(machine: Machine):
    """Administrator refresh: zero this month's usage and lift a bandwidth suspension.
    Raw counters (traffic_last_*) are kept so the next sample only adds new traffic."""
    machine.traffic_period = period()
    machine.traffic_rx_bytes = 0
    machine.traffic_tx_bytes = 0
    if machine.state == "suspended" and machine.suspend_reason == "bandwidth":
        machine.set_power_state("stopped")
        machine.suspend_reason = ""


def rollover(db, now: datetime | None = None):
    """New month: reset counters, and lift suspensions that were only for the cap."""
    now = now or utcnow()
    current = period(now)
    for machine in db.query(Machine).filter(Machine.traffic_period != current, Machine.traffic_period != "").all():
        machine.traffic_period = current
        machine.traffic_rx_bytes = machine.traffic_tx_bytes = 0
        if machine.state == "suspended" and machine.suspend_reason == "bandwidth":
            machine.set_power_state("stopped")
            machine.suspend_reason = ""
            db.add(AuditLog(action="machine.bandwidth_restore", target=machine.id, result="ok"))
    cutoff = (now - timedelta(days=400)).strftime("%Y-%m-%d")
    db.query(TrafficDaily).filter(TrafficDaily.day < cutoff).delete(synchronize_session=False)


def daily_series(db, machine_id: str, days: int = 30, now: datetime | None = None) -> list[dict]:
    now = now or utcnow()
    start = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rows = {r.day: r for r in db.query(TrafficDaily).filter(TrafficDaily.machine_id == machine_id, TrafficDaily.day >= start).all()}
    series = []
    for offset in range(days - 1, -1, -1):
        day = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
        row = rows.get(day)
        series.append({"day": day, "rx": int(row.rx_bytes) if row else 0, "tx": int(row.tx_bytes) if row else 0})
    return series


def human_bytes(value) -> str:
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


def human_speed(mbps: int) -> str:
    if not mbps:
        return "Unlimited"
    return f"{mbps / 1000:g} Gbps" if mbps >= 1000 and mbps % 100 == 0 else f"{mbps} Mbps"
