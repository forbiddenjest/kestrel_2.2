"""Per-account quotas and per-node capacity admission control.

Every create / resize / owner change / transfer goes through check_owner_quota and
check_cluster_capacity *inside the same transaction that writes the change*:

* Postgres: the owner (and cluster) rows are locked FOR UPDATE first, so two concurrent
  requests for the same owner serialize and the second sees the first one's machine.
* SQLite: callers flush their write before calling, which takes SQLite's database-wide
  write lock; a concurrent writer blocks until commit, so the totals read here are exact.

0 means unlimited for every account limit.
"""
from fastapi import HTTPException
from sqlalchemy import func
from app.models import Cluster, ClusterIP, Machine, User

# Memory is never overcommitted: an OOM on the node kills guests. Keep headroom for the host.
HOST_RESERVED_MB = 1024
DELETED_STATES = ("deleting",)


def owner_usage(db, owner_id: int, exclude_machine: str | None = None) -> dict:
    query = db.query(func.count(Machine.id), func.coalesce(func.sum(Machine.vcpu), 0), func.coalesce(func.sum(Machine.memory_mb), 0), func.coalesce(func.sum(Machine.disk_gb), 0)).filter(Machine.owner_id == owner_id)
    ip_query = db.query(func.count(ClusterIP.id)).join(Machine, Machine.id == ClusterIP.machine_id).filter(Machine.owner_id == owner_id)
    if exclude_machine:
        query = query.filter(Machine.id != exclude_machine)
        ip_query = ip_query.filter(Machine.id != exclude_machine)
    vms, vcpu, memory, disk = query.one()
    return {"vms": int(vms), "vcpu": int(vcpu), "memory_mb": int(memory), "disk_gb": int(disk), "ips": int(ip_query.scalar() or 0)}


def _lock(db, model, key):
    row = db.query(model).filter(model.id == key).with_for_update().one_or_none()
    if row is None:
        raise HTTPException(422, f"{model.__name__} not found")
    return row


def check_owner_quota(db, owner_id: int, vcpu: int, memory_mb: int, disk_gb: int, ips: int = 1, exclude_machine: str | None = None):
    """Raise 422 if adding (or resizing exclude_machine to) these resources exceeds the owner's limits."""
    owner = _lock(db, User, owner_id)
    used = owner_usage(db, owner_id, exclude_machine)
    checks = [
        ("machines", owner.max_vms, used["vms"] + 1, ""),
        ("vCPU", owner.max_vcpu, used["vcpu"] + vcpu, ""),
        ("memory", owner.max_memory_mb, used["memory_mb"] + memory_mb, " MB"),
        ("disk", owner.max_disk_gb, used["disk_gb"] + disk_gb, " GB"),
        ("IPv4 addresses", owner.max_ips, used["ips"] + ips, ""),
    ]
    for label, limit, wanted, unit in checks:
        if limit and wanted > limit:
            raise HTTPException(422, f"Account limit reached for {label}: {wanted}{unit} requested, {limit}{unit} allowed")
    return owner


def check_cluster_capacity(db, cluster_id: int, memory_mb: int, disk_gb: int, exclude_machine: str | None = None):
    cluster = _lock(db, Cluster, cluster_id)
    query = db.query(func.coalesce(func.sum(Machine.memory_mb), 0), func.coalesce(func.sum(Machine.disk_gb), 0)).filter(Machine.cluster_id == cluster_id)
    if exclude_machine:
        query = query.filter(Machine.id != exclude_machine)
    mem_used, disk_used = (int(v) for v in query.one())
    if cluster.memory_capacity_mb:
        usable = max(0, cluster.memory_capacity_mb - HOST_RESERVED_MB)
        if mem_used + memory_mb > usable:
            raise HTTPException(409, f"{cluster.name} does not have enough free memory ({usable - mem_used} MB available)")
    if cluster.disk_capacity_gb and disk_used + disk_gb > cluster.disk_capacity_gb:
        raise HTTPException(409, f"{cluster.name} does not have enough free disk ({cluster.disk_capacity_gb - disk_used} GB available)")
    return cluster


def parse_limit(value, name: str, maximum: int) -> int:
    try:
        number = int(str(value).strip() or 0)
    except ValueError as exc:
        raise HTTPException(422, f"{name} must be a whole number") from exc
    if not 0 <= number <= maximum:
        raise HTTPException(422, f"{name} must be between 0 (unlimited) and {maximum}")
    return number
