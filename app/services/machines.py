"""Machine identifiers, specification validation, IP mapping and allocation."""
import ipaddress
import re
import secrets
import string
from fastapi import HTTPException
from sqlalchemy import select, update
from app.models import ClusterIP, Machine

VM_RE = re.compile(r"^vm[0-9]+$")
ID_RE = re.compile(r"^vm-[a-z0-9]{5}$")
PASSWORD_RE = re.compile(r"^[\x21-\x7e]{12,128}$")
ID_ALPHABET = string.ascii_lowercase + string.digits

def new_machine_id(db) -> str:
    for _ in range(20):
        candidate = "vm-" + "".join(secrets.choice(ID_ALPHABET) for _ in range(5))
        if db.get(Machine, candidate) is None:
            return candidate
    raise HTTPException(503, "Could not allocate a machine identifier")

def new_vm_name(db) -> str:
    for _ in range(20):
        candidate = f"vm{secrets.randbelow(900000) + 100000}"
        if not db.query(Machine.id).filter(Machine.vm_name == candidate).first():
            return candidate
    raise HTTPException(503, "Could not allocate a hypervisor name")

def new_guest_password() -> str:
    return secrets.token_urlsafe(18)

def validate_password(password: str):
    if not PASSWORD_RE.fullmatch(password):
        raise HTTPException(422, "Password must be 12–128 printable characters without spaces")

def validate_specs(vcpu: int, memory_mb: int, disk_gb: int):
    if not 1 <= vcpu <= 64 or not 512 <= memory_mb <= 262144 or not 5 <= disk_gb <= 4096:
        raise HTTPException(422, "Machine specifications are outside allowed limits")

def guest_gateway(subnet: str) -> str:
    return str(next(ipaddress.ip_network(subnet, strict=False).hosts()))

def next_guest_address(db, cluster):
    network = ipaddress.ip_network(cluster.guest_subnet, strict=False)
    assigned = {row[0] for row in db.query(ClusterIP.guest_ipv4).filter(ClusterIP.cluster_id == cluster.id).all()}
    reserved = {str(network.network_address), str(network.broadcast_address), guest_gateway(cluster.guest_subnet)}
    hosts = list(network.hosts())
    # Guests start at .101 so the low range stays free for host-side services.
    for host in hosts[100:] + hosts[:100]:
        address = str(host)
        if address not in assigned and address not in reserved:
            return address
    raise HTTPException(409, "No free guest IPv4 address in this cluster")

def allocate_ip(db, cluster_id: int, machine_id: str, attempts: int = 8):
    """Claim a free address for an already-flushed machine.

    SELECT ... FOR UPDATE is a no-op on SQLite, so the claim is a compare-and-set
    UPDATE that only succeeds while machine_id is still NULL. A concurrent create that
    took the same row sees rowcount 0 and moves on to the next free row; the unique
    constraint on cluster_ips.machine_id remains the final backstop.
    """
    tried: set[int] = set()
    for _ in range(attempts):
        query = select(ClusterIP.id).where(ClusterIP.cluster_id == cluster_id, ClusterIP.machine_id.is_(None))
        if tried:
            query = query.where(ClusterIP.id.notin_(tried))
        candidate = db.execute(query.order_by(ClusterIP.id).limit(1)).scalar()
        if candidate is None:
            break
        tried.add(candidate)
        claimed = db.execute(
            update(ClusterIP)
            .where(ClusterIP.id == candidate, ClusterIP.machine_id.is_(None))
            .values(machine_id=machine_id)
        ).rowcount
        if claimed == 1:
            return db.get(ClusterIP, candidate, populate_existing=True)
    raise HTTPException(409, "No free IPv4 address on this cluster")
