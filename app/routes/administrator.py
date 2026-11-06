"""Server-side guarded administrator operations.

Every route on `router` depends on require_admin; mutating routes also go through
csrf_protect. List pages and creation pages are separate: GET /administrator/<section>
lists, GET /administrator/<section>/new shows the form, POST creates.
"""
import ipaddress, json, logging, secrets
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.deps import _aware, csrf_protect, require_admin
from app.web import templates
from app.models import AuditLog, Cluster, ClusterIP, Image, Job, Machine, Notice, Session as LoginSession, User, utcnow
from app.security import digest_token, encrypt_node_key, hash_password
from app.services.clusters import issue_setup_token, node_subnet, render_setup_script, validate_cluster
from app.services.machines import allocate_ip, new_guest_password, new_machine_id, new_vm_name, next_guest_address, validate_specs
from app.services.panel_settings import NOTICE_KINDS, SUPPORT_URL, get_setting, set_setting, validate_location, validate_notice, validate_support_url
from app.services.quotas import check_cluster_capacity, check_owner_quota, owner_usage, parse_limit
from app.services.traffic import BANDWIDTH_MAX_GB, SPEED_MAX_MBPS, reset_traffic
from app.services.images import OS_FAMILIES, detect_os, validate_image_url
from app.services.accounts import validate_email, validate_username
from app.services.network import parse_ip_pairs
from app.services.libvirt import verify_node
from app.worker import seal

log = logging.getLogger("kestrel.admin")
router = APIRouter(prefix="/administrator", dependencies=[Depends(require_admin)])
# Node enrollment endpoint: authenticated only by the one-time, 15-minute setup token.
node_router = APIRouter()
PAGES = {"overview", "machines", "accounts", "clusters", "network", "images", "logs", "others"}
NEW_PAGES = {"machines", "accounts", "clusters", "network", "images"}
ROLES = {"user", "admin"}
# Never echo these back into a re-rendered form.
SECRET_FIELDS = {"csrf_token", "ssh_private_key", "password", "new_password"}
# Jobs that own the machine exclusively; nothing else may be queued alongside them.
EXCLUSIVE_JOBS = ("provision", "rebuild", "delete", "transfer", "resize")


def context(request, user, db, page, **extra):
    data = {
        "user": user, "page": page, "csrf_token": getattr(request.state, "csrf_token", ""),
        "machines": db.query(Machine).order_by(Machine.created_at.desc()).all(),
        "users": db.query(User).order_by(User.created_at, User.id).all(),
        "clusters": db.query(Cluster).order_by(Cluster.name).all(),
        "ips": db.query(ClusterIP).order_by(ClusterIP.cluster_id, ClusterIP.id).all(),
        "images": db.query(Image).order_by(Image.name).all(),
        "jobs": db.query(Job).order_by(Job.created_at.desc(), Job.id.desc()).limit(100).all(),
        "logs": db.query(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(100).all(),
        "support_link": get_setting(db, SUPPORT_URL),
        "notices": db.query(Notice).order_by(Notice.created_at.desc(), Notice.id.desc()).all(),
        "notice_kinds": NOTICE_KINDS, "os_families": OS_FAMILIES,
        "flash": "", "secret": "", "notice": "", "error": "", "values": {},  # nosec B105 - empty placeholders
    }
    data.update(extra)
    return data


def record(db, actor, request, action, target="", result="ok"):
    db.add(AuditLog(actor_id=actor.id, action=action, target=str(target)[:160], remote_ip=request.client.host if request.client else "", result=result))


def render(request, db, actor, page, template=None, status_code=200, **extra):
    return templates.TemplateResponse(request, template or f"administrator/{page}.html", context(request, actor, db, page, **extra), status_code=status_code)


async def form_error(request, db, actor, page, exc: HTTPException):
    """Re-render the creation form with the error and the non-secret values entered."""
    db.rollback()
    form = await request.form()
    values = {k: str(v)[:2000] for k, v in form.items() if k not in SECRET_FIELDS}
    return render(request, db, actor, page, template=f"administrator/{page}_new.html", status_code=exc.status_code, error=str(exc.detail), values=values)


def as_int(value, label: str, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    """Form numbers arrive as text so a bad value re-renders the form instead of a 422 page."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, f"{label} must be a whole number") from exc
    if not minimum <= number <= maximum:
        raise HTTPException(422, f"{label} must be between {minimum} and {maximum}")
    return number


def _pending(db, machine, kinds=None):
    query = db.query(Job.id).filter(Job.machine_id == machine.id, Job.state.in_(["queued", "running"]))
    if kinds:
        query = query.filter(Job.kind.in_(kinds))
    return query.first() is not None


@router.get("")
def admin_root():
    return RedirectResponse("/administrator/overview", status_code=303)


@router.get("/users")
def legacy_users():
    return RedirectResponse("/administrator/accounts", status_code=301)


@router.get("/networking")
def legacy_networking():
    return RedirectResponse("/administrator/network", status_code=301)


@router.get("/{page}")
def admin_page(page: str, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    if page not in PAGES:
        raise HTTPException(404, "Page not found")
    return render(request, db, user, page)


@router.get("/{page}/new")
def admin_new_page(page: str, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    if page not in NEW_PAGES:
        raise HTTPException(404, "Page not found")
    return render(request, db, user, page, template=f"administrator/{page}_new.html")


# ---------- others: support link and notices ----------

@router.post("/settings")
def update_settings(request: Request, support_url: str = Form("", max_length=2000), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        value = validate_support_url(support_url)
    except HTTPException as exc:
        return render(request, db, actor, "others", status_code=exc.status_code, error=str(exc.detail))
    set_setting(db, SUPPORT_URL, value); record(db, actor, request, "settings.support_url"); db.commit()
    return render(request, db, actor, "others", notice="Support link saved." if value else "Support link removed.")


@router.post("/notices")
def create_notice(request: Request, kind: str = Form(..., max_length=32), title: str = Form(..., max_length=2000), message: str = Form("", max_length=5000), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        kind, title, message = validate_notice(kind, title, message)
    except HTTPException as exc:
        return render(request, db, actor, "others", status_code=exc.status_code, error=str(exc.detail))
    notice = Notice(kind=kind, title=title, message=message, active=True)
    db.add(notice); db.flush(); record(db, actor, request, "notice.create", notice.id); db.commit()
    return RedirectResponse("/administrator/others", status_code=303)


@router.post("/notices/{notice_id}/toggle")
def toggle_notice(notice_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    notice = db.get(Notice, notice_id)
    if not notice:
        raise HTTPException(404, "Notice not found")
    notice.active = not notice.active; record(db, actor, request, "notice.toggle", notice_id); db.commit()
    return RedirectResponse("/administrator/others", status_code=303)


@router.post("/notices/{notice_id}/delete")
def delete_notice(notice_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    notice = db.get(Notice, notice_id)
    if not notice:
        raise HTTPException(404, "Notice not found")
    db.delete(notice); record(db, actor, request, "notice.delete", notice_id); db.commit()
    return RedirectResponse("/administrator/others", status_code=303)


# ---------- accounts ----------

def _limits(max_vms, max_vcpu, max_memory_mb, max_disk_gb, max_ips) -> dict:
    return {"max_vms": parse_limit(max_vms, "Machine limit", 10_000), "max_vcpu": parse_limit(max_vcpu, "vCPU limit", 100_000),
            "max_memory_mb": parse_limit(max_memory_mb, "Memory limit", 100_000_000), "max_disk_gb": parse_limit(max_disk_gb, "Disk limit", 10_000_000),
            "max_ips": parse_limit(max_ips, "IP limit", 100_000)}


def _other_active_admins(db, exclude_id: int) -> int:
    return db.query(User).filter(User.role == "admin", User.active.is_(True), User.id != exclude_id).count()


def _revoke_sessions(db, user_id: int):
    db.query(LoginSession).filter(LoginSession.user_id == user_id).delete(synchronize_session=False)


@router.post("/accounts")
async def create_account(request: Request, email: str = Form(..., max_length=320), username: str = Form("", max_length=64), role: str = Form("user", max_length=16),
                         max_vms: str = Form("0", max_length=16), max_vcpu: str = Form("0", max_length=16), max_memory_mb: str = Form("0", max_length=16), max_disk_gb: str = Form("0", max_length=16), max_ips: str = Form("0", max_length=16),
                         actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        if role not in ROLES:
            raise HTTPException(422, "Choose a valid role")
        email = validate_email(db, email)
        username = validate_username(db, username)
        limits = _limits(max_vms, max_vcpu, max_memory_mb, max_disk_gb, max_ips)
    except HTTPException as exc:
        return await form_error(request, db, actor, "accounts", exc)
    temporary_password = secrets.token_urlsafe(18)
    account = User(email=email, username=username, password_hash=hash_password(temporary_password), role=role, force_password_change=True, **limits)
    db.add(account); db.flush(); record(db, actor, request, "account.create", f"{account.id}:{role}"); db.commit()
    return render(request, db, actor, "accounts", flash=f"Account created for {email}. Share this temporary password securely; it is shown once and must be changed at first sign-in.", secret=temporary_password)


@router.get("/accounts/{user_id}/edit")
def edit_account_page(user_id: int, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Account not found")
    return render(request, db, user, "accounts", template="administrator/accounts_edit.html", target=target, usage=owner_usage(db, target.id))


@router.post("/accounts/{user_id}/edit")
def edit_account(user_id: int, request: Request, email: str = Form(..., max_length=320), username: str = Form("", max_length=64), role: str = Form("user", max_length=16), active: str = Form("", max_length=8),
                 new_password: str = Form("", max_length=256), force_change: str = Form("", max_length=8),
                 max_vms: str = Form("0", max_length=16), max_vcpu: str = Form("0", max_length=16), max_memory_mb: str = Form("0", max_length=16), max_disk_gb: str = Form("0", max_length=16), max_ips: str = Form("0", max_length=16),
                 actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Account not found")
    try:
        if role not in ROLES:
            raise HTTPException(422, "Choose a valid role")
        is_active = active == "on"
        if target.id == actor.id and (role != "admin" or not is_active):
            raise HTTPException(422, "You cannot remove your own administrator access or suspend yourself")
        if target.role == "admin" and (role != "admin" or not is_active) and _other_active_admins(db, target.id) == 0:
            raise HTTPException(422, "At least one active administrator must remain")
        email = validate_email(db, email, exclude_id=target.id)
        username = validate_username(db, username, exclude_id=target.id)
        limits = _limits(max_vms, max_vcpu, max_memory_mb, max_disk_gb, max_ips)
        if new_password and not 12 <= len(new_password) <= 256:
            raise HTTPException(422, "New password must be 12 to 256 characters")
    except HTTPException as exc:
        db.rollback()
        return render(request, db, actor, "accounts", template="administrator/accounts_edit.html", status_code=exc.status_code, target=target, usage=owner_usage(db, target.id), error=str(exc.detail))
    revoke = role != target.role or not is_active or bool(new_password) or email != target.email or username != target.username
    target.email, target.username, target.role, target.active = email, username, role, is_active
    for key, value in limits.items():
        setattr(target, key, value)
    if new_password:
        target.password_hash = hash_password(new_password)
        target.force_password_change = force_change == "on"
        target.failed_attempts = 0; target.locked_until = None
    if revoke and target.id != actor.id:
        _revoke_sessions(db, target.id)
    record(db, actor, request, "account.update", f"{target.id}:{role}"); db.commit()
    return render(request, db, actor, "accounts", notice=f"{target.email} updated." + (" Existing sessions were signed out." if revoke and target.id != actor.id else ""))


@router.post("/accounts/{user_id}/toggle")
def toggle_account(user_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.id == actor.id:
        raise HTTPException(404, "Account not found")
    if target.active and target.role == "admin" and _other_active_admins(db, target.id) == 0:
        raise HTTPException(422, "At least one active administrator must remain")
    target.active = not target.active
    if not target.active:  # suspending signs the account out everywhere
        _revoke_sessions(db, target.id)
    record(db, actor, request, "account.toggle", user_id); db.commit()
    return RedirectResponse("/administrator/accounts", status_code=303)


@router.post("/accounts/{user_id}/unlock")
def unlock_account(user_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Account not found")
    target.failed_attempts = 0; target.locked_until = None
    record(db, actor, request, "account.unlock", user_id); db.commit()
    return RedirectResponse(f"/administrator/accounts/{user_id}/edit", status_code=303)


@router.post("/accounts/{user_id}/role")
def change_role(user_id: int, request: Request, role: str = Form(..., max_length=16), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.id == actor.id:
        raise HTTPException(404, "Account not found")
    if role not in ROLES:
        raise HTTPException(422, "Choose a valid role")
    if target.role == "admin" and role != "admin" and _other_active_admins(db, target.id) == 0:
        raise HTTPException(422, "At least one active administrator must remain")
    if target.role != role:
        target.role = role
        # Privilege changes take effect immediately: drop existing sessions.
        _revoke_sessions(db, target.id)
        record(db, actor, request, "account.role", f"{user_id}:{role}")
    db.commit()
    return RedirectResponse("/administrator/accounts", status_code=303)


@router.post("/accounts/{user_id}/delete")
def delete_account(user_id: int, request: Request, confirm_email: str = Form(..., max_length=320), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.id == actor.id:
        raise HTTPException(404, "Account not found")
    if confirm_email.strip().lower() != target.email:
        raise HTTPException(422, "Type the account's email exactly to confirm")
    if db.query(Machine.id).filter(Machine.owner_id == target.id).first():
        raise HTTPException(409, "Move or delete this account's machines first")
    if target.role == "admin" and target.active and _other_active_admins(db, target.id) == 0:
        raise HTTPException(422, "At least one active administrator must remain")
    record(db, actor, request, "account.delete", f"{target.id}:{target.email}")
    db.delete(target); db.commit()
    return RedirectResponse("/administrator/accounts", status_code=303)


# ---------- clusters ----------

def setup_command(token: str) -> str:
    return f"curl -fsSL --proto '=https' https://{settings.trusted_host}/node-setup/{token} | sudo bash"


def _check_host_key(host_key: str):
    if len(host_key) > 4096:
        raise HTTPException(422, "Enter a valid OpenSSH known_hosts entry for this node")
    try:
        import asyncssh
        asyncssh.import_known_hosts(host_key)
    except Exception as exc:
        raise HTTPException(422, "Enter a valid OpenSSH known_hosts entry for this node") from exc


def _check_private_key(private_key: str):
    try:
        from app.services.libvirt import panel_public_key
        panel_public_key(private_key)
    except Exception as exc:
        raise HTTPException(422, "Enter a valid unencrypted OpenSSH private key for the panel") from exc


@router.post("/clusters")
async def create_cluster(request: Request, name: str = Form(..., max_length=200), node_ipv4: str = Form(..., max_length=64), ssh_port: str = Form("22", max_length=8), guest_subnet: str = Form(..., max_length=64),
                         uplink_interface: str = Form(..., max_length=64), pairs: str = Form(..., max_length=64_000), ssh_private_key: str = Form(..., max_length=16_000), node_host_key: str = Form(..., max_length=4096),
                         location: str = Form("", max_length=200), location_id: str = Form("", max_length=16), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        name = name.strip()
        if not name or len(name) > 80:
            raise HTTPException(422, "Enter a cluster name of up to 80 characters")
        if db.query(Cluster).filter(Cluster.name == name).first():
            raise HTTPException(409, "Cluster name already exists")
        port = as_int(ssh_port, "SSH port", 1, 65535)
        node_ipv4, guest_subnet, uplink_interface = node_ipv4.strip(), guest_subnet.strip(), uplink_interface.strip()
        try:
            validate_cluster(node_ipv4, port, guest_subnet, uplink_interface)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        location, location_id = validate_location(location, location_id)
        _check_host_key(node_host_key.strip())
        ip_pairs = parse_ip_pairs(pairs, str(ipaddress.ip_interface(node_ipv4 + "/24").network), node_ipv4)
        _check_private_key(ssh_private_key)
    except HTTPException as exc:
        return await form_error(request, db, actor, "clusters", exc)
    cluster = Cluster(name=name, node_ipv4=node_ipv4, ssh_port=port, guest_subnet=str(ipaddress.ip_network(guest_subnet, strict=False)), uplink_interface=uplink_interface,
                      ssh_key_encrypted=encrypt_node_key(ssh_private_key), node_host_key=node_host_key.strip(), state="pending", location=location, location_id=location_id)
    db.add(cluster); db.flush()
    for private, public in ip_pairs:
        db.add(ClusterIP(cluster_id=cluster.id, private_ipv4=private, public_ipv4=public, guest_ipv4=next_guest_address(db, cluster)))
        db.flush()
    setup_token = issue_setup_token(cluster)
    record(db, actor, request, "cluster.create", cluster.id); db.commit()
    return render(request, db, actor, "clusters", flash="Run this once as root on the node. It expires in 15 minutes; then press Verify.", secret=setup_command(setup_token))


@router.get("/clusters/{cluster_id}/edit")
def edit_cluster_page(cluster_id: int, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    return render(request, db, user, "clusters", template="administrator/clusters_edit.html", cluster=cluster)


@router.post("/clusters/{cluster_id}/edit")
def update_cluster(cluster_id: int, request: Request, name: str = Form(..., max_length=200), ssh_port: str = Form("22", max_length=8), location: str = Form("", max_length=200), location_id: str = Form("", max_length=16),
                   disk_capacity_gb: str = Form("0", max_length=16), node_host_key: str = Form("", max_length=4096), ssh_private_key: str = Form("", max_length=16_000),
                   actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    try:
        name = name.strip()
        if not name or len(name) > 80:
            raise HTTPException(422, "Enter a cluster name of up to 80 characters")
        if db.query(Cluster).filter(Cluster.name == name, Cluster.id != cluster.id).first():
            raise HTTPException(409, "Cluster name already exists")
        port = as_int(ssh_port, "SSH port", 1, 65535)
        loc, loc_id = validate_location(location, location_id)
        disk_cap = parse_limit(disk_capacity_gb, "Disk capacity", 10_000_000)
        host_key = node_host_key.strip()
        if host_key:
            _check_host_key(host_key)
        if ssh_private_key.strip():
            _check_private_key(ssh_private_key)
    except HTTPException as exc:
        return render(request, db, actor, "clusters", template="administrator/clusters_edit.html", status_code=exc.status_code, cluster=cluster, error=str(exc.detail))
    reverify = bool(host_key or ssh_private_key.strip() or port != cluster.ssh_port)
    cluster.name, cluster.ssh_port, cluster.location, cluster.location_id, cluster.disk_capacity_gb = name, port, loc, loc_id, disk_cap
    if host_key:
        cluster.node_host_key = host_key
    if ssh_private_key.strip():
        cluster.ssh_key_encrypted = encrypt_node_key(ssh_private_key)
    if reverify:
        cluster.state = "pending"  # connection details changed: must be verified again before use
    record(db, actor, request, "cluster.update", cluster_id); db.commit()
    return render(request, db, actor, "clusters", notice=f"{cluster.name} updated." + (" Verify the node again to reactivate it." if reverify else ""))


@router.post("/clusters/{cluster_id}/activate")
def activate_cluster(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster or cluster.state != "draining":
        raise HTTPException(404, "Cluster not found")
    cluster.state = "active"; record(db, actor, request, "cluster.activate", cluster_id); db.commit()
    return RedirectResponse("/administrator/clusters", status_code=303)


@router.post("/clusters/{cluster_id}/token")
def reissue_token(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    token = issue_setup_token(cluster); record(db, actor, request, "cluster.token", cluster_id); db.commit()
    return render(request, db, actor, "clusters", flash="New one-time setup command. It expires in 15 minutes.", secret=setup_command(token))


@router.post("/clusters/{cluster_id}/verify")
async def verify_cluster(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    try:
        checks = await verify_node(cluster)
    except Exception:
        checks = {}
    passed = bool(checks) and all(checks.values())
    if passed:
        import asyncio
        from app.services.libvirt import node_capacity
        try:
            cluster.cpu_capacity, cluster.memory_capacity_mb = await asyncio.to_thread(node_capacity, cluster)
        except Exception:
            log.warning("Could not read capacity of %s; memory admission stays unenforced until the next verify", cluster.name)
        # A drained node stays drained; verification only proves it is healthy.
        if cluster.state != "draining":
            cluster.state = "active"
    record(db, actor, request, "cluster.verify", cluster_id, "ok" if passed else "failed")
    db.commit()
    failed = ", ".join(k for k, v in checks.items() if not v) or "node unreachable"
    if passed:
        return render(request, db, actor, "clusters", notice=f"{cluster.name} verified and {cluster.state}.")
    return render(request, db, actor, "clusters", error=f"Verification failed for {cluster.name}: {failed}.")


@router.post("/clusters/{cluster_id}/drain")
def drain_cluster(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    cluster.state = "draining"; record(db, actor, request, "cluster.drain", cluster_id); db.commit()
    return RedirectResponse("/administrator/clusters", status_code=303)


@node_router.get("/node-setup/{token}", response_class=PlainTextResponse)
def node_setup(token: str, request: Request, db: DBSession = Depends(get_db)):
    if not 20 <= len(token) <= 64:
        raise HTTPException(404, "Not found")
    cluster = db.query(Cluster).filter(Cluster.setup_token_hash == digest_token(token)).first()
    expires = _aware(cluster.setup_token_expires) if cluster else None
    if not cluster or not expires or expires <= utcnow():
        raise HTTPException(404, "Not found")
    cluster.setup_token_hash = None; cluster.setup_token_expires = None  # one-time
    db.add(AuditLog(action="cluster.setup_fetched", target=str(cluster.id), remote_ip=request.client.host if request.client else "", result="ok"))
    script = render_setup_script(db, cluster)
    db.commit()
    return PlainTextResponse(script, headers={"Cache-Control": "no-store"})


# ---------- machines ----------

def _traffic_fields(bandwidth_limit_gb, speed_in_mbps, speed_out_mbps) -> dict:
    return {"bandwidth_limit_gb": parse_limit(bandwidth_limit_gb, "Bandwidth limit", BANDWIDTH_MAX_GB),
            "speed_in_mbps": parse_limit(speed_in_mbps, "Inbound speed", SPEED_MAX_MBPS),
            "speed_out_mbps": parse_limit(speed_out_mbps, "Outbound speed", SPEED_MAX_MBPS)}


def _specs(vcpu, memory_mb, disk_gb) -> tuple[int, int, int]:
    values = as_int(vcpu, "vCPU"), as_int(memory_mb, "Memory"), as_int(disk_gb, "Disk")
    validate_specs(*values)
    return values


@router.post("/machines")
async def create_machine(request: Request, owner_id: str = Form("", max_length=16), cluster_id: str = Form("", max_length=16), image_id: str = Form("", max_length=16),
                         vcpu: str = Form(..., max_length=8), memory_mb: str = Form(..., max_length=12), disk_gb: str = Form(..., max_length=12),
                         bandwidth_limit_gb: str = Form("0", max_length=16), speed_in_mbps: str = Form("0", max_length=16), speed_out_mbps: str = Form("0", max_length=16),
                         actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        cpu, memory, disk = _specs(vcpu, memory_mb, disk_gb)
        traffic = _traffic_fields(bandwidth_limit_gb, speed_in_mbps, speed_out_mbps)
        owner = db.get(User, as_int(owner_id, "Owner", 1)) if str(owner_id).strip() else None
        cluster = db.get(Cluster, as_int(cluster_id, "Cluster", 1)) if str(cluster_id).strip() else None
        image = db.get(Image, as_int(image_id, "Image", 1)) if str(image_id).strip() else None
        if not owner or not owner.active or not cluster or cluster.state != "active" or not image or not image.active:
            raise HTTPException(422, "Select an active owner, cluster, and image")
        if image.kind != "cloud":
            raise HTTPException(422, "Machines are built from cloud images")
        check_owner_quota(db, owner.id, cpu, memory, disk)
        check_cluster_capacity(db, cluster.id, memory, disk)
        machine = Machine(id=new_machine_id(db), vm_name=new_vm_name(db), owner_id=owner.id, cluster_id=cluster.id, image_id=image.id, vcpu=cpu, memory_mb=memory, disk_gb=disk, **traffic)
        db.add(machine)
        db.flush()  # machine row must exist before an address can reference it (also takes SQLite's write lock)
        # Re-check with the new row in place: catches a concurrent create that committed meanwhile.
        _recheck_after_flush(db, machine)
        allocate_ip(db, cluster.id, machine.id)
    except HTTPException as exc:
        return await form_error(request, db, actor, "machines", exc)
    password = new_guest_password()
    db.add(Job(kind="provision", machine_id=machine.id, actor_id=actor.id, payload=seal({"password": password}), state="queued"))
    record(db, actor, request, "machine.create", machine.id); db.commit()
    response = render(request, db, actor, "machines", flash=f"{machine.id} queued for provisioning. Guest login is ubuntu with this password. It is shown once.", secret=password)
    response.headers["Cache-Control"] = "no-store"
    return response


def _recheck_after_flush(db, machine, owner=True, cluster=True):
    """Totals including this machine must still fit (exact once our write lock is held)."""
    if owner:
        check_owner_quota(db, machine.owner_id, machine.vcpu, machine.memory_mb, machine.disk_gb, exclude_machine=machine.id)
    if cluster:
        check_cluster_capacity(db, machine.cluster_id, machine.memory_mb, machine.disk_gb, exclude_machine=machine.id)


def _machine_or_404(db, machine_id):
    machine = db.get(Machine, machine_id) if len(machine_id) <= 16 else None
    if not machine:
        raise HTTPException(404, "Machine not found")
    return machine


def _edit_page(request, db, actor, machine, status_code=200, **extra):
    return render(request, db, actor, "machines", template="administrator/machines_edit.html", status_code=status_code, machine=machine, **extra)


@router.get("/machines/{machine_id}/edit")
def edit_machine_page(machine_id: str, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    return _edit_page(request, db, user, _machine_or_404(db, machine_id))


@router.post("/machines/{machine_id}/edit")
def edit_machine(machine_id: str, request: Request, owner_id: str = Form("", max_length=16), vcpu: str = Form(..., max_length=8), memory_mb: str = Form(..., max_length=12), disk_gb: str = Form(..., max_length=12),
                 bandwidth_limit_gb: str = Form("0", max_length=16), speed_in_mbps: str = Form("0", max_length=16), speed_out_mbps: str = Form("0", max_length=16),
                 actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = _machine_or_404(db, machine_id)
    previous = {"vcpu": machine.vcpu, "memory_mb": machine.memory_mb, "disk_gb": machine.disk_gb, "speed_in_mbps": machine.speed_in_mbps, "speed_out_mbps": machine.speed_out_mbps}
    try:
        cpu, memory, disk = _specs(vcpu, memory_mb, disk_gb)
        traffic = _traffic_fields(bandwidth_limit_gb, speed_in_mbps, speed_out_mbps)
        if machine.state in {"provisioning", "rebuilding", "deleting", "transferring", "failed"}:
            raise HTTPException(409, f"Machines cannot be edited while {machine.state}")
        if _pending(db, machine):
            raise HTTPException(409, "Another operation is pending for this machine")
        owner = db.get(User, as_int(owner_id, "Owner", 1)) if str(owner_id).strip() else None
        if not owner or not owner.active:
            raise HTTPException(422, "Select an active owner")
        if disk < machine.disk_gb:
            raise HTTPException(422, "Disks can only grow; shrinking would destroy data")
        hardware = cpu != machine.vcpu or memory != machine.memory_mb or disk != machine.disk_gb
        if hardware and machine.state not in {"stopped", "suspended"}:
            raise HTTPException(409, "Shut the machine down before changing vCPU, memory or disk")
        owner_changed = owner.id != machine.owner_id
        grows = cpu > machine.vcpu or memory > machine.memory_mb or disk > machine.disk_gb
        grows_on_node = memory > machine.memory_mb or disk > machine.disk_gb
        speeds_changed = traffic["speed_in_mbps"] != machine.speed_in_mbps or traffic["speed_out_mbps"] != machine.speed_out_mbps
        machine.owner_id, machine.vcpu, machine.memory_mb, machine.disk_gb = owner.id, cpu, memory, disk
        for key, value in traffic.items():
            setattr(machine, key, value)
        db.flush()
        # Only growth (or a new owner) is admission-checked. A limit lowered below current
        # usage must not block unrelated edits such as bandwidth or shrinking memory.
        _recheck_after_flush(db, machine, owner=owner_changed or grows, cluster=grows_on_node)
    except HTTPException as exc:
        db.rollback(); db.refresh(machine)
        return _edit_page(request, db, actor, machine, status_code=exc.status_code, error=str(exc.detail))
    if hardware or speeds_changed:
        grow = disk if disk != previous["disk_gb"] else 0
        db.add(Job(kind="resize", machine_id=machine.id, actor_id=actor.id, state="queued", payload=json.dumps({"grow_disk_gb": grow, "previous": previous})))
    record(db, actor, request, "machine.update", machine.id + (f":owner={owner.id}" if owner_changed else "")); db.commit()
    return _edit_page(request, db, actor, machine, notice="Saved." + (" Applying to the hypervisor now." if hardware or speeds_changed else ""))


@router.post("/machines/{machine_id}/traffic/reset")
def reset_machine_traffic(machine_id: str, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = _machine_or_404(db, machine_id)
    reset_traffic(machine); record(db, actor, request, "machine.traffic_reset", machine.id); db.commit()
    return _edit_page(request, db, actor, machine, notice="This month's bandwidth usage was reset.")


@router.post("/machines/{machine_id}/transfer")
def transfer_machine(machine_id: str, request: Request, target_cluster_id: str = Form("", max_length=16), confirm_name: str = Form(..., max_length=32), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = _machine_or_404(db, machine_id)
    try:
        if confirm_name != machine.vm_name:
            raise HTTPException(422, "Type the machine name exactly to confirm")
        if machine.state not in {"running", "stopped"}:
            raise HTTPException(409, "Only running or stopped machines can be moved")
        if _pending(db, machine):
            raise HTTPException(409, "Another operation is pending for this machine")
        target = db.get(Cluster, as_int(target_cluster_id, "Target cluster", 1)) if str(target_cluster_id).strip() else None
        if not target or target.state != "active" or target.id == machine.cluster_id:
            raise HTTPException(422, "Choose a different, active cluster")
        if not db.query(ClusterIP.id).filter(ClusterIP.cluster_id == target.id, ClusterIP.machine_id.is_(None)).first():
            raise HTTPException(409, f"{target.name} has no free IPv4 address")
        check_cluster_capacity(db, target.id, machine.memory_mb, machine.disk_gb, exclude_machine=machine.id)
    except HTTPException as exc:
        db.rollback()
        return _edit_page(request, db, actor, machine, status_code=exc.status_code, error=str(exc.detail))
    db.add(Job(kind="transfer", machine_id=machine.id, actor_id=actor.id, state="queued", payload=json.dumps({"target_cluster_id": target.id})))
    record(db, actor, request, "machine.transfer", f"{machine.id}:{target.id}"); db.commit()
    return _edit_page(request, db, actor, machine, notice=f"Transfer to {target.name} queued. The machine is shut down, copied with checksum verification, and booted with a new public IP.")


@router.post("/machines/{machine_id}/delete")
def delete_machine(machine_id: str, request: Request, confirm_name: str = Form(..., max_length=32), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = _machine_or_404(db, machine_id)
    if confirm_name != machine.vm_name:
        raise HTTPException(422, "Type the machine name exactly to confirm")
    if _pending(db, machine):
        raise HTTPException(409, "Another operation is pending for this machine")
    machine.set_power_state("deleting")
    db.add(Job(kind="delete", machine_id=machine.id, actor_id=actor.id, state="queued"))
    record(db, actor, request, "machine.delete", machine.id); db.commit()
    return RedirectResponse("/administrator/machines", status_code=303)


@router.post("/machines/{machine_id}/suspend")
def suspend_machine(machine_id: str, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = _machine_or_404(db, machine_id)
    if machine.state in {"provisioning", "rebuilding", "deleting", "transferring"} or _pending(db, machine, EXCLUSIVE_JOBS):
        raise HTTPException(409, f"This machine is busy ({machine.state}); try again when the current operation finishes")
    if machine.state == "suspended":
        machine.set_power_state("stopped"); machine.suspend_reason = ""
        record(db, actor, request, "machine.unsuspend", machine.id)
    else:
        machine.set_power_state("suspended"); machine.suspend_reason = "admin"
        db.add(Job(kind="force-stop", machine_id=machine.id, actor_id=actor.id, state="queued"))
        record(db, actor, request, "machine.suspend", machine.id)
    db.commit()
    if request.headers.get("referer", "").split("?")[0].endswith(f"/administrator/machines/{machine.id}/edit"):
        return RedirectResponse(f"/administrator/machines/{machine.id}/edit", status_code=303)
    return RedirectResponse("/administrator/machines", status_code=303)


@router.post("/machines/{machine_id}/repin")
def repin_host_key(machine_id: str, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    """Re-pin the guest SSH host key after the guest regenerated it (console stops working)."""
    machine = _machine_or_404(db, machine_id)
    if machine.state != "running":
        raise HTTPException(409, "Start the machine before re-pinning its host key")
    if _pending(db, machine):
        raise HTTPException(409, "Another operation is pending for this machine")
    db.add(Job(kind="repin-host-key", machine_id=machine.id, actor_id=actor.id, state="queued"))
    record(db, actor, request, "machine.repin", machine.id); db.commit()
    return RedirectResponse(f"/machines/{machine.id}?tab=settings", status_code=303)


# ---------- images ----------

@router.post("/images")
async def create_image(request: Request, name: str = Form(..., max_length=200), url: str = Form(..., max_length=2048), checksum: str = Form(..., max_length=128), kind: str = Form("cloud", max_length=16),
                       os_family: str = Form("auto", max_length=16), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        name, url, checksum = name.strip(), url.strip(), checksum.strip()
        if not name or len(name) > 100:
            raise HTTPException(422, "Enter an image name of up to 100 characters")
        parsed = urlparse(url)
        if kind not in {"cloud", "iso"} or not validate_image_url(url, checksum) or parsed.username or parsed.password:
            raise HTTPException(422, "Use a secure image URL and a valid SHA-256 checksum")
        if db.query(Image).filter(Image.name == name).first():
            raise HTTPException(409, "An image with that name already exists")
        family = detect_os(name) if os_family == "auto" else os_family
        if family not in OS_FAMILIES:
            raise HTTPException(422, "Choose an operating system")
    except HTTPException as exc:
        return await form_error(request, db, actor, "images", exc)
    image = Image(name=name, url=url, checksum=checksum.lower(), kind=kind, os_family=family)
    db.add(image); db.flush()
    for cluster in db.query(Cluster).filter(Cluster.state.in_(["active", "draining"])).all():
        db.add(Job(kind="sync-image", actor_id=actor.id, state="queued", payload=json.dumps({"image_id": image.id, "cluster_id": cluster.id})))
    record(db, actor, request, "image.create", image.id); db.commit()
    return RedirectResponse("/administrator/images", status_code=303)


@router.get("/images/{image_id}/edit")
def edit_image_page(image_id: int, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    image = db.get(Image, image_id)
    if not image:
        raise HTTPException(404, "Image not found")
    return render(request, db, user, "images", template="administrator/images_edit.html", image=image)


@router.post("/images/{image_id}/edit")
def edit_image(image_id: int, request: Request, name: str = Form(..., max_length=200), os_family: str = Form("other", max_length=16), active: str = Form("", max_length=8), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    image = db.get(Image, image_id)
    if not image:
        raise HTTPException(404, "Image not found")
    name = name.strip()
    error = ""
    if not name or len(name) > 100:
        error = "Enter an image name of up to 100 characters"
    elif db.query(Image).filter(Image.name == name, Image.id != image.id).first():
        error = "An image with that name already exists"
    elif os_family not in OS_FAMILIES:
        error = "Choose an operating system"
    if error:
        return render(request, db, actor, "images", template="administrator/images_edit.html", status_code=422, image=image, error=error)
    image.name, image.os_family, image.active = name, os_family, active == "on"
    record(db, actor, request, "image.update", image.id); db.commit()
    return render(request, db, actor, "images", notice=f"{image.name} updated.")


# ---------- network ----------

@router.post("/network/ips")
async def add_ips(request: Request, cluster_id: str = Form("", max_length=16), pairs: str = Form(..., max_length=64_000), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    try:
        cluster = db.get(Cluster, as_int(cluster_id, "Cluster", 1)) if str(cluster_id).strip() else None
        if not cluster:
            raise HTTPException(422, "Select a cluster")
        parsed = parse_ip_pairs(pairs, node_subnet(cluster), cluster.node_ipv4)
        existing = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id).all()
        private, public = {ip.private_ipv4 for ip in existing}, {ip.public_ipv4 for ip in existing}
        if any(a in private or b in public for a, b in parsed):
            raise HTTPException(409, "An address is already in this cluster")
    except HTTPException as exc:
        return await form_error(request, db, actor, "network", exc)
    for private_ip, public_ip in parsed:
        guest_ip = next_guest_address(db, cluster)
        db.add(ClusterIP(cluster_id=cluster.id, private_ipv4=private_ip, public_ipv4=public_ip, guest_ipv4=guest_ip))
        db.flush()
    if cluster.state in {"active", "draining"}:
        db.add(Job(kind="push-rules", actor_id=actor.id, state="queued", payload=json.dumps({"cluster_id": cluster.id})))
    record(db, actor, request, "network.ips.add", cluster.id); db.commit()
    return RedirectResponse("/administrator/network", status_code=303)


@router.post("/network/ips/{ip_id}/delete")
def remove_ip(ip_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    """Remove a free address from a pool. Assigned addresses can never be removed."""
    address = db.get(ClusterIP, ip_id)
    if not address:
        raise HTTPException(404, "Address not found")
    claimed = db.query(ClusterIP).filter(ClusterIP.id == ip_id, ClusterIP.machine_id.is_(None)).delete(synchronize_session=False)
    if claimed != 1:
        db.rollback()
        raise HTTPException(409, "That address is assigned to a machine")
    cluster = db.get(Cluster, address.cluster_id)
    if cluster and cluster.state in {"active", "draining"}:
        db.add(Job(kind="push-rules", actor_id=actor.id, state="queued", payload=json.dumps({"cluster_id": cluster.id})))
    record(db, actor, request, "network.ips.remove", f"{address.cluster_id}:{address.public_ipv4}"); db.commit()
    return RedirectResponse("/administrator/network", status_code=303)
