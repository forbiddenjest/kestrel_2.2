"""Customer machine inventory and guarded machine actions."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from markupsafe import escape
from sqlalchemy.orm import Session as DBSession
from app.db import get_db
from app.deps import csrf_protect, require_owner, require_user
from app.web import templates
from app.models import AuditLog, FirewallRule, Image, Job, Machine, MetricSample, User
from app.services.machines import validate_password
from app.services.network import validate_firewall_rule
from app.services.traffic import daily_series
from app.worker import seal

router = APIRouter()
TABS = ("overview", "metrics", "console", "network", "media", "settings")
POWER_ACTIONS = {"start", "stop", "restart", "force-stop"}
# Nothing can be queued while the machine is in one of these states.
BUSY = {"provisioning", "rebuilding", "deleting", "suspended", "transferring"}


def csrf_token(request: Request):
    row = getattr(request.state, "login_session", None)
    return getattr(request.state, "csrf_token", "") if row else ""


@router.get("/dashboard")
def dashboard(request: Request, scope: str = "mine", user: User = Depends(require_user), db: DBSession = Depends(get_db)):
    """Everyone lands here. Users only ever see their own machines; administrators can
    switch to every machine on the system with ?scope=all."""
    show_all = user.role == "admin" and scope == "all"
    query = db.query(Machine)
    if not show_all:
        query = query.filter(Machine.owner_id == user.id)
    rows = query.order_by(Machine.created_at.desc()).all()
    return templates.TemplateResponse(request, "dashboard.html", {"page": "dashboard", "machines": rows, "scope": "all" if show_all else "mine", "user": user, "csrf_token": csrf_token(request)})


@router.get("/machines")
def machine_list_redirect():
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/machines/{machine_id}")
def machine_detail(request: Request, machine: Machine = Depends(require_owner("machine_id")), current_user: User = Depends(require_user), tab: str = "overview", db: DBSession = Depends(get_db)):
    if tab not in TABS:
        raise HTTPException(404, "Tab not found")
    traffic = daily_series(db, machine.id) if tab in {"overview", "metrics"} else []
    metrics = db.query(MetricSample).filter(MetricSample.machine_id == machine.id).order_by(MetricSample.sampled_at.desc()).limit(48).all() if tab == "metrics" else []
    return templates.TemplateResponse(request, "machine.html", {"page": "dashboard", "machine": machine, "tab": tab, "metrics": list(reversed(metrics)), "traffic": traffic,
                                                                 "images": db.query(Image).filter(Image.active.is_(True)).order_by(Image.name).all(), "user": current_user, "csrf_token": csrf_token(request)})


@router.get("/machines/{machine_id}/metrics/live", response_class=HTMLResponse)
def machine_metrics_live(request: Request, machine: Machine = Depends(require_owner("machine_id")), db: DBSession = Depends(get_db)):
    samples = db.query(MetricSample).filter(MetricSample.machine_id == machine.id).order_by(MetricSample.sampled_at.desc()).limit(24).all()
    return templates.TemplateResponse(request, "metrics_fragment.html", {"machine": machine, "samples": list(reversed(samples))})


@router.post("/machines/{machine_id}/actions")
def machine_action(request: Request, action: str = Form(..., max_length=16), machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if action not in POWER_ACTIONS:
        raise HTTPException(422, "Unsupported action")
    if machine.state == "failed":
        raise HTTPException(409, "This machine failed to build; rebuild it or contact support")
    pending = "starting" if action == "start" else "stopping" if action in {"stop", "force-stop"} else "restarting"
    return _queue(db, request, actor, machine, action, state=pending)


def _queue(db, request, actor, machine, kind, payload=None, state=None):
    if machine.state in BUSY:
        raise HTTPException(409, "This machine is busy or suspended")
    if db.query(Job.id).filter(Job.machine_id == machine.id, Job.state.in_(["queued", "running"])).first():
        raise HTTPException(409, "Another operation is already pending for this machine")
    db.add(Job(kind=kind, machine_id=machine.id, actor_id=actor.id, state="queued", payload=seal(payload) if payload else "{}"))
    db.add(AuditLog(actor_id=actor.id, action=f"machine.{kind}", target=machine.id, remote_ip=request.client.host if request.client else "", result="queued"))
    if state:
        machine.set_power_state(state)
    db.commit()
    label = escape(kind.replace("-", " ").title())
    return HTMLResponse(f'<div class="alert alert-info" role="status">{label} queued for {escape(machine.id)}.</div>')


@router.post("/machines/{machine_id}/password")
def machine_password(request: Request, password: str = Form(..., max_length=256), machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    validate_password(password)
    if machine.state != "running":
        raise HTTPException(409, "Start the machine before changing its password")
    return _queue(db, request, actor, machine, "password", {"password": password})


@router.post("/machines/{machine_id}/rebuild")
def machine_rebuild(request: Request, image_id: int = Form(...), password: str = Form(..., max_length=256), confirm_name: str = Form(..., max_length=32), machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if confirm_name != machine.vm_name:
        raise HTTPException(422, "Type the machine name exactly to confirm")
    validate_password(password)
    image = db.get(Image, image_id)
    if not image or not image.active or image.kind != "cloud":
        raise HTTPException(422, "Select an active cloud image")
    return _queue(db, request, actor, machine, "rebuild", {"password": password, "image_id": image.id}, state="rebuilding")


@router.post("/machines/{machine_id}/media")
def machine_media(request: Request, iso_image_id: int = Form(0), boot_device: str = Form("disk", max_length=8), machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if boot_device not in {"disk", "cdrom"}:
        raise HTTPException(422, "Unsupported boot device")
    if machine.state == "failed":
        raise HTTPException(409, "This machine failed to build; rebuild it first")
    if iso_image_id:
        iso = db.get(Image, iso_image_id)
        if not iso or not iso.active or iso.kind != "iso":
            raise HTTPException(422, "Select an active ISO")
    machine.iso_image_id = iso_image_id or None
    machine.boot_device = boot_device if iso_image_id else "disk"
    return _queue(db, request, actor, machine, "media")


@router.post("/machines/{machine_id}/firewall")
def firewall_add(request: Request, protocol: str = Form(..., max_length=4), port: int = Form(...), machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    validate_firewall_rule(protocol, port)
    if db.query(FirewallRule).filter_by(machine_id=machine.id, protocol=protocol, port=port).first():
        raise HTTPException(409, "That rule already exists")
    if len(machine.firewall_rules) >= 64:
        raise HTTPException(422, "Rule limit reached")
    db.add(FirewallRule(machine_id=machine.id, protocol=protocol, port=port))
    return _queue(db, request, actor, machine, "firewall")


@router.post("/machines/{machine_id}/firewall/{rule_id}/delete")
def firewall_delete(request: Request, rule_id: int, machine: Machine = Depends(require_owner("machine_id")), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    rule = db.get(FirewallRule, rule_id)
    if not rule or rule.machine_id != machine.id:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    return _queue(db, request, actor, machine, "firewall")
