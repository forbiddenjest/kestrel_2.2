"""Authenticated account preferences."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.deps import csrf_protect, require_user
from app.models import AuditLog, Session as LoginSession, User
from app.security import hash_password, verify_password
from app.web import templates

router = APIRouter()


def _page(request, user, error="", message="", status_code=200):
    session = getattr(request.state, "login_session", None)
    return templates.TemplateResponse(request, "account.html", {"page": "account", "user": user, "csrf_token": request.state.csrf_token if session else "", "message": message, "error": error}, status_code=status_code)


@router.get("/account")
def account_page(request: Request, user: User = Depends(require_user)):
    return _page(request, user)


@router.post("/account/password")
def change_password(request: Request, current_password: str = Form(..., max_length=256), new_password: str = Form(..., max_length=256), user: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if not 12 <= len(new_password) <= 256 or not verify_password(user.password_hash, current_password):
        return _page(request, user, error="Enter your current password and a new password of at least 12 characters.", status_code=400)
    if new_password == current_password:
        return _page(request, user, error="Choose a password different from the current one.", status_code=400)
    user.password_hash = hash_password(new_password)
    user.force_password_change = False
    db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
    db.add(AuditLog(actor_id=user.id, action="account.password", target=str(user.id), remote_ip=request.client.host if request.client else "", result="ok"))
    db.commit()
    response = RedirectResponse("/auth", status_code=303)
    response.delete_cookie(settings.session_cookie, path="/")
    response.delete_cookie("kestrel_csrf", path="/")
    return response
