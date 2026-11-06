"""Login, rate limiting and opaque session lifecycle."""
from datetime import timedelta
import hashlib, secrets
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.deps import _aware, csrf_protect
from app.models import AuditLog, LoginAttempt, Session as LoginSession, User, utcnow
from app.security import DUMMY_HASH, digest_token, hash_password, needs_rehash, new_session, verify_password
from app.web import templates

router = APIRouter()
CSRF_COOKIE = "kestrel_csrf"
FAILED = "Sign-in failed. Check your details or try again later."


def _key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_login_cookie(response, csrf: str):
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    return response


def _form(request, error="", identifier="", status_code=200):
    csrf = secrets.token_urlsafe(32)
    response = templates.TemplateResponse(request, "auth.html", {"error": error, "email": identifier, "csrf_token": csrf}, status_code=status_code)
    return _set_login_cookie(response, csrf)


@router.get("/auth")
def login_page(request: Request, db: DBSession = Depends(get_db)):
    raw = request.cookies.get(settings.session_cookie)
    row = db.get(LoginSession, digest_token(raw)) if raw and len(raw) <= 256 else None
    expires = _aware(row.expires_at) if row else None
    if row and expires and expires > utcnow() and row.user.active:
        return RedirectResponse("/dashboard", status_code=303)
    return _form(request)


@router.post("/auth")
def login(request: Request, email: str = Form(..., max_length=255), password: str = Form(..., max_length=256), csrf_token: str = Form(..., max_length=128), db: DBSession = Depends(get_db)):
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    csrf_ok = bool(cookie_token) and secrets.compare_digest(cookie_token, csrf_token)
    identifier = email.strip().lower()[:255]
    now = utcnow()
    ip_key, account_key = _key(_ip(request)), _key(identifier)
    # Sign in with email or username.
    user = db.query(User).filter(or_(User.email == identifier, User.username == identifier)).first() if identifier else None
    # Administrators are exempt from per-account lockout: otherwise anyone could lock the
    # admin out by guessing wrongly on purpose. They remain subject to per-IP limits.
    account_lockable = not (user and user.role == "admin")
    window = now - timedelta(minutes=settings.login_lock_minutes)
    block_filter = or_(LoginAttempt.ip_key == ip_key, LoginAttempt.account_key == account_key) if account_lockable else (LoginAttempt.ip_key == ip_key)
    blocked = db.query(LoginAttempt.id).filter(LoginAttempt.attempted_at > window, block_filter, LoginAttempt.blocked_until.is_not(None), LoginAttempt.blocked_until > now).first()
    locked_until = _aware(user.locked_until) if user and account_lockable else None
    account_locked = bool(locked_until and locked_until > now)
    # Always run one Argon2 verification, so response time does not reveal whether the
    # account exists, is suspended or is locked.
    password_ok = verify_password(user.password_hash if user else DUMMY_HASH, password)
    valid = bool(user and user.active and not account_locked and password_ok)
    recent_ip = db.query(LoginAttempt).filter(LoginAttempt.ip_key == ip_key, LoginAttempt.attempted_at > window).count()
    recent_account = db.query(LoginAttempt).filter(LoginAttempt.account_key == account_key, LoginAttempt.attempted_at > window).count() if account_lockable else 0
    if not csrf_ok or blocked or recent_ip >= settings.login_ip_limit or recent_account >= settings.login_account_limit or not valid:
        lock = recent_ip + 1 >= settings.login_ip_limit or (account_lockable and recent_account + 1 >= settings.login_account_limit)
        db.add(LoginAttempt(account_key=account_key, ip_key=ip_key, attempted_at=now, blocked_until=now + timedelta(minutes=settings.login_lock_minutes) if lock else None))
        if user and not password_ok:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if account_lockable and user.failed_attempts >= settings.login_account_limit:
                user.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
                db.add(AuditLog(actor_id=user.id, action="auth.locked", target=str(user.id), remote_ip=_ip(request), result="failed"))
        db.commit()
        return _form(request, FAILED, identifier, status_code=401)
    user.failed_attempts = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    # One session per account: signing in elsewhere ends older sessions.
    db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
    raw, csrf, _row = new_session(db, user)
    db.query(LoginAttempt).filter(LoginAttempt.account_key == account_key).delete(synchronize_session=False)
    db.add(AuditLog(actor_id=user.id, action="auth.login", target=str(user.id), remote_ip=_ip(request), result="ok"))
    db.commit()
    target = "/account?password_change=1" if user.force_password_change else "/dashboard"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(settings.session_cookie, raw, httponly=True, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    return response


@router.post("/auth/logout")
def logout(request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    row = getattr(request.state, "login_session", None)
    if row:
        db.delete(row)
        db.commit()
    response = RedirectResponse("/auth", status_code=303)
    response.delete_cookie(settings.session_cookie, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response
