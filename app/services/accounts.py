"""Account field validation shared by create and edit."""
import re
from fastapi import HTTPException
from app.models import User

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def validate_email(db, email: str, exclude_id: int | None = None) -> str:
    email = (email or "").strip().lower()
    if len(email) > 255 or not EMAIL_RE.fullmatch(email):
        raise HTTPException(422, "Enter a valid email address")
    query = db.query(User.id).filter(User.email == email)
    if exclude_id:
        query = query.filter(User.id != exclude_id)
    if query.first():
        raise HTTPException(409, "An account with that email already exists")
    return email


def validate_username(db, username: str, exclude_id: int | None = None) -> str | None:
    """Optional. Lowercase letters, digits, dot, dash, underscore; 3-32 characters."""
    username = (username or "").strip().lower()
    if not username:
        return None
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(422, "Username must be 3-32 lowercase letters, digits, '.', '-' or '_'")
    query = db.query(User.id).filter(User.username == username)
    if exclude_id:
        query = query.filter(User.id != exclude_id)
    if query.first():
        raise HTTPException(409, "That username is taken")
    return username
