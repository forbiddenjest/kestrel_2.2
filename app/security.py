"""Password hashing, opaque DB sessions, CSRF and encrypted node keys."""
import hashlib
import hmac
import secrets
from datetime import timedelta
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from app.config import settings
from app.models import Session, User, utcnow

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Verified against when an account does not exist, so a failed sign-in costs the same time.
DUMMY_HASH = password_hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerifyMismatchError, VerificationError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return password_hasher.check_needs_rehash(password_hash)
    except Exception:
        return False


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(db, user: User, hours: int | None = None):
    raw, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    row = Session(token_hash=digest_token(raw), csrf_hash=digest_token(csrf), user_id=user.id,
                  expires_at=utcnow() + timedelta(hours=hours or settings.session_hours))
    db.add(row)
    db.flush()
    return raw, csrf, row


def node_cipher() -> Fernet:
    return Fernet(settings.encryption_key.get_secret_value().encode())


def encrypt_node_key(value: str) -> str:
    return node_cipher().encrypt(value.encode()).decode()


def decrypt_node_key(value: str) -> str:
    return node_cipher().decrypt(value.encode()).decode()


def csrf_matches(supplied: str, expected_hash: str) -> bool:
    return hmac.compare_digest(digest_token(supplied), expected_hash)
