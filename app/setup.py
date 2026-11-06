"""Local first-run setup and explicit administrator bootstrap commands."""
import argparse
import getpass
import os
from pathlib import Path
import secrets

BASE = Path(__file__).resolve().parent.parent
ENV_FILE = BASE / ".env"

def initialize_environment():
    if ENV_FILE.exists():
        raise SystemExit(".env already exists; refusing to replace secrets")
    from cryptography.fernet import Fernet
    ENV_FILE.write_text(
        "KESTREL_ENVIRONMENT=production\n"
        "KESTREL_TRUSTED_HOST=vps.mydomain.xyz\n"
        "KESTREL_DATABASE_URL=sqlite:////var/lib/kestrel/kestrel.db\n"
        f"KESTREL_SECRET_KEY={secrets.token_urlsafe(48)}\n"
        f"KESTREL_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n"
        "KESTREL_SECURE_COOKIES=true\n",
        encoding="utf-8",
    )
    os.chmod(ENV_FILE, 0o600)
    print(f"Created {ENV_FILE} with unique secrets. Set KESTREL_TRUSTED_HOST before starting.")

def create_admin(email: str, username: str = ""):
    from fastapi import HTTPException
    from app.db import SessionLocal
    from app.models import User
    from app.security import hash_password
    from app.services.accounts import validate_email, validate_username
    db = SessionLocal()
    try:
        try:
            normalized = validate_email(db, email)
            name = validate_username(db, username)
        except HTTPException as exc:
            raise SystemExit(str(exc.detail)) from exc
        password = getpass.getpass("New administrator password (12+ characters): ")
        confirm = getpass.getpass("Repeat password: ")
        if password != confirm or len(password) < 12 or len(password) > 256:
            raise SystemExit("Passwords must match and contain 12–256 characters")
        db.add(User(email=normalized, username=name, password_hash=hash_password(password), role="admin", active=True))
        db.commit()
        print("Administrator account created.")
    finally:
        db.close()

def main():
    parser = argparse.ArgumentParser(prog="python -m app.setup")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-env", help="Generate a private .env file")
    admin = sub.add_parser("create-admin", help="Create the first administrator")
    admin.add_argument("email")
    admin.add_argument("--username", default="", help="optional sign-in name")
    args = parser.parse_args()
    if args.command == "init-env":
        initialize_environment()
    elif args.command == "create-admin":
        create_admin(args.email, args.username)

if __name__ == "__main__":
    main()
