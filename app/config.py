"""Environment-only settings for the Kestrel control plane."""
import base64
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_SECRETS = {"replace-with-a-long-random-value", "replace-with-a-Fernet-key", "change-me", ""}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False, env_prefix="KESTREL_")
    app_name: str = "Kestrel"
    environment: str = "production"
    database_url: str = "sqlite:////var/lib/kestrel/kestrel.db"
    db_pool_size: int = Field(default=20, ge=1, le=200)
    db_max_overflow: int = Field(default=40, ge=0, le=400)
    media_path: str = "/var/lib/kestrel/media"
    # Parent for the per-call libvirt key directory. Empty = the system temp dir, which
    # both systemd units make private to the service with PrivateTmp=true.
    runtime_dir: str = ""
    # Largest request body the panel accepts (forms only; there is no upload endpoint).
    max_request_kb: int = Field(default=1024, ge=64, le=65536)
    session_hours: int = Field(default=12, ge=1, le=720)
    session_cookie: str = "kestrel_session"
    secret_key: SecretStr
    encryption_key: SecretStr
    trusted_host: str = "vps.mydomain.xyz"
    secure_cookies: bool = True
    login_ip_limit: int = Field(default=10, ge=1, le=100)
    login_account_limit: int = Field(default=8, ge=1, le=100)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)
    worker_interval_seconds: int = Field(default=2, ge=1, le=60)
    worker_concurrency: int = Field(default=8, ge=1, le=64)
    metrics_interval_seconds: int = Field(default=10, ge=5, le=300)
    metrics_retention_days: int = Field(default=7, ge=1, le=365)
    audit_retention_days: int = Field(default=365, ge=30, le=3650)


def production_problems(s: "Settings") -> list[str]:
    """Configuration that must never reach production. Checked at web and worker start."""
    if s.environment == "development":
        return []
    problems = []
    secret = s.secret_key.get_secret_value()
    if secret in PLACEHOLDER_SECRETS or len(secret) < 32:
        problems.append("KESTREL_SECRET_KEY must be a unique random value of at least 32 characters")
    try:
        if len(base64.urlsafe_b64decode(s.encryption_key.get_secret_value().encode())) != 32:
            raise ValueError
    except Exception:
        problems.append("KESTREL_ENCRYPTION_KEY must be a Fernet key (python -m app.setup init-env)")
    if not s.secure_cookies:
        problems.append("KESTREL_SECURE_COOKIES must be true outside development")
    if not s.trusted_host or s.trusted_host in {"*", "vps.mydomain.xyz", "vps.example.com"}:
        problems.append("KESTREL_TRUSTED_HOST must be set to the panel's public hostname")
    return problems


settings = Settings()
