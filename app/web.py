"""Shared server-rendered template environment."""
from pathlib import Path
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

APP_VERSION = "2.2"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
# Autoescaping is on for every template. Only the static icon set in components.html is
# marked |safe; nothing user-supplied ever is.
_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
templates = Jinja2Templates(env=_env)


def format_uptime(seconds):
    """Render Machine.uptime() as e.g. '3d 4h', '2h 15m', '42s'; '—' when not running."""
    if seconds is None:
        return "—"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days: return f"{days}d {hours}h"
    if hours: return f"{hours}h {minutes}m"
    if minutes: return f"{minutes}m {secs}s"
    return f"{secs}s"


def support_url() -> str:
    """Support link for the sidebar button; short-lived session so templates stay simple."""
    from app.db import SessionLocal
    from app.services.panel_settings import SUPPORT_URL, get_setting
    db = SessionLocal()
    try:
        return get_setting(db, SUPPORT_URL)
    except Exception:
        return ""
    finally:
        db.close()


def active_notices():
    from app.db import SessionLocal
    from app.models import Notice
    db = SessionLocal()
    try:
        return db.query(Notice).filter(Notice.active.is_(True)).order_by(Notice.created_at.desc(), Notice.id.desc()).limit(5).all()
    except Exception:
        return []
    finally:
        db.close()


from app.services.panel_settings import NOTICE_KINDS, country_code, flag_url  # noqa: E402
from app.services.images import OS_FAMILIES, OS_LOGOS  # noqa: E402
from app.services.traffic import human_bytes, human_speed  # noqa: E402

_env.filters["uptime"] = format_uptime
_env.filters["bytes"] = human_bytes
_env.filters["speed"] = human_speed
_env.globals["active_notices"] = active_notices
_env.globals["notice_kinds"] = NOTICE_KINDS
_env.globals["flag_url"] = flag_url
_env.globals["country_code"] = country_code
_env.globals["os_families"] = OS_FAMILIES
_env.globals["os_logos"] = OS_LOGOS
_env.globals["support_url"] = support_url
_env.globals["app_version"] = APP_VERSION
