"""Administrator-configurable panel settings: support link, notices and locations."""
import re
from urllib.parse import urlparse
from fastapi import HTTPException
from app.models import Setting

SUPPORT_URL = "support_url"
SUPPORT_HOSTS = {"discord.gg", "discord.com", "www.discord.com"}


def get_setting(db, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if row and row.value else default


def set_setting(db, key: str, value: str):
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def validate_support_url(url: str) -> str:
    """Empty clears the link. Otherwise only an https Discord invite is accepted, so
    the Support button can never be turned into an arbitrary redirect."""
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if (
        len(url) > 300
        or parsed.scheme != "https"
        or (parsed.hostname or "").lower() not in SUPPORT_HOSTS
        or parsed.username
        or parsed.password
        or parsed.port
    ):
        raise HTTPException(422, "Use an https Discord invite link, e.g. https://discord.gg/yourcode")
    path = parsed.path.strip("/")
    if parsed.hostname.lower() == "discord.gg":
        ok = bool(path) and "/" not in path
    else:
        ok = path.startswith("invite/") and len(path) > len("invite/")
    if not ok:
        raise HTTPException(422, "Use an https Discord invite link, e.g. https://discord.gg/yourcode")
    return url


# ISO 3166-1 alpha-2 codes that flagcdn.com serves.
ISO_CODES = set("""ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge
gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp
kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf
ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn
so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws xk ye yt
za zm zw""".split())
ALIASES = {"uk": "gb", "el": "gr"}
LOCATION_ID_RE = re.compile(r"^[A-Za-z]{2}$")
FLAG_WIDTH = 320  # flagcdn widths: 20,40,80,160,320,640,1280,2560. 320 is crisp at 2x for the 48-96px display.


def country_code(location_id: str) -> str:
    code = (location_id or "").strip().lower()
    code = ALIASES.get(code, code)
    return code if code in ISO_CODES else ""


def flag_url(location_id: str, width: int = FLAG_WIDTH) -> str:
    code = country_code(location_id)
    return f"https://flagcdn.com/w{int(width)}/{code}.png" if code else ""


def validate_location(location: str, location_id: str) -> tuple[str, str]:
    """location_id is an ISO 3166-1 alpha-2 country code (IN, US, DE ...); location is free text."""
    location, location_id = (location or "").strip(), (location_id or "").strip().upper()
    if len(location) > 80:
        raise HTTPException(422, "Location must be 80 characters or fewer")
    if any(ord(ch) < 32 for ch in location):
        raise HTTPException(422, "Location contains invalid characters")
    if location_id and (not LOCATION_ID_RE.fullmatch(location_id) or not country_code(location_id)):
        raise HTTPException(422, "Location ID must be a two-letter country code such as IN, US or DE")
    return location, location_id


# ---------- notices ----------

NOTICE_KINDS = {
    "info": ("Information", "info"),
    "update": ("Update", "update"),
    "maintenance": ("Maintenance", "settings"),
    "warning": ("Warning", "alert"),
    "alert": ("Alert", "alert"),
    "success": ("Resolved", "check"),
}


def validate_notice(kind: str, title: str, message: str) -> tuple[str, str, str]:
    title, message = (title or "").strip(), (message or "").strip()
    if kind not in NOTICE_KINDS:
        raise HTTPException(422, "Choose a notice type")
    if not title or len(title) > 120:
        raise HTTPException(422, "Enter a title of up to 120 characters")
    if len(message) > 1000:
        raise HTTPException(422, "Message must be 1000 characters or fewer")
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in title + message):
        raise HTTPException(422, "Notice contains invalid characters")
    return kind, title, message
