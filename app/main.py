"""Kestrel application entry point."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.config import production_problems, settings
from app.db import SessionLocal
from app.deps import set_security_headers
from app.routes import account, administrator, auth, machines, sockets
from app.web import templates

ROOT = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app):
    problems = production_problems(settings)
    if problems:
        raise RuntimeError("Refusing to start: " + "; ".join(problems))
    yield


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
allowed_hosts = ["*"] if settings.environment == "development" else [settings.trusted_host, "localhost", "127.0.0.1"]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.middleware("http")(set_security_headers)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
app.include_router(auth.router)
app.include_router(account.router)
app.include_router(machines.router)
app.include_router(administrator.router)
app.include_router(administrator.node_router)
app.include_router(sockets.router)

GENERIC = {
    400: "The request could not be completed.",
    403: "You do not have access to this page.",
    404: "This page does not exist.",
    405: "That action is not allowed here.",
    409: "The request conflicts with the current state.",
    413: "The request is too large.",
    422: "Some fields are missing or invalid.",
}


@app.get("/", include_in_schema=False)
async def home():
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness for the reverse proxy / monitoring. Reveals nothing beyond up or down."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return PlainTextResponse("ok")
    except Exception:
        return PlainTextResponse("database unavailable", status_code=503)
    finally:
        db.close()


def _error_page(request: Request, status: int, message: str):
    return templates.TemplateResponse(request, "errors.html", {"status": status, "message": message}, status_code=status)


# Registered on Starlette's base class, so the router's own 404/405 responses (raised as
# starlette HTTPException) render the error page too, not only FastAPI's subclass.
@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    headers = getattr(exc, "headers", None) or {}
    location = headers.get("Location", "")
    # Only same-site paths are ever used as redirect targets.
    if exc.status_code in {401, 303} and location.startswith("/") and not location.startswith("//"):
        return RedirectResponse(location, status_code=303)
    if exc.status_code == 401:
        return RedirectResponse("/auth", status_code=303)
    detail = exc.detail if isinstance(exc.detail, str) and exc.detail else ""
    # Starlette's stock phrases ("Not Found") are replaced with friendlier copy.
    if detail in {"Not Found", "Method Not Allowed", "Bad Request", "Forbidden", ""}:
        detail = GENERIC.get(exc.status_code, "The request could not be completed.")
    if exc.status_code >= 500:
        detail = "The request could not be completed."
    return _error_page(request, exc.status_code, detail)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, _exc: RequestValidationError):
    return _error_page(request, 422, GENERIC[422])


@app.exception_handler(Exception)
async def server_error(request: Request, _exc: Exception):
    # Never leak a traceback or exception text to the browser.
    return _error_page(request, 500, "The request could not be completed.")
