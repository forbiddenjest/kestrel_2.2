"""Authenticated websocket SSH console: node, guest IP and pinned guest host key all come from the database."""
import asyncio
from contextlib import suppress
from datetime import timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session as DBSession
from app.db import SessionLocal
from app.config import settings
from app.models import Machine, Session as LoginSession, utcnow
from app.security import digest_token
from app.services.libvirt import open_console
from app.services.machines import ID_RE, VM_RE

router = APIRouter()
# How often an open console re-checks that the session, account and machine are still valid.
RECHECK_SECONDS = 30
MAX_INPUT_CHUNK = 64 * 1024


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def console_allowed(token_hash: str, machine_id: str) -> bool:
    """True while the session is valid, the account active and the machine still theirs and running."""
    db = SessionLocal()
    try:
        session = db.get(LoginSession, token_hash)
        if not session or not session.user.active or session.user.force_password_change:
            return False
        expires = _aware(session.expires_at)
        if not expires or expires <= utcnow():
            return False
        machine = db.get(Machine, machine_id)
        if not machine or machine.state != "running":
            return False
        return session.user.role == "admin" or machine.owner_id == session.user_id
    finally:
        db.close()


@router.websocket("/ws/machines/{machine_id}/console")
async def console(websocket: WebSocket, machine_id: str):
    db: DBSession | None = SessionLocal()
    connection = process = None
    try:
        origin = websocket.headers.get("origin", "")
        expected_origin = f"https://{settings.trusted_host}" if settings.secure_cookies else f"http://{websocket.headers.get('host', '')}"
        if origin.rstrip("/") != expected_origin.rstrip("/") or not ID_RE.fullmatch(machine_id):
            await websocket.close(code=4403)
            return
        raw = websocket.cookies.get(settings.session_cookie)
        token_hash = digest_token(raw) if raw and len(raw) <= 256 else ""
        session = db.get(LoginSession, token_hash) if token_hash else None
        expires = _aware(session.expires_at) if session else None
        if not session or not session.user.active or not expires or expires <= utcnow() or session.user.force_password_change:
            await websocket.close(code=4401)
            return
        machine = db.get(Machine, machine_id)
        if not machine or (session.user.role != "admin" and machine.owner_id != session.user_id) or not VM_RE.fullmatch(machine.vm_name):
            await websocket.close(code=4403)
            return
        if machine.state != "running":
            await websocket.close(code=4409)
            return
        # Load everything the console needs, then hand the pooled connection back
        # before streaming. A console can stay open for hours; holding a session for
        # that long exhausted the pool after ~15 consoles and hung every page.
        cluster, _ip = machine.cluster, machine.cluster_ip
        db.expunge_all()
        db.close(); db = None
        connection, process = await open_console(cluster, machine)
        await websocket.accept()

        async def to_browser():
            while True:
                message = await process.stdout.read(4096)
                if not message:
                    break
                await websocket.send_bytes(message)

        async def to_node():
            while True:
                data = await websocket.receive_bytes()
                if len(data) > MAX_INPUT_CHUNK:
                    break
                process.stdin.write(data)
                await process.stdin.drain()

        async def watchdog():
            # Signing out, suspension, a role change, an ownership change or the machine
            # stopping all end an open console within RECHECK_SECONDS.
            while True:
                await asyncio.sleep(RECHECK_SECONDS)
                if not await asyncio.to_thread(console_allowed, token_hash, machine_id):
                    break

        tasks = {asyncio.create_task(to_browser()), asyncio.create_task(to_node()), asyncio.create_task(watchdog())}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        pass
    except Exception:
        # Also close when the failure happens before accept(), otherwise the browser
        # handshake is left hanging until the proxy times it out.
        if websocket.application_state.name in {"CONNECTING", "CONNECTED"}:
            with suppress(Exception):
                await websocket.close(code=1011)
    finally:
        if process:
            process.close()
        for item in connection or ():
            item.close()
        if db is not None:
            db.close()
