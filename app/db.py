"""SQLAlchemy 2 database setup with SQLite WAL and foreign keys."""
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import settings

if settings.database_url.startswith("sqlite:") and settings.database_url not in {"sqlite://", "sqlite:///:memory:"}:
    db_path = settings.database_url.removeprefix("sqlite:///")
    Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
connect_args = {"check_same_thread": False, "timeout": 30} if settings.database_url.startswith("sqlite") else {}
# Long-lived websocket consoles no longer hold a session (see routes/sockets.py), but the
# pool is still sized for bursts of concurrent page loads plus worker tasks.
_memory = settings.database_url in {"sqlite://", "sqlite:///:memory:"}
pool_args = {} if _memory else {"pool_size": settings.db_pool_size, "max_overflow": settings.db_max_overflow, "pool_timeout": 15}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True, **pool_args)
if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def sqlite_pragmas(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

class Base(DeclarativeBase):
    pass

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
