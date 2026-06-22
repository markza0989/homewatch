"""Flask extension singletons.

Instantiated unbound here so both the Flask app factory and the (future,
separate-process) scheduler can import the same `db` without circular imports.
"""
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, _connection_record):
    """Enable WAL + a busy timeout on SQLite connections.

    The Flask app and the separate scanner process both write to the same
    SQLite file. WAL lets readers and a writer coexist; the busy timeout makes
    a brief lock contention wait-and-retry instead of erroring immediately.
    Guarded to SQLite so it's inert for any other backend.
    """
    if "sqlite" not in type(dbapi_connection).__module__:
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Rate limiter. No global default limits — the only limit for MVP is on /login
# (applied in the auth blueprint in Slice 6). Storage configured per-app.
limiter = Limiter(key_func=get_remote_address)

login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"
