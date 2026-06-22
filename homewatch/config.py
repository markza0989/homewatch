"""Configuration classes for HomeWatch.

Selected via the HOMEWATCH_CONFIG env var (development | production | testing).
Secrets come from the environment / .env only — nothing real is hardcoded here.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _resolve_db_uri() -> str:
    """Resolve DATABASE_URL, anchoring relative sqlite paths to the project root.

    Flask-SQLAlchemy otherwise resolves a relative ``sqlite:///x.db`` against its
    instance folder, which surprises operators who expect the DB at the project
    root. Anchoring here keeps the location predictable no matter how it's run.
    """
    uri = os.environ.get("DATABASE_URL")
    if not uri:
        return f"sqlite:///{BASE_DIR / 'homewatch.db'}"
    prefix = "sqlite:///"
    if uri.startswith(prefix):
        path = uri[len(prefix):]
        # Absolute sqlite URIs use four slashes (sqlite:////abs/path); leave those.
        if path and not path.startswith("/") and not Path(path).is_absolute():
            return f"{prefix}{BASE_DIR / path}"
    return uri


class Config:
    """Base config — shared defaults."""

    SECRET_KEY = os.environ.get("SECRET_KEY")

    # DB lives at the project root unless an absolute DATABASE_URL is given.
    SQLALCHEMY_DATABASE_URI = _resolve_db_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening. Secure is off in dev (no TLS on localhost),
    # flipped on in production where the operator is expected to front this
    # with a TLS-terminating reverse proxy.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    # Input length caps (enforced again at the form layer in Slice 2).
    MAX_FRIENDLY_NAME_LEN = 64
    MAX_NOTES_LEN = 1000

    # Flask-Limiter storage. In-memory is fine for a single-process Flask app;
    # production swap to Redis is documented in THREAT_MODEL.md.
    RATELIMIT_STORAGE_URI = "memory://"

    # Scanner config (consumed from Slice 3 onward).
    HOMEWATCH_SUBNET = os.environ.get("HOMEWATCH_SUBNET") or None
    SCAN_BACKEND = os.environ.get("HOMEWATCH_SCAN_BACKEND", "mock")
    # Optional ICMP follow-up: before marking a stale device offline, ping its
    # last known IP once. Off by default — keeps the offline sweep fast and
    # privilege-free; the documented behaviour stays purely last_seen-based.
    SCAN_ICMP_CONFIRM = os.environ.get("HOMEWATCH_ICMP_CONFIRM", "").lower() in (
        "1",
        "true",
        "yes",
    )


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = False
    # Isolated in-memory DB so tests never touch a real file.
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret-key"
    WTF_CSRF_ENABLED = False  # exercised explicitly where it matters, off elsewhere
    SCAN_BACKEND = "mock"
    RATELIMIT_ENABLED = False  # turned on in the rate-limit tests (Slice 6)


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None = None):
    """Resolve a config class by name, defaulting to development."""
    name = (name or os.environ.get("HOMEWATCH_CONFIG", "development")).lower()
    return CONFIG_MAP.get(name, DevelopmentConfig)
