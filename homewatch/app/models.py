"""SQLAlchemy models for HomeWatch.

The full schema is defined in Slice 1 so `init-db` creates every table up front
and later slices need no migrations. Only `User` is exercised until Slice 2+.

Conventions:
- MAC addresses are stored lowercase, colon-separated (normalised on the way in).
- Timestamps are timezone-aware UTC.
"""
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask_login import UserMixin

from .extensions import db

# argon2id is the default variant for PasswordHasher — meets the brief.
_password_hasher = PasswordHasher()


def utcnow() -> datetime:
    """Timezone-aware UTC now. Centralised so every model agrees."""
    return datetime.now(timezone.utc)


def normalize_mac(mac: str) -> str:
    """Lowercase, colon-separated canonical form. Validation lives at the form
    layer (Slice 2); this just canonicalises an already-validated string."""
    return mac.strip().lower().replace("-", ":")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = _password_hasher.hash(password)

    def check_password(self, password: str) -> bool:
        try:
            _password_hasher.verify(self.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        # Transparently upgrade the hash if argon2 params have changed.
        if _password_hasher.check_needs_rehash(self.password_hash):
            self.password_hash = _password_hasher.hash(password)
        return True

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False, index=True)
    current_ip = db.Column(db.String(45), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    vendor = db.Column(db.String(255), nullable=True)
    friendly_name = db.Column(db.String(64), nullable=True)
    trusted = db.Column(db.Boolean, nullable=False, default=False)
    first_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    status = db.Column(db.String(16), nullable=False, default="unknown")  # online|offline|unknown
    notes = db.Column(db.Text, nullable=True)

    events = db.relationship("Event", backref="device", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Device {self.mac_address} status={self.status}>"


class ScanRun(db.Model):
    __tablename__ = "scan_runs"

    id = db.Column(db.Integer, primary_key=True)
    scan_time = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    devices_found = db.Column(db.Integer, nullable=False)
    duration_ms = db.Column(db.Integer, nullable=False)


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True)
    mac_address = db.Column(db.String(17), nullable=False, index=True)
    # first_seen|came_online|went_offline|ip_changed|marked_trusted|
    # marked_untrusted|renamed|deleted
    event_type = db.Column(db.String(32), nullable=False, index=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    details = db.Column(db.Text, nullable=True)  # JSON string


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    # Denormalised so the record survives a user delete.
    username = db.Column(db.String(64), nullable=True)
    # login_success|login_fail|device_trusted|device_renamed|device_deleted
    action = db.Column(db.String(32), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    details = db.Column(db.Text, nullable=True)  # JSON string
