"""Helpers for writing to the two log tables.

`record_event`  -> events table (device state changes; also called by the scanner).
`record_audit`  -> audit_log table (admin write actions: logins, trust, rename, delete).

Neither commits by default — the caller owns the transaction boundary so an
action and its log entry commit atomically. `record_event` is request-context
free so the scanner process can use it too; `record_audit` pulls the actor and
client IP from the request context.
"""
import json

from flask import has_request_context, request
from flask_login import current_user

from .extensions import db
from .models import AuditLog, Event, utcnow


def record_event(event_type, mac, device_id=None, details=None, commit=False):
    db.session.add(
        Event(
            device_id=device_id,
            mac_address=mac,
            event_type=event_type,
            timestamp=utcnow(),
            details=json.dumps(details) if details else None,
        )
    )
    if commit:
        db.session.commit()


def record_audit(action, username=None, user_id=None, details=None, commit=False):
    """Record an admin action. Actor defaults to the logged-in user; pass
    `username` explicitly for events with no/!= session actor (e.g. login_fail)."""
    if username is None and current_user and current_user.is_authenticated:
        username = current_user.username
        user_id = current_user.id
    ip_address = request.remote_addr if has_request_context() else None
    db.session.add(
        AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            ip_address=ip_address,
            timestamp=utcnow(),
            details=json.dumps(details) if details else None,
        )
    )
    if commit:
        db.session.commit()
