"""Event log and audit log pages.

/events  — chronological device state-change timeline, filterable by device and
           date range (the brief's Slice 5 requirement).
/audit   — read-only view of admin actions (login attempts, trust, rename,
           delete). Read-only by design: the audit trail is evidence.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, request
from flask_login import login_required

from ..models import AuditLog, Device, Event

events_bp = Blueprint("events", __name__)

PER_PAGE = 50


def _parse_date(value: str | None):
    """Parse a YYYY-MM-DD filter value into a UTC datetime, or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@events_bp.route("/events")
@login_required
def index():
    query = Event.query

    device_id = request.args.get("device_id", type=int)
    if device_id:
        query = query.filter(Event.device_id == device_id)

    date_from = _parse_date(request.args.get("date_from"))
    if date_from:
        query = query.filter(Event.timestamp >= date_from)

    date_to = _parse_date(request.args.get("date_to"))
    if date_to:
        # Inclusive of the whole 'to' day.
        query = query.filter(Event.timestamp < date_to + timedelta(days=1))

    page = request.args.get("page", 1, type=int)
    events = query.order_by(Event.timestamp.desc()).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )

    devices = Device.query.order_by(Device.friendly_name, Device.mac_address).all()
    return render_template(
        "events/list.html",
        events=events,
        devices=devices,
        filters={
            "device_id": device_id,
            "date_from": request.args.get("date_from", ""),
            "date_to": request.args.get("date_to", ""),
        },
    )


@events_bp.route("/audit")
@login_required
def audit():
    page = request.args.get("page", 1, type=int)
    entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=PER_PAGE, error_out=False
    )
    return render_template("events/audit.html", entries=entries)
