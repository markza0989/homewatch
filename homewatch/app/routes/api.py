"""HTMX partial endpoints.

These return HTML fragments (not full pages) for the dashboard to poll every
15s. GET-only and login-gated; no CSRF needed on reads. The POST mutation forms
embedded in the fragments carry their own CSRF tokens (re-rendered each poll).
"""
from flask import Blueprint, render_template
from flask_login import login_required

from ..models import Device, ScanRun
from .devices import list_devices

api_bp = Blueprint("api", __name__, url_prefix="/api")


def untrusted_devices():
    """Untrusted devices, newest first — these are the ones demanding attention."""
    return (
        Device.query.filter_by(trusted=False)
        .order_by(Device.first_seen.desc())
        .all()
    )


@api_bp.route("/partials/devices")
@login_required
def device_table():
    latest_scan = ScanRun.query.order_by(ScanRun.scan_time.desc()).first()
    return render_template(
        "partials/device_table.html",
        devices=list_devices(),
        latest_scan=latest_scan,
    )


@api_bp.route("/partials/unknown")
@login_required
def unknown_panel():
    return render_template(
        "partials/unknown_panel.html", unknown=untrusted_devices()
    )
