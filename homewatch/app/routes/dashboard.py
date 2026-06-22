"""Dashboard route — full-page shell. Live fragments come from the api blueprint."""
from flask import Blueprint, render_template
from flask_login import login_required

from ..forms import AddDeviceForm
from ..models import ScanRun
from .api import untrusted_devices
from .devices import list_devices

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    # Initial server render so there's no empty flash before the first poll;
    # HTMX then refreshes the panels (see api.device_table / api.unknown_panel).
    latest_scan = ScanRun.query.order_by(ScanRun.scan_time.desc()).first()
    return render_template(
        "dashboard/index.html",
        add_form=AddDeviceForm(),
        devices=list_devices(),
        unknown=untrusted_devices(),
        latest_scan=latest_scan,
    )
