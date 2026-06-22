"""Manual device inventory CRUD.

Every mutation is POST-only and CSRF-protected, and records both a device event
and an audit-log entry (see app/audit.py) within the same transaction.
"""
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required

from ..audit import record_audit, record_event
from ..extensions import db
from ..forms import AddDeviceForm, EditDeviceForm
from ..models import Device, Event, normalize_mac, utcnow

devices_bp = Blueprint("devices", __name__, url_prefix="/devices")


def list_devices():
    """Untrusted devices first (they want attention), then most-recent first."""
    return (
        Device.query.order_by(Device.trusted.asc(), Device.first_seen.desc()).all()
    )


@devices_bp.route("/add", methods=["POST"])
@login_required
def add():
    form = AddDeviceForm()
    if form.validate_on_submit():
        mac = normalize_mac(form.mac_address.data)
        if Device.query.filter_by(mac_address=mac).first():
            flash(f"A device with MAC {mac} already exists.", "warning")
        else:
            now = utcnow()
            device = Device(
                mac_address=mac,
                friendly_name=form.friendly_name.data or None,
                notes=form.notes.data or None,
                trusted=form.trusted.data,
                status="unknown",  # no scan data yet
                first_seen=now,
                last_seen=now,
            )
            db.session.add(device)
            db.session.flush()  # assign device.id
            record_event("first_seen", mac, device.id, {"source": "manual"})
            record_audit("device_added", details={"mac": mac})
            db.session.commit()
            flash(f"Added device {mac}.", "success")
            return redirect(url_for("dashboard.index"))

    # Validation failed — re-render the dashboard with the form's errors intact.
    return (
        render_template(
            "dashboard/index.html", add_form=form, devices=list_devices()
        ),
        400,
    )


@devices_bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
def edit(device_id: int):
    device = db.session.get(Device, device_id) or abort(404)
    form = EditDeviceForm(obj=device)
    if form.validate_on_submit():
        old_name = device.friendly_name
        old_trusted = device.trusted
        new_name = form.friendly_name.data or None

        device.friendly_name = new_name
        device.notes = form.notes.data or None
        device.trusted = form.trusted.data

        if new_name != old_name:
            record_event(
                "renamed", device.mac_address, device.id,
                {"old": old_name, "new": new_name},
            )
            record_audit(
                "device_renamed",
                details={"mac": device.mac_address, "old": old_name, "new": new_name},
            )
        if device.trusted != old_trusted:
            _record_trust_change(device)

        db.session.commit()
        flash("Device updated.", "success")
        return redirect(url_for("dashboard.index"))
    return render_template("devices/edit.html", form=form, device=device)


@devices_bp.route("/<int:device_id>/trust", methods=["POST"])
@login_required
def toggle_trust(device_id: int):
    device = db.session.get(Device, device_id) or abort(404)
    device.trusted = not device.trusted
    _record_trust_change(device)
    db.session.commit()
    state = "trusted" if device.trusted else "untrusted"
    flash(f"Marked {device.mac_address} as {state}.", "success")
    return redirect(request.referrer or url_for("dashboard.index"))


def _record_trust_change(device: Device) -> None:
    """Emit the matching event + audit entry for a trust flip (caller commits)."""
    event_type = "marked_trusted" if device.trusted else "marked_untrusted"
    record_event(event_type, device.mac_address, device.id)
    record_audit(
        "device_trusted",
        details={"mac": device.mac_address, "trusted": device.trusted},
    )


@devices_bp.route("/<int:device_id>/delete", methods=["POST"])
@login_required
def delete(device_id: int):
    device = db.session.get(Device, device_id) or abort(404)
    mac = device.mac_address

    # Detach historical events from the FK so the audit/event trail survives the
    # delete (mac is denormalised on every event). foreign_keys=ON would
    # otherwise block the delete; SET NULL keeps the timeline intact.
    Event.query.filter_by(device_id=device.id).update(
        {Event.device_id: None}, synchronize_session=False
    )
    db.session.delete(device)
    record_event("deleted", mac, None, {"former_device_id": device_id})
    record_audit("device_deleted", details={"mac": mac})
    db.session.commit()

    flash(f"Deleted device {mac}.", "info")
    return redirect(url_for("dashboard.index"))
