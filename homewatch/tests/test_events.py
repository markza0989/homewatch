"""Slice 5 tests: event emission on CRUD, audit logging, and the events page."""
from datetime import timedelta

import pytest

from app.extensions import db
from app.models import AuditLog, Device, Event, utcnow


@pytest.fixture
def logged_in(client, user):
    client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    return client


def _make_device(app, mac="aa:bb:cc:00:00:01", trusted=False):
    with app.app_context():
        d = Device(mac_address=mac, trusted=trusted, status="online")
        db.session.add(d)
        db.session.commit()
        return d.id


# --- audit logging on auth ------------------------------------------------

def test_login_success_writes_audit(client, user, app):
    client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery"},
    )
    with app.app_context():
        entry = AuditLog.query.filter_by(action="login_success").one()
        assert entry.username == "alice"


def test_login_fail_writes_audit_with_attempted_username(client, user, app):
    client.post("/login", data={"username": "alice", "password": "wrong"})
    with app.app_context():
        entry = AuditLog.query.filter_by(action="login_fail").one()
        assert entry.username == "alice"  # attempted name recorded for investigation


def test_login_fail_unknown_user_still_audited(client, app):
    client.post("/login", data={"username": "ghost", "password": "x"})
    with app.app_context():
        assert AuditLog.query.filter_by(action="login_fail").count() == 1


# --- CRUD emits events + audit --------------------------------------------

def test_manual_add_emits_first_seen_and_audit(logged_in, app):
    logged_in.post(
        "/devices/add",
        data={"mac_address": "aa:bb:cc:00:00:01", "friendly_name": "TV"},
        follow_redirects=True,
    )
    with app.app_context():
        assert Event.query.filter_by(event_type="first_seen").count() == 1
        assert AuditLog.query.filter_by(action="device_added").count() == 1


def test_toggle_trust_emits_event_and_audit(logged_in, app):
    device_id = _make_device(app, trusted=False)
    logged_in.post(f"/devices/{device_id}/trust", follow_redirects=True)
    with app.app_context():
        assert Event.query.filter_by(event_type="marked_trusted").count() == 1
        assert AuditLog.query.filter_by(action="device_trusted").count() == 1


def test_rename_emits_renamed_event_and_audit(logged_in, app):
    device_id = _make_device(app)
    logged_in.post(
        f"/devices/{device_id}/edit",
        data={"friendly_name": "New name", "trusted": "y"},
        follow_redirects=True,
    )
    with app.app_context():
        assert Event.query.filter_by(event_type="renamed").count() == 1
        assert AuditLog.query.filter_by(action="device_renamed").count() == 1


def test_delete_emits_event_audit_and_preserves_history(logged_in, app):
    device_id = _make_device(app)
    with app.app_context():
        # Pre-existing event referencing the device (e.g. a prior first_seen).
        db.session.add(Event(device_id=device_id, mac_address="aa:bb:cc:00:00:01",
                             event_type="first_seen", timestamp=utcnow()))
        db.session.commit()

    logged_in.post(f"/devices/{device_id}/delete", follow_redirects=True)
    with app.app_context():
        assert db.session.get(Device, device_id) is None
        # Delete event recorded, and the old event survived (detached, mac kept).
        assert Event.query.filter_by(event_type="deleted").count() == 1
        old = Event.query.filter_by(event_type="first_seen").one()
        assert old.device_id is None
        assert old.mac_address == "aa:bb:cc:00:00:01"
        assert AuditLog.query.filter_by(action="device_deleted").count() == 1


# --- events page + filters -------------------------------------------------

def test_events_page_requires_login(client):
    resp = client.get("/events")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_events_page_filters_by_device(logged_in, app):
    d1 = _make_device(app, mac="aa:bb:cc:00:00:01")
    d2 = _make_device(app, mac="de:ad:be:ef:00:99")
    with app.app_context():
        db.session.add(Event(device_id=d1, mac_address="aa:bb:cc:00:00:01",
                             event_type="first_seen", timestamp=utcnow()))
        db.session.add(Event(device_id=d2, mac_address="de:ad:be:ef:00:99",
                             event_type="first_seen", timestamp=utcnow()))
        db.session.commit()

    body = logged_in.get(f"/events?device_id={d1}").data.decode()
    # Check the events table specifically (MACs render in <code>); the other
    # device still appears in the filter dropdown, which is expected.
    assert "<code>aa:bb:cc:00:00:01</code>" in body
    assert "<code>de:ad:be:ef:00:99</code>" not in body


def test_events_page_filters_by_date_range(logged_in, app):
    d1 = _make_device(app)
    with app.app_context():
        old = utcnow() - timedelta(days=10)
        db.session.add(Event(device_id=d1, mac_address="aa:bb:cc:00:00:01",
                             event_type="came_online", timestamp=old))
        db.session.add(Event(device_id=d1, mac_address="aa:bb:cc:00:00:01",
                             event_type="went_offline", timestamp=utcnow()))
        db.session.commit()

    # Only today onward -> the 10-day-old event is excluded.
    today = utcnow().strftime("%Y-%m-%d")
    body = logged_in.get(f"/events?date_from={today}").data.decode()
    assert "went_offline" in body
    assert "came_online" not in body
