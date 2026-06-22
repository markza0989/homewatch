"""Slice 2 tests: manual device CRUD, validation, and auth gating."""
import pytest

from app.extensions import db
from app.models import Device


@pytest.fixture
def logged_in(client, user):
    client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    return client


def test_device_routes_require_login(client):
    # Anonymous POST to a mutation is redirected to login, nothing created.
    resp = client.post("/devices/add", data={"mac_address": "aa:bb:cc:dd:ee:ff"})
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_add_valid_device_normalises_mac(logged_in, app):
    resp = logged_in.post(
        "/devices/add",
        data={
            "mac_address": "AA-BB-CC-DD-EE-FF",  # uppercase + hyphens
            "friendly_name": "Office laptop",
            "trusted": "y",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        d = Device.query.one()
        assert d.mac_address == "aa:bb:cc:dd:ee:ff"  # normalised
        assert d.friendly_name == "Office laptop"
        assert d.trusted is True
        assert d.status == "unknown"


def test_add_rejects_malformed_mac(logged_in, app):
    resp = logged_in.post(
        "/devices/add",
        data={"mac_address": "not-a-mac", "friendly_name": "x"},
    )
    assert resp.status_code == 400
    assert b"valid MAC address" in resp.data
    with app.app_context():
        assert Device.query.count() == 0


def test_add_rejects_duplicate_mac(logged_in, app):
    payload = {"mac_address": "aa:bb:cc:dd:ee:ff", "friendly_name": "first"}
    logged_in.post("/devices/add", data=payload, follow_redirects=True)
    resp = logged_in.post(
        "/devices/add",
        data={"mac_address": "AA:BB:CC:DD:EE:FF", "friendly_name": "dup"},
        follow_redirects=True,
    )
    assert b"already exists" in resp.data
    with app.app_context():
        assert Device.query.count() == 1


def test_add_enforces_friendly_name_length_cap(logged_in, app):
    resp = logged_in.post(
        "/devices/add",
        data={"mac_address": "aa:bb:cc:dd:ee:ff", "friendly_name": "x" * 65},
    )
    assert resp.status_code == 400
    with app.app_context():
        assert Device.query.count() == 0


def test_toggle_trust_flips_state(logged_in, app):
    with app.app_context():
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", trusted=False, status="unknown")
        db.session.add(d)
        db.session.commit()
        device_id = d.id

    logged_in.post(f"/devices/{device_id}/trust", follow_redirects=True)
    with app.app_context():
        assert db.session.get(Device, device_id).trusted is True

    logged_in.post(f"/devices/{device_id}/trust", follow_redirects=True)
    with app.app_context():
        assert db.session.get(Device, device_id).trusted is False


def test_edit_updates_fields(logged_in, app):
    with app.app_context():
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", trusted=False, status="unknown")
        db.session.add(d)
        db.session.commit()
        device_id = d.id

    logged_in.post(
        f"/devices/{device_id}/edit",
        data={"friendly_name": "Renamed", "notes": "moved to garage", "trusted": "y"},
        follow_redirects=True,
    )
    with app.app_context():
        d = db.session.get(Device, device_id)
        assert d.friendly_name == "Renamed"
        assert d.notes == "moved to garage"
        assert d.trusted is True


def test_delete_removes_device(logged_in, app):
    with app.app_context():
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", status="unknown")
        db.session.add(d)
        db.session.commit()
        device_id = d.id

    logged_in.post(f"/devices/{device_id}/delete", follow_redirects=True)
    with app.app_context():
        assert db.session.get(Device, device_id) is None


def test_delete_missing_device_404(logged_in):
    assert logged_in.post("/devices/9999/delete").status_code == 404
