"""Slice 4 tests: HTMX partial endpoints (device table + unknown panel)."""
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


def _add_device(app, mac, trusted, status="online"):
    with app.app_context():
        db.session.add(Device(mac_address=mac, trusted=trusted, status=status))
        db.session.commit()


def test_partials_require_login(client):
    for path in ("/api/partials/devices", "/api/partials/unknown"):
        resp = client.get(path)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_device_table_lists_all_devices(logged_in, app):
    _add_device(app, "aa:bb:cc:00:00:01", trusted=True)
    _add_device(app, "de:ad:be:ef:00:99", trusted=False)
    resp = logged_in.get("/api/partials/devices")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "aa:bb:cc:00:00:01" in body
    assert "de:ad:be:ef:00:99" in body
    # Fragment, not a full page.
    assert "<html" not in body.lower()


def test_unknown_panel_shows_only_untrusted(logged_in, app):
    _add_device(app, "aa:bb:cc:00:00:01", trusted=True)
    _add_device(app, "de:ad:be:ef:00:99", trusted=False)
    body = logged_in.get("/api/partials/unknown").data.decode()
    assert "NEW / UNTRUSTED" in body
    assert "de:ad:be:ef:00:99" in body      # the untrusted one is flagged
    assert "aa:bb:cc:00:00:01" not in body  # the trusted one is not


def test_unknown_panel_all_clear_when_no_untrusted(logged_in, app):
    _add_device(app, "aa:bb:cc:00:00:01", trusted=True)
    body = logged_in.get("/api/partials/unknown").data.decode()
    assert "No unknown devices" in body
    assert "NEW / UNTRUSTED" not in body


def test_device_table_carries_csrf_tokens_for_actions(logged_in, app):
    _add_device(app, "aa:bb:cc:00:00:01", trusted=False)
    body = logged_in.get("/api/partials/devices").data.decode()
    # Each re-render must embed a fresh CSRF token for the POST action forms.
    assert "csrf_token" in body
