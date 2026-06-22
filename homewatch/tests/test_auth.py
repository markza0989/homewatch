"""Auth tests: password hashing, login success/failure, @login_required,
and (Slice 6) /login rate limiting."""

from app import create_app
from app.extensions import db as _db
from app.models import User


def test_password_hash_is_argon2id_and_verifies(user):
    # argon2id hashes are prefixed $argon2id$ and never store the plaintext.
    assert user.password_hash.startswith("$argon2id$")
    assert "correct horse battery" not in user.password_hash
    assert user.check_password("correct horse battery") is True
    assert user.check_password("wrong password") is False


def test_dashboard_requires_login(client):
    resp = client.get("/")
    # Anonymous users are redirected to the login page.
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_success_then_dashboard_accessible(client, user):
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data

    # Session persists — the dashboard is now reachable directly.
    assert client.get("/").status_code == 200


def test_login_failure_shows_generic_message(client, user):
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "nope"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data
    # Still anonymous: dashboard redirects back to login.
    assert client.get("/").status_code == 302


def test_login_does_not_reveal_unknown_username(client):
    resp = client.post(
        "/login",
        data={"username": "ghost", "password": "whatever"},
        follow_redirects=True,
    )
    # Same generic message as a wrong password — no user enumeration.
    assert b"Invalid username or password" in resp.data


def test_logout_requires_post_and_clears_session(client, user):
    client.post(
        "/login",
        data={"username": "alice", "password": "correct horse battery"},
        follow_redirects=True,
    )
    assert client.get("/").status_code == 200

    resp = client.post("/logout", follow_redirects=True)
    assert resp.status_code == 200
    # Logged out — dashboard redirects to login again.
    assert client.get("/").status_code == 302


def test_login_is_rate_limited_after_five_attempts():
    # Dedicated app with limiting enabled (it's off in the shared testing config).
    app = create_app("testing", RATELIMIT_ENABLED=True)
    with app.app_context():
        _db.create_all()
        u = User(username="bob")
        u.set_password("hunter2hunter2")
        _db.session.add(u)
        _db.session.commit()

        client = app.test_client()
        # 5 attempts in the window are processed (wrong creds -> 200).
        for _ in range(5):
            assert client.post(
                "/login", data={"username": "bob", "password": "wrong"}
            ).status_code == 200
        # The 6th is rejected by the limiter.
        assert client.post(
            "/login", data={"username": "bob", "password": "wrong"}
        ).status_code == 429
        # A correct password is also blocked while throttled.
        assert client.post(
            "/login", data={"username": "bob", "password": "hunter2hunter2"}
        ).status_code == 429

        _db.drop_all()
