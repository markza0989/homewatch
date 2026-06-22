"""Shared pytest fixtures."""
import pytest

from app import create_app
from app.extensions import db as _db
from app.models import User


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app):
    """A known user to log in as. Password: 'correct horse battery'."""
    u = User(username="alice")
    u.set_password("correct horse battery")
    _db.session.add(u)
    _db.session.commit()
    return u
