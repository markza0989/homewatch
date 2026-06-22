"""WSGI entry point for production (gunicorn behind systemd).

    gunicorn --bind 127.0.0.1:8000 wsgi:application

Unlike run.py (dev server), this is what the homewatch-web systemd unit runs.
"""
from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402

application = create_app("production")
