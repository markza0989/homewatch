#!/usr/bin/env python3
"""Development server entry point.

Binds to 127.0.0.1 by default. To expose on the LAN set HOMEWATCH_BIND=0.0.0.0
in your .env — and read the network-exposure warning in README.md first.
Do not use this server in production; run under a WSGI server behind a reverse
proxy instead (see systemd/ in a later slice).
"""
import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOMEWATCH_BIND", "127.0.0.1")
    port = int(os.environ.get("HOMEWATCH_PORT", "8000"))
    app.run(host=host, port=port)
