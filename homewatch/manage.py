#!/usr/bin/env python3
"""HomeWatch management CLI.

Commands:
    python manage.py init-db                 Create all tables.
    python manage.py create-user <username>  Create an admin user (prompts for password).
"""
import argparse
import getpass
import sys

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402  (must follow load_dotenv)
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402


def cmd_init_db(_args) -> int:
    app = create_app()
    with app.app_context():
        db.create_all()
    print("Database initialised — all tables created.")
    return 0


def cmd_create_user(args) -> int:
    app = create_app()
    with app.app_context():
        if User.query.filter_by(username=args.username).first():
            print(f"User '{args.username}' already exists.", file=sys.stderr)
            return 1

        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 1
        if len(password) < 8:
            print("Password must be at least 8 characters.", file=sys.stderr)
            return 1

        user = User(username=args.username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    print(f"User '{args.username}' created.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HomeWatch management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create all database tables").set_defaults(
        func=cmd_init_db
    )

    p_user = sub.add_parser("create-user", help="Create an admin user")
    p_user.add_argument("username")
    p_user.set_defaults(func=cmd_create_user)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
