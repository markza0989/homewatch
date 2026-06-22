"""Authentication: login / logout.

Slice 1 scope: working session auth with CSRF-protected login form.
Audit logging of login attempts and /login rate limiting arrive in Slices 5 & 6.
"""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from .audit import record_audit
from .extensions import db, limiter
from .models import User, utcnow

auth_bp = Blueprint("auth", __name__)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Log in")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            user.last_login = utcnow()
            record_audit("login_success", username=user.username, user_id=user.id)
            db.session.commit()
            login_user(user)
            return redirect(_safe_next() or url_for("dashboard.index"))

        # Same generic message whether the username or password was wrong —
        # don't leak which usernames exist. The attempted username is still
        # recorded in the audit log for investigation.
        record_audit("login_fail", username=form.username.data)
        db.session.commit()
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


def _safe_next() -> str | None:
    """Only honour a relative ?next= target to avoid open-redirects."""
    target = request.args.get("next")
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None
