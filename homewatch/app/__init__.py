"""Flask application factory for HomeWatch."""
from flask import Flask, render_template

from config import get_config
from .extensions import csrf, db, limiter, login_manager


def create_app(config_name: str | None = None, **config_overrides) -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))
    # Overrides let tests flip individual settings (e.g. RATELIMIT_ENABLED)
    # before the extensions read them at init time.
    app.config.update(config_overrides)

    if not app.config.get("SECRET_KEY"):
        # Fail loud rather than silently running with an insecure session key.
        raise RuntimeError(
            "SECRET_KEY is not set. Copy .env.example to .env and set a real value."
        )

    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)

    return app


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(429)
    def too_many_requests(error):
        # Rate limit hit (e.g. brute-force on /login). Friendly page, 429 status.
        return render_template("429.html", error=error), 429


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from .models import User  # local import to avoid circular import at module load

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))


def _register_blueprints(app: Flask) -> None:
    from .auth import auth_bp
    from .routes.api import api_bp
    from .routes.dashboard import dashboard_bp
    from .routes.devices import devices_bp
    from .routes.events import events_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(events_bp)
