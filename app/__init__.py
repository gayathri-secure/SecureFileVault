
import os
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask


def create_app():
    # Load configuration from the project's root .env file.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_dotenv(os.path.join(project_root, ".env"))

    app = Flask(__name__)

    # Use a secret from .env to sign Flask session cookies.
    app.config["SECRET_KEY"] = os.getenv("OTP_SECRET")

    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "OTP_SECRET is missing. Add it to your project's .env file."
        )

    # Limit the lifetime of the browser session.
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app
