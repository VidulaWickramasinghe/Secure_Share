"""Server-rendered entry points for the Secure Share web interface."""

from __future__ import annotations

from flask import Blueprint, current_app, render_template


web_bp = Blueprint("web", __name__)


@web_bp.get("/")
def index():
    """Render the public landing page with the login form."""

    return render_template("login.html", page_name="landing")


@web_bp.get("/login")
def login():
    """Render the dedicated login page."""

    return render_template("login.html", page_name="login")


@web_bp.get("/register")
def register():
    """Render account registration."""

    return render_template("register.html", page_name="register")


@web_bp.get("/dashboard")
def dashboard():
    """Render the application shell; its data always comes from the API."""

    return render_template(
        "dashboard.html",
        page_name="dashboard",
        max_upload_bytes=current_app.config["MAX_CONTENT_LENGTH"],
    )


__all__ = ["web_bp"]
