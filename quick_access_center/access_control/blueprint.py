# access_control/blueprint.py
"""Blueprint и подключение Access Control к MSB Quick Access Center."""
from __future__ import annotations

import os
from datetime import timedelta

from flask import Blueprint, Flask, request

from access_control.access_settings import (
    access_control_page,
    access_login_route,
    access_logout_route,
    get_main_csrf_token,
    protect_admin_routes,
    reload_access_config,
    require_main_csrf_token,
)

try:
    from on_off_debug.debug_mode import debug_success_print as _debug_success_print
except Exception:  # pragma: no cover
    def _debug_success_print(message) -> None:
        return None


LOG_SOURCE = "access_control.blueprint"


def _log_success(message: str) -> None:
    _debug_success_print(f"[{LOG_SOURCE}] {message}")


def add_access_security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    if request.path.startswith("/access-control") or response.mimetype in {"text/html", "application/json"}:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


def create_access_control_blueprint() -> Blueprint:
    access_bp = Blueprint(
        "access_control",
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/access_control_static",
    )

    access_bp.add_url_rule(
        "/access-control",
        endpoint="access_control_page",
        view_func=access_control_page,
        methods=["GET"],
    )

    access_bp.add_url_rule(
        "/access-control/login",
        endpoint="access_login_route",
        view_func=access_login_route,
        methods=["POST"],
    )

    access_bp.add_url_rule(
        "/access-control/logout",
        endpoint="access_logout_route",
        view_func=access_logout_route,
        methods=["POST"],
    )

    return access_bp


def init_access_control(app: Flask) -> None:
    """Подключает вход, IP-фильтр и anti brute-force ко всем routes приложения."""
    config = reload_access_config(log=True)

    app.permanent_session_lifetime = timedelta(
        hours=max(1, int(config["session_hours"]))
    )

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Secure by default. Only a local HTTP development server should set this to 0.
    app.config["SESSION_COOKIE_SECURE"] = (
        str(os.environ.get("MSB_QUICK_ACCESS_COOKIE_SECURE", "1")).strip().lower()
        in {"1", "true", "yes", "on"}
    )

    @app.context_processor
    def inject_main_csrf_token():
        return {"main_csrf_token": get_main_csrf_token()}

    app.before_request(protect_admin_routes)
    app.before_request(require_main_csrf_token)
    app.after_request(add_access_security_headers)
    app.register_blueprint(create_access_control_blueprint())

    _log_success("Access Control подключён ко всем маршрутам приложения.")
