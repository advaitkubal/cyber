import os
from flask import Flask, request, jsonify, render_template, session, abort
from flask_limiter.errors import RateLimitExceeded

from app.config import Config
from app.db import init_db, close_db
from app.security import (
    limiter,
    enforce_session_timeout,
    apply_security_headers,
    generate_csrf_token,
    verify_csrf,
    log_audit,
)
from app.auth import auth_bp
from app.vault import vault_bp
from app.views import views_bp

def create_app(config=None) -> Flask:
    """Application factory for SecureVault."""
    app = Flask(__name__)
    app.config.from_object(Config)

    if config:
        app.config.update(config)

    # Initialize rate limiter with app configuration
    limiter.init_app(app)

    # Register application blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(views_bp)

    # Tear down database connection at end of request
    app.teardown_appcontext(close_db)

    # Initialize SQLite database schema
    init_db(app)

    # SECURITY: CSRF Token Context Processor - Makes csrf_token() available to Jinja2 templates
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)

    # SECURITY: Global Request Interceptor - Enforces idle session timeout & CSRF validation
    @app.before_request
    def before_request_hook():
        # Check 15-minute idle session timeout
        timeout_resp = enforce_session_timeout()
        if timeout_resp:
            return timeout_resp

        # SECURITY: CSRF Protection - Enforce valid token on every state-changing HTTP method
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if not verify_csrf():
                if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
                    return jsonify({"error": "CSRF validation failed: missing or invalid CSRF token"}), 403
                abort(403)

    # SECURITY: Defensive Security Headers - Attached to every HTTP response
    @app.after_request
    def after_request_hook(response):
        return apply_security_headers(response)

    # ========================================================================
    # ERROR HANDLERS (Generic responses - Stack traces suppressed)
    # ========================================================================

    def _handle_error(code: int, title: str, default_message: str):
        if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
            return jsonify({"error": default_message}), code
        return render_template("error.html", code=code, title=title, message=default_message), code

    @app.errorhandler(400)
    def bad_request(e):
        return _handle_error(400, "Bad Request", "Invalid request syntax or parameters.")

    @app.errorhandler(401)
    def unauthorized(e):
        return _handle_error(401, "Unauthorized", "Authentication is required to access this resource.")

    @app.errorhandler(403)
    def forbidden(e):
        return _handle_error(403, "Forbidden", "Access denied or CSRF token verification failed.")

    @app.errorhandler(404)
    def not_found(e):
        return _handle_error(404, "Not Found", "The requested resource could not be found.")

    @app.errorhandler(405)
    def method_not_allowed(e):
        return _handle_error(405, "Method Not Allowed", "HTTP method is not allowed for this route.")

    @app.errorhandler(413)
    def payload_too_large(e):
        return _handle_error(413, "Payload Too Large", "Request entity exceeds maximum allowable limit (1 MB).")

    @app.errorhandler(429)
    @app.errorhandler(RateLimitExceeded)
    def rate_limit_handler(e):
        user_id = session.get("user_id")
        log_audit("rate_limited", user_id=user_id)
        if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
            return jsonify({"error": "Too many requests. Please slow down."}), 429
        return render_template(
            "error.html",
            code=429,
            title="Too Many Requests",
            message="Too many requests. Please slow down.",
        ), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        return _handle_error(500, "Server Error", "An unexpected internal server error occurred.")

    return app
