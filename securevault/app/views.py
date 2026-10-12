import time
from flask import Blueprint, render_template, redirect, url_for, session, current_app
from app.security import login_required, generate_csrf_token

views_bp = Blueprint("views", __name__)

@views_bp.route("/")
def index():
    """Redirects authenticated users to dashboard and guests to login."""
    if "user_id" in session:
        return redirect(url_for("views.dashboard"))
    return redirect(url_for("auth.login"))

@views_bp.route("/dashboard")
@login_required
def dashboard():
    """Renders the primary application dashboard."""
    generate_csrf_token()
    return render_template("dashboard.html", username=session.get("username", ""))

@views_bp.route("/security")
@login_required
def security_center():
    """Renders the educational Security Center page with live status indicators."""
    generate_csrf_token()
    last_active = session.get("last_active", time.time())
    elapsed_seconds = time.time() - last_active
    remaining_minutes = max(0, int((15 * 60 - elapsed_seconds) / 60))

    security_status = {
        "session_minutes_left": remaining_minutes,
        "cookie_httponly": current_app.config.get("SESSION_COOKIE_HTTPONLY", True),
        "cookie_samesite": current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        "cookie_secure": current_app.config.get("SESSION_COOKIE_SECURE", False),
        "csp_active": True,
        "encryption_algorithm": "AES-256-GCM (Authenticated Encryption)",
        "kdf_algorithm": "HKDF-SHA256 (32-byte salt per user)",
        "hash_algorithm": "Scrypt / PBKDF2-SHA256 (Salted)",
    }

    return render_template(
        "security.html",
        username=session.get("username", ""),
        status=security_status,
    )
