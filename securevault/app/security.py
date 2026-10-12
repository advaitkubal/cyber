import re
import time
import hmac
import secrets
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, Tuple
from flask import (
    request,
    session,
    redirect,
    url_for,
    jsonify,
    abort,
    flash,
    Response,
    current_app,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# SECURITY: Rate Limiter - Keyed by remote client IP address
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)

# Pre-computed dummy hash to maintain constant-time response for nonexistent users
try:
    DUMMY_PASSWORD_HASH = generate_password_hash("DummyP@ssw0rdForConstantTime!", method="scrypt")
except Exception:
    DUMMY_PASSWORD_HASH = generate_password_hash(
        "DummyP@ssw0rdForConstantTime!", method="pbkdf2:sha256", salt_length=16
    )

def hash_password(password: str) -> str:
    """Hashes a password with scrypt (or PBKDF2 600,000 iterations fallback)."""
    # SECURITY: Password Hashing - Salted hash with high work factor
    try:
        return generate_password_hash(password, method="scrypt")
    except Exception:
        return generate_password_hash(password, method="pbkdf2:sha256:600000")

def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Safely verifies a password hash against a candidate."""
    # SECURITY: Hash Verification - Constant-time check prevents timing attacks
    return check_password_hash(stored_hash, candidate_password)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates password against complexity requirements:
    - 10 to 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    """
    # SECURITY: Password Complexity Policy - Prevents brute force and dictionary attacks
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"""[!@#$%^&*(),.?":{}|<>\-_\+=\[\]\\\/~`']""", password):
        return False, "Password must contain at least one special symbol."
    return True, ""

def validate_username(username: str) -> Tuple[bool, str]:
    """Ensures username is alphanumeric with underscores, between 3 and 30 characters."""
    # SECURITY: Input Validation - Restricts characters to prevent injection/path traversal
    if not re.match(r"^[A-Za-z0-9_]{3,30}$", username):
        return False, "Username must be 3-30 characters and contain only letters, numbers, and underscores."
    return True, ""

def generate_csrf_token() -> str:
    """Generates and stores a cryptographically secure random CSRF token in the session."""
    # SECURITY: CSRF Token Generation - High-entropy token bound to the current session
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def verify_csrf() -> bool:
    """Verifies that the CSRF token in header or form matches the session token."""
    # SECURITY: CSRF Verification - Double-submit/session token comparison using constant-time hmac
    stored_token = session.get("csrf_token")
    if not stored_token:
        return False

    received_token = request.headers.get("X-CSRF-Token")
    if not received_token:
        received_token = request.form.get("csrf_token")

    if not received_token:
        return False

    return hmac.compare_digest(stored_token, received_token)

def login_required(f):
    """Decorator ensuring that only authenticated users with active sessions can access the route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # SECURITY: Authorization Check - Enforces valid authenticated session
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function

def log_audit(event: str, user_id: Optional[int] = None, ip: Optional[str] = None) -> None:
    """Records security-relevant events into the audit_log table without leaking sensitive data."""
    # SECURITY: Audit Logging - Maintains immutable record of authentication and data access events
    from app.db import execute_db
    try:
        client_ip = ip or request.headers.get("X-Forwarded-For", request.remote_addr)
        if client_ip and "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        now_utc = datetime.now(timezone.utc).isoformat()
        execute_db(
            "INSERT INTO audit_log (user_id, event, ip, created_at) VALUES (?, ?, ?, ?)",
            (user_id, event, client_ip, now_utc),
        )
    except Exception:
        # Avoid crashing primary flows if audit logging fails
        pass

def enforce_session_timeout() -> Optional[Response]:
    """
    Checks if the current session has exceeded the 15-minute idle timeout.
    If expired, clears session, logs audit event, and returns 401 or redirect.
    """
    # SECURITY: Idle Session Timeout - Invalidates stale sessions after 15 minutes of inactivity
    if "user_id" in session:
        last_active = session.get("last_active")
        current_time = time.time()
        timeout_seconds = 15 * 60

        if last_active and (current_time - last_active > timeout_seconds):
            user_id = session.get("user_id")
            log_audit("session_expired", user_id=user_id)
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Session expired"}), 401
            flash("Session expired due to inactivity. Please log in again.", "info")
            return redirect(url_for("auth.login"))

        session["last_active"] = current_time
    return None

def apply_security_headers(response: Response) -> Response:
    """Attaches modern defensive HTTP security headers to all outbound responses."""
    # SECURITY: Content Security Policy - Prevents XSS by forbidding inline scripts and untrusted origins
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    # SECURITY: MIME Sniffing Protection - Enforces strict content types
    response.headers["X-Content-Type-Options"] = "nosniff"
    # SECURITY: Clickjacking Defense - Forbids framing of pages
    response.headers["X-Frame-Options"] = "DENY"
    # SECURITY: Referrer Policy - Prevents leaking URL paths in outgoing requests
    response.headers["Referrer-Policy"] = "no-referrer"
    # SECURITY: Permissions Policy - Disables sensitive browser hardware APIs
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    # SECURITY: Cache-Control - Disables caching on authenticated views and API responses
    if "user_id" in session or request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    return response
