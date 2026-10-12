import os
import time
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import query_db, execute_db
from app.security import (
    limiter,
    hash_password,
    verify_password,
    validate_password_strength,
    validate_username,
    generate_csrf_token,
    log_audit,
    DUMMY_PASSWORD_HASH,
)

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    """Handles user registration with strong password enforcement and salted hashing."""
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("views.dashboard"))
        generate_csrf_token()
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # SECURITY: Input Validation - Validate username syntax and length
    valid_u, u_msg = validate_username(username)
    if not valid_u:
        return render_template("register.html", error=u_msg, username=username), 400

    # SECURITY: Password Policy - Enforce uppercase, lowercase, digit, symbol, min 10 chars
    valid_p, p_msg = validate_password_strength(password)
    if not valid_p:
        return render_template("register.html", error=p_msg, username=username), 400

    # Check for existing username using parameterized query
    existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
    if existing:
        return render_template("register.html", error="Username is already taken.", username=username), 400

    # SECURITY: Salted Password Hashing - Generates a secure salt and hash using scrypt/pbkdf2
    pwd_hash = hash_password(password)

    # SECURITY: User Key Salt - 16 random bytes for HKDF per-user encryption key derivation
    key_salt = os.urandom(16)
    created_at = datetime.now(timezone.utc).isoformat()

    user_id = execute_db(
        "INSERT INTO users (username, password_hash, key_salt, failed_attempts, locked_until, created_at) "
        "VALUES (?, ?, ?, 0, NULL, ?)",
        (username, pwd_hash, key_salt, created_at),
    )

    # SECURITY: Audit Logging - Record account registration
    log_audit("register", user_id=user_id)

    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Handles user login with account lockout and timing-attack mitigation."""
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("views.dashboard"))
        generate_csrf_token()
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    now = datetime.now(timezone.utc)

    # SECURITY: Parameterized Query - Prevents SQL injection during authentication lookup
    user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)

    if not user:
        # SECURITY: Constant-Time Dummy Verification - Mitigates user enumeration timing attacks
        verify_password(DUMMY_PASSWORD_HASH, password)
        log_audit("login_failed", user_id=None)
        return render_template("login.html", error="Invalid username or password.", username=username), 401

    user_id = user["id"]

    # SECURITY: Account Lockout Check - Enforces 5-minute lockout after 5 consecutive failed attempts
    locked_until_raw = user["locked_until"]
    if locked_until_raw:
        locked_dt = datetime.fromisoformat(locked_until_raw)
        if locked_dt > now:
            remaining_seconds = max(1, int((locked_dt - now).total_seconds()))
            log_audit("login_failed", user_id=user_id)
            return render_template(
                "login.html",
                error=f"Account is temporarily locked due to too many failed attempts. Please try again in {remaining_seconds} seconds.",
                username=username,
            ), 403
        else:
            # Lockout expired; reset counters
            execute_db("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
            user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)

    # SECURITY: Constant-Time Password Verification
    if verify_password(user["password_hash"], password):
        # Reset failed attempts counter on valid login
        execute_db("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))

        # SECURITY: Session Fixation Defense - Clear any previous session and establish a clean one
        session.clear()
        session["user_id"] = user_id
        session["username"] = user["username"]
        session["last_active"] = time.time()
        generate_csrf_token()

        log_audit("login_success", user_id=user_id)
        return redirect(url_for("views.dashboard"))
    else:
        failed_count = user["failed_attempts"] + 1
        if failed_count >= 5:
            # Lock account for 5 minutes
            lockout_time = (now + timedelta(minutes=5)).isoformat()
            execute_db(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (failed_count, lockout_time, user_id),
            )
            # SECURITY: Audit Logging - Account locked event
            log_audit("account_locked", user_id=user_id)
            return render_template(
                "login.html",
                error="Account is temporarily locked due to too many failed attempts. Please try again in 300 seconds.",
                username=username,
            ), 403
        else:
            execute_db("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_count, user_id))
            log_audit("login_failed", user_id=user_id)
            return render_template("login.html", error="Invalid username or password.", username=username), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Handles secure user logout by fully purging the session."""
    user_id = session.get("user_id")
    # SECURITY: Audit Logging - Record user logout
    if user_id:
        log_audit("logout", user_id=user_id)

    # SECURITY: Session Destruction - Clears all session keys to prevent reuse
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("auth.login"))
