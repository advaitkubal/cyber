import time
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, session, current_app
from app.db import query_db, execute_db
from app.security import login_required, log_audit, limiter
from app.crypto import decode_master_key, derive_user_key, encrypt, decrypt, DecryptionError

vault_bp = Blueprint("vault", __name__, url_prefix="/api")

def _get_user_crypto_context(user_id: int):
    """Retrieves user salt and derives the user's dedicated AES-256-GCM encryption key."""
    # SECURITY: Key Isolation - Derives unique user AES key via HKDF
    user = query_db("SELECT key_salt FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        return None
    master_key_bytes = decode_master_key(current_app.config["ENCRYPTION_MASTER_KEY"])
    user_key = derive_user_key(master_key_bytes, user["key_salt"])
    return user_key


# ============================================================================
# NOTES API
# ============================================================================

@vault_bp.route("/notes", methods=["GET"])
@login_required
def list_notes():
    """Returns decrypted notes for the current user, with optional search filtering."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    query_str = request.args.get("q", "").strip().lower()

    # SECURITY: IDOR Protection - Query strictly restricted to logged-in user_id
    rows = query_db(
        "SELECT id, title_enc, body_enc, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    )

    results = []
    for row in rows:
        try:
            # SECURITY: AES-256-GCM Decryption - Plaintext recovered in memory, never stored in DB
            title = decrypt(user_key, row["title_enc"], user_id)
            body = decrypt(user_key, row["body_enc"], user_id)
        except DecryptionError:
            log_audit("decrypt_failed", user_id=user_id)
            title = "[Decryption Failed: Tampered Data]"
            body = "[Decryption Failed: Tampered Data]"

        if query_str and query_str not in title.lower():
            continue

        results.append({
            "id": row["id"],
            "title": title,
            "body": body,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })

    return jsonify(results)


@vault_bp.route("/notes", methods=["POST"])
@login_required
def create_note():
    """Creates a new note with encrypted title and body."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    title = data.get("title", "").strip()
    body = data.get("body", "").strip()

    # SECURITY: Input Validation - Enforce length restrictions
    if not title or len(title) > 200:
        return jsonify({"error": "Title is required and must not exceed 200 characters"}), 400
    if len(body) > 20000:
        return jsonify({"error": "Note body must not exceed 20,000 characters"}), 400

    now_utc = datetime.now(timezone.utc).isoformat()

    # SECURITY: Encryption at Rest - All sensitive fields encrypted before SQL INSERT
    title_enc = encrypt(user_key, title, user_id)
    body_enc = encrypt(user_key, body, user_id)

    note_id = execute_db(
        "INSERT INTO notes (user_id, title_enc, body_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, title_enc, body_enc, now_utc, now_utc),
    )

    log_audit("note_created", user_id=user_id)
    return jsonify({
        "id": note_id,
        "title": title,
        "body": body,
        "created_at": now_utc,
        "updated_at": now_utc,
    }), 201


@vault_bp.route("/notes/<int:note_id>", methods=["PUT"])
@login_required
def update_note(note_id: int):
    """Updates an existing note after verifying ownership (IDOR check)."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    # SECURITY: IDOR Protection - Returns 404 if record does not belong to the user
    existing = query_db("SELECT id FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id), one=True)
    if not existing:
        return jsonify({"error": "Note not found"}), 404

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    title = data.get("title", "").strip()
    body = data.get("body", "").strip()

    if not title or len(title) > 200:
        return jsonify({"error": "Title is required and must not exceed 200 characters"}), 400
    if len(body) > 20000:
        return jsonify({"error": "Note body must not exceed 20,000 characters"}), 400

    now_utc = datetime.now(timezone.utc).isoformat()
    title_enc = encrypt(user_key, title, user_id)
    body_enc = encrypt(user_key, body, user_id)

    execute_db(
        "UPDATE notes SET title_enc = ?, body_enc = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (title_enc, body_enc, now_utc, note_id, user_id),
    )

    log_audit("note_updated", user_id=user_id)
    return jsonify({
        "id": note_id,
        "title": title,
        "body": body,
        "updated_at": now_utc,
    })


@vault_bp.route("/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id: int):
    """Deletes a note after IDOR validation."""
    user_id = session["user_id"]

    # SECURITY: IDOR Protection - Prevents deleting records owned by other users
    existing = query_db("SELECT id FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id), one=True)
    if not existing:
        return jsonify({"error": "Note not found"}), 404

    execute_db("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    log_audit("note_deleted", user_id=user_id)
    return jsonify({"message": "Note deleted successfully"})


@vault_bp.route("/notes/<int:note_id>/raw", methods=["GET"])
@login_required
def get_raw_note(note_id: int):
    """Returns the raw encrypted ciphertext as stored in SQLite to demonstrate encryption at rest."""
    user_id = session["user_id"]

    # SECURITY: IDOR Protection - Restricts raw ciphertext access strictly to owner
    row = query_db(
        "SELECT id, title_enc, body_enc, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
        (note_id, user_id),
        one=True,
    )
    if not row:
        return jsonify({"error": "Note not found"}), 404

    return jsonify({
        "id": row["id"],
        "title_enc": row["title_enc"],
        "body_enc": row["body_enc"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    })


# ============================================================================
# CREDENTIALS API
# ============================================================================

@vault_bp.route("/credentials", methods=["GET"])
@login_required
def list_credentials():
    """Lists credentials with masked passwords. Searches on decrypted site and username."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    query_str = request.args.get("q", "").strip().lower()

    # SECURITY: IDOR Protection - Query filtered by user_id
    rows = query_db(
        "SELECT id, site_enc, username_enc, url_enc, remarks_enc, created_at, updated_at "
        "FROM credentials WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    )

    results = []
    for row in rows:
        try:
            site = decrypt(user_key, row["site_enc"], user_id)
            username = decrypt(user_key, row["username_enc"], user_id)
            url = decrypt(user_key, row["url_enc"], user_id) if row["url_enc"] else ""
            remarks = decrypt(user_key, row["remarks_enc"], user_id) if row["remarks_enc"] else ""
        except DecryptionError:
            log_audit("decrypt_failed", user_id=user_id)
            site = "[Decryption Failed]"
            username = "[Decryption Failed]"
            url = ""
            remarks = ""

        if query_str and (query_str not in site.lower() and query_str not in username.lower()):
            continue

        results.append({
            "id": row["id"],
            "site": site,
            "username": username,
            # SECURITY: Password Masking - Passwords never returned in bulk listings
            "password_masked": "••••••••",
            "url": url,
            "remarks": remarks,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })

    return jsonify(results)


@vault_bp.route("/credentials", methods=["POST"])
@login_required
def create_credential():
    """Stores a new credential with all fields encrypted at rest."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    site = data.get("site", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    url = data.get("url", "").strip()
    remarks = data.get("remarks", "").strip()

    # SECURITY: Input Validation - Limits field lengths to prevent DoS/overflows
    if not site or len(site) > 200:
        return jsonify({"error": "Site is required and must not exceed 200 characters"}), 400
    if not username or len(username) > 200:
        return jsonify({"error": "Username is required and must not exceed 200 characters"}), 400
    if not password or len(password) > 500:
        return jsonify({"error": "Password is required and must not exceed 500 characters"}), 400
    if len(url) > 500:
        return jsonify({"error": "URL must not exceed 500 characters"}), 400
    if len(remarks) > 2000:
        return jsonify({"error": "Remarks must not exceed 2,000 characters"}), 400

    now_utc = datetime.now(timezone.utc).isoformat()

    # SECURITY: AES-256-GCM Encryption - All credential fields encrypted with individual nonces
    site_enc = encrypt(user_key, site, user_id)
    username_enc = encrypt(user_key, username, user_id)
    password_enc = encrypt(user_key, password, user_id)
    url_enc = encrypt(user_key, url, user_id) if url else ""
    remarks_enc = encrypt(user_key, remarks, user_id) if remarks else ""

    cred_id = execute_db(
        "INSERT INTO credentials (user_id, site_enc, username_enc, password_enc, url_enc, remarks_enc, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, site_enc, username_enc, password_enc, url_enc, remarks_enc, now_utc, now_utc),
    )

    log_audit("credential_created", user_id=user_id)
    return jsonify({
        "id": cred_id,
        "site": site,
        "username": username,
        "password_masked": "••••••••",
        "url": url,
        "remarks": remarks,
        "created_at": now_utc,
        "updated_at": now_utc,
    }), 201


@vault_bp.route("/credentials/<int:cred_id>", methods=["PUT"])
@login_required
def update_credential(cred_id: int):
    """Updates a credential record with IDOR verification."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    # SECURITY: IDOR Protection - Must belong to current user
    existing = query_db(
        "SELECT id, password_enc FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, user_id),
        one=True,
    )
    if not existing:
        return jsonify({"error": "Credential not found"}), 404

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    site = data.get("site", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password")  # None or empty string implies keeping existing
    url = data.get("url", "").strip()
    remarks = data.get("remarks", "").strip()

    if not site or len(site) > 200:
        return jsonify({"error": "Site is required and must not exceed 200 characters"}), 400
    if not username or len(username) > 200:
        return jsonify({"error": "Username is required and must not exceed 200 characters"}), 400
    if password is not None and len(password) > 500:
        return jsonify({"error": "Password must not exceed 500 characters"}), 400
    if len(url) > 500:
        return jsonify({"error": "URL must not exceed 500 characters"}), 400
    if len(remarks) > 2000:
        return jsonify({"error": "Remarks must not exceed 2,000 characters"}), 400

    now_utc = datetime.now(timezone.utc).isoformat()
    site_enc = encrypt(user_key, site, user_id)
    username_enc = encrypt(user_key, username, user_id)
    url_enc = encrypt(user_key, url, user_id) if url else ""
    remarks_enc = encrypt(user_key, remarks, user_id) if remarks else ""

    if password:
        password_enc = encrypt(user_key, password, user_id)
    else:
        password_enc = existing["password_enc"]

    execute_db(
        "UPDATE credentials SET site_enc = ?, username_enc = ?, password_enc = ?, url_enc = ?, remarks_enc = ?, updated_at = ? "
        "WHERE id = ? AND user_id = ?",
        (site_enc, username_enc, password_enc, url_enc, remarks_enc, now_utc, cred_id, user_id),
    )

    log_audit("credential_updated", user_id=user_id)
    return jsonify({
        "id": cred_id,
        "site": site,
        "username": username,
        "password_masked": "••••••••",
        "url": url,
        "remarks": remarks,
        "updated_at": now_utc,
    })


@vault_bp.route("/credentials/<int:cred_id>", methods=["DELETE"])
@login_required
def delete_credential(cred_id: int):
    """Deletes a credential with IDOR check."""
    user_id = session["user_id"]

    # SECURITY: IDOR Protection - Only owner can delete
    existing = query_db("SELECT id FROM credentials WHERE id = ? AND user_id = ?", (cred_id, user_id), one=True)
    if not existing:
        return jsonify({"error": "Credential not found"}), 404

    execute_db("DELETE FROM credentials WHERE id = ? AND user_id = ?", (cred_id, user_id))
    log_audit("credential_deleted", user_id=user_id)
    return jsonify({"message": "Credential deleted successfully"})


@vault_bp.route("/credentials/<int:cred_id>/reveal", methods=["GET"])
@limiter.limit("30 per minute")
@login_required
def reveal_credential(cred_id: int):
    """Decrypts and returns the sensitive password for a credential. Rate limited to 30/min."""
    user_id = session["user_id"]
    user_key = _get_user_crypto_context(user_id)
    if not user_key:
        return jsonify({"error": "User context unavailable"}), 500

    # SECURITY: IDOR Protection - Query verified against session user_id
    row = query_db(
        "SELECT password_enc FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, user_id),
        one=True,
    )
    if not row:
        return jsonify({"error": "Credential not found"}), 404

    try:
        # SECURITY: Decryption & Tamper Check - Authenticates tag before revealing
        plain_password = decrypt(user_key, row["password_enc"], user_id)
    except DecryptionError:
        log_audit("decrypt_failed", user_id=user_id)
        return jsonify({"error": "Integrity check failed: ciphertext has been tampered with."}), 400

    # SECURITY: Audit Logging - Logs credential reveal action
    log_audit("credential_revealed", user_id=user_id)
    return jsonify({"password": plain_password})


@vault_bp.route("/credentials/<int:cred_id>/raw", methods=["GET"])
@login_required
def get_raw_credential(cred_id: int):
    """Returns the raw ciphertext stored in SQLite to prove encryption at rest."""
    user_id = session["user_id"]

    # SECURITY: IDOR Protection - Returns 404 if record is not owned by user
    row = query_db(
        "SELECT id, site_enc, username_enc, password_enc, url_enc, remarks_enc, created_at, updated_at "
        "FROM credentials WHERE id = ? AND user_id = ?",
        (cred_id, user_id),
        one=True,
    )
    if not row:
        return jsonify({"error": "Credential not found"}), 404

    return jsonify({
        "id": row["id"],
        "site_enc": row["site_enc"],
        "username_enc": row["username_enc"],
        "password_enc": row["password_enc"],
        "url_enc": row["url_enc"],
        "remarks_enc": row["remarks_enc"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    })


# ============================================================================
# AUDIT & SESSION PING
# ============================================================================

@vault_bp.route("/audit", methods=["GET"])
@login_required
def get_audit_logs():
    """Returns the last 25 security audit events for the authenticated user."""
    user_id = session["user_id"]
    # SECURITY: Parameterized Query - Read user's audit logs safely
    rows = query_db(
        "SELECT id, event, ip, created_at FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 25",
        (user_id,),
    )
    results = [
        {"id": r["id"], "event": r["event"], "ip": r["ip"], "created_at": r["created_at"]}
        for r in rows
    ]
    return jsonify(results)


@vault_bp.route("/ping", methods=["POST"])
@login_required
def ping_session():
    """Refreshes the session last_active timestamp on client user activity."""
    # SECURITY: Session Activity Refresh - Extends active session while user interacts
    session["last_active"] = time.time()
    return jsonify({"status": "ok", "last_active": session["last_active"]})
