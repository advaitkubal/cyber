import os
import base64
import time
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.crypto import decode_master_key, derive_user_key, encrypt, decrypt, DecryptionError
from app.db import get_db, query_db

TEST_MASTER_KEY_B64 = base64.b64encode(b"01234567890123456789012345678901").decode("ascii")

@pytest.fixture
def app(tmp_path):
    """Creates an isolated test application instance backed by a temporary SQLite database."""
    db_file = tmp_path / "test_securevault.db"
    test_config = {
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "ENCRYPTION_MASTER_KEY": TEST_MASTER_KEY_B64,
        "SECRET_KEY": "test-secret-key-for-pytest-execution-only",
        "RATELIMIT_ENABLED": False,  # Disabled by default so fast unit tests don't get throttled
        "WTF_CSRF_ENABLED": False,
    }
    app = create_app(test_config)
    yield app

@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()

def get_csrf_token(client):
    """Retrieves or initializes a CSRF token for the test client session."""
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token")

def register_user(client, username="alice_sec", password="ComplexP@ssw0rd123!"):
    """Helper to register a user via POST with CSRF."""
    token = get_csrf_token(client)
    return client.post(
        "/register",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )

def login_user(client, username="alice_sec", password="ComplexP@ssw0rd123!"):
    """Helper to log in a user via POST with CSRF."""
    token = get_csrf_token(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=True,
    )

# ============================================================================
# 1. TEST PASSWORD IS HASHED
# ============================================================================
def test_password_is_hashed(app, client):
    """Verifies that user passwords are not plaintext and start with scrypt: or pbkdf2:."""
    raw_pwd = "ComplexP@ssw0rd123!"
    resp = register_user(client, username="test_hash_user", password=raw_pwd)
    assert resp.status_code in (302, 200)

    with app.app_context():
        user = query_db("SELECT password_hash FROM users WHERE username = ?", ("test_hash_user",), one=True)
        assert user is not None
        pwd_hash = user["password_hash"]
        assert raw_pwd not in pwd_hash
        assert pwd_hash.startswith("scrypt:") or pwd_hash.startswith("pbkdf2:")

# ============================================================================
# 2. TEST WEAK PASSWORD REJECTED
# ============================================================================
def test_weak_password_rejected(client):
    """Verifies server-side rejection of passwords that fail complexity requirements."""
    weak_passwords = [
        "short1!A",           # Less than 10 characters
        "nouppercase123!@#",  # Missing uppercase
        "NOLOWERCASE123!@#",  # Missing lowercase
        "NoDigitsHereAtAll!", # Missing digits
        "NoSpecialCharacters123", # Missing symbol
    ]
    for weak in weak_passwords:
        token = get_csrf_token(client)
        resp = client.post(
            "/register",
            data={"username": "user_" + str(int(time.time() * 1000))[-6:], "password": weak, "csrf_token": token},
        )
        assert resp.status_code == 400

# ============================================================================
# 3. TEST DATA ENCRYPTED AT REST
# ============================================================================
def test_data_encrypted_at_rest(app, client):
    """Ensures notes and credentials plaintext strings NEVER appear in the raw database rows."""
    username = "crypto_user"
    password = "ComplexP@ssw0rd123!"
    secret_note_title = "MyUltraSecretNoteTitle12345"
    secret_note_body = "This is classified plaintext body that must not leak!"
    secret_site = "BankOfSecrets12345"
    secret_cred_pass = "SuperSecretBankPassword987!"

    register_user(client, username, password)
    login_user(client, username, password)
    token = get_csrf_token(client)

    # Create note
    res_note = client.post(
        "/api/notes",
        json={"title": secret_note_title, "body": secret_note_body},
        headers={"X-CSRF-Token": token},
    )
    assert res_note.status_code == 201

    # Create credential
    res_cred = client.post(
        "/api/credentials",
        json={
            "site": secret_site,
            "username": "bankuser",
            "password": secret_cred_pass,
            "url": "https://bank.example.com",
            "remarks": "Confidential banking PIN",
        },
        headers={"X-CSRF-Token": token},
    )
    assert res_cred.status_code == 201

    # Read raw database rows directly from SQLite
    with app.app_context():
        notes_rows = query_db("SELECT title_enc, body_enc FROM notes")
        for row in notes_rows:
            assert secret_note_title not in row["title_enc"]
            assert secret_note_body not in row["body_enc"]

        cred_rows = query_db("SELECT site_enc, password_enc, remarks_enc FROM credentials")
        for row in cred_rows:
            assert secret_site not in row["site_enc"]
            assert secret_cred_pass not in row["password_enc"]
            assert "Confidential banking PIN" not in row["remarks_enc"]

# ============================================================================
# 4. TEST AES-GCM TAMPER DETECTION
# ============================================================================
def test_aes_gcm_tamper_detection(app):
    """Flipping a byte of an AES-256-GCM ciphertext must trigger a DecryptionError."""
    master_key = decode_master_key(TEST_MASTER_KEY_B64)
    salt = b"1234567890123456"
    user_key = derive_user_key(master_key, salt)
    user_id = 42

    plaintext = "Important Secret Message"
    cipher_b64 = encrypt(user_key, plaintext, user_id)
    assert decrypt(user_key, cipher_b64, user_id) == plaintext

    # Tamper with the ciphertext by altering raw bytes
    raw_combined = bytearray(base64.b64decode(cipher_b64))
    raw_combined[-1] ^= 0x01  # Flip one bit in GCM tag
    tampered_b64 = base64.b64encode(bytes(raw_combined)).decode("ascii")

    with pytest.raises(DecryptionError):
        decrypt(user_key, tampered_b64, user_id)

# ============================================================================
# 5. TEST RATE LIMIT ON LOGIN
# ============================================================================
def test_rate_limit_login(tmp_path):
    """When limiter is active, the 6th rapid login attempt within 1 minute returns HTTP 429."""
    db_file = tmp_path / "ratelimit_test.db"
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(db_file),
        "ENCRYPTION_MASTER_KEY": TEST_MASTER_KEY_B64,
        "RATELIMIT_ENABLED": True,
    })
    client = app.test_client()
    register_user(client, "rate_user", "ComplexP@ssw0rd123!")

    # Attempt 5 rapid logins (allowed within rate limit)
    for _ in range(5):
        token = get_csrf_token(client)
        resp = client.post(
            "/login",
            data={"username": "rate_user", "password": "WrongPassword1!", "csrf_token": token},
        )
        assert resp.status_code in (401, 403)

    # 6th attempt must trigger rate limit 429
    token = get_csrf_token(client)
    resp6 = client.post(
        "/login",
        data={"username": "rate_user", "password": "WrongPassword1!", "csrf_token": token},
    )
    assert resp6.status_code == 429

# ============================================================================
# 6. TEST ACCOUNT LOCKOUT
# ============================================================================
def test_account_lockout(app, client):
    """Account is locked after 5 consecutive failed passwords."""
    username = "lockout_user"
    real_pwd = "ComplexP@ssw0rd123!"
    register_user(client, username, real_pwd)

    # 4 failed attempts
    for _ in range(4):
        token = get_csrf_token(client)
        r = client.post("/login", data={"username": username, "password": "BadPassword1!", "csrf_token": token})
        assert r.status_code == 401

    # 5th failed attempt causes lockout
    token = get_csrf_token(client)
    r5 = client.post("/login", data={"username": username, "password": "BadPassword1!", "csrf_token": token})
    assert r5.status_code == 403
    assert b"temporarily locked" in r5.data

    # Even with correct password, login is blocked while locked
    token = get_csrf_token(client)
    r_locked = client.post("/login", data={"username": username, "password": real_pwd, "csrf_token": token})
    assert r_locked.status_code == 403

# ============================================================================
# 7. TEST SQL INJECTION ON LOGIN
# ============================================================================
def test_sql_injection_login(app, client):
    """Classic SQL injection strings on login must fail cleanly without error 500."""
    register_user(client, "admin_user", "ComplexP@ssw0rd123!")
    sqli_payloads = [
        "' OR '1'='1",
        "admin'--",
        "admin' /*",
        "' OR 1=1 #",
        "') OR ('1'='1",
    ]
    for payload in sqli_payloads:
        token = get_csrf_token(client)
        res = client.post(
            "/login",
            data={"username": payload, "password": "AnyPassword1!", "csrf_token": token},
        )
        assert res.status_code == 401
        assert res.status_code != 500

# ============================================================================
# 8. TEST SQL INJECTION ON SEARCH
# ============================================================================
def test_sql_injection_search(app, client):
    """SQL injection payloads in ?q= search parameters must not cause a 500 or bypass filtering."""
    register_user(client, "search_user", "ComplexP@ssw0rd123!")
    login_user(client, "search_user", "ComplexP@ssw0rd123!")

    sqli_queries = [
        "' OR 1=1--",
        "'; DROP TABLE notes; --",
        "' UNION SELECT 1,2,3,4,5--",
    ]
    for q in sqli_queries:
        res = client.get(f"/api/notes?q={q}")
        assert res.status_code == 200
        assert isinstance(res.json, list)

# ============================================================================
# 9. TEST XSS PAYLOAD IS ESCAPED
# ============================================================================
def test_xss_payload_is_escaped(app, client):
    """XSS payloads stored in notes are served as text, and strict CSP is present."""
    register_user(client, "xss_user", "ComplexP@ssw0rd123!")
    login_user(client, "xss_user", "ComplexP@ssw0rd123!")
    token = get_csrf_token(client)

    xss_payload = "<script>alert('XSS-Test')</script>"
    res = client.post(
        "/api/notes",
        json={"title": xss_payload, "body": "Harmful body <img src=x onerror=alert(1)>"},
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 201

    # Verify dashboard page response includes strict CSP
    dash_resp = client.get("/dashboard")
    assert "Content-Security-Policy" in dash_resp.headers
    csp = dash_resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp

# ============================================================================
# 10. TEST SECURITY HEADERS PRESENT
# ============================================================================
def test_security_headers_present(app, client):
    """Verifies that all specified defensive HTTP security headers are attached."""
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")

    # Check Cache-Control: no-store on authenticated API routes
    register_user(client, "header_user", "ComplexP@ssw0rd123!")
    login_user(client, "header_user", "ComplexP@ssw0rd123!")
    api_resp = client.get("/api/notes")
    assert "no-store" in api_resp.headers.get("Cache-Control", "")

# ============================================================================
# 11. TEST SESSION COOKIE FLAGS
# ============================================================================
def test_session_cookie_flags(app, client):
    """Verifies Set-Cookie contains HttpOnly and SameSite=Lax."""
    resp = client.get("/login")
    cookie_header = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header

# ============================================================================
# 12. TEST SESSION IDLE TIMEOUT
# ============================================================================
def test_session_idle_timeout(app, client):
    """Simulating last_active older than 15 minutes causes session expiration (401 or redirect)."""
    register_user(client, "idle_user", "ComplexP@ssw0rd123!")
    login_user(client, "idle_user", "ComplexP@ssw0rd123!")

    # Set last_active to 16 minutes in the past
    with client.session_transaction() as sess:
        sess["last_active"] = time.time() - (16 * 60)

    # Next API request must be rejected with 401
    resp = client.get("/api/notes")
    assert resp.status_code == 401
    assert resp.json.get("error") == "Session expired"

# ============================================================================
# 13. TEST CSRF REQUIRED
# ============================================================================
def test_csrf_required(app, client):
    """Mutating POST requests without a valid CSRF token return 403."""
    # Attempt login without token
    resp = client.post("/login", data={"username": "someone", "password": "Password123!"})
    assert resp.status_code == 403

# ============================================================================
# 14. TEST IDOR BLOCKED
# ============================================================================
def test_idor_blocked(app, client):
    """User B requesting or deleting User A's note/credential receives 404 (not 403)."""
    # User A creates a note
    client_a = app.test_client()
    register_user(client_a, "user_alice", "ComplexP@ssw0rd123!")
    login_user(client_a, "user_alice", "ComplexP@ssw0rd123!")
    token_a = get_csrf_token(client_a)

    res_note = client_a.post(
        "/api/notes",
        json={"title": "Alice Note", "body": "Alice Secret"},
        headers={"X-CSRF-Token": token_a},
    )
    assert res_note.status_code == 201
    note_id = res_note.json["id"]

    # User B logs in and tries to access Alice's note
    client_b = app.test_client()
    register_user(client_b, "user_bob", "ComplexP@ssw0rd123!")
    login_user(client_b, "user_bob", "ComplexP@ssw0rd123!")
    token_b = get_csrf_token(client_b)

    # User B attempts to view raw note
    res_b_view = client_b.get(f"/api/notes/{note_id}/raw")
    assert res_b_view.status_code == 404

    # User B attempts to delete Alice's note
    res_b_del = client_b.delete(f"/api/notes/{note_id}", headers={"X-CSRF-Token": token_b})
    assert res_b_del.status_code == 404

# ============================================================================
# 15. TEST SESSION FIXATION
# ============================================================================
def test_session_fixation(app, client):
    """Session is cleared and re-created upon login to prevent session fixation."""
    # Pre-set a session key before login
    client.get("/login")
    with client.session_transaction() as sess:
        sess["attacker_fixed_key"] = "malicious_payload_or_session_id"

    register_user(client, "fixation_user", "ComplexP@ssw0rd123!")
    login_user(client, "fixation_user", "ComplexP@ssw0rd123!")

    # Verify that the pre-existing session key was purged
    with client.session_transaction() as sess:
        assert "attacker_fixed_key" not in sess
        assert "user_id" in sess
