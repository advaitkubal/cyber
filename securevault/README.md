# SecureVault - Encrypted Note & Credential Keeper

SecureVault is an academic-grade, full-stack cybersecurity web application built with Python, Flask, SQLite, and vanilla frontend technologies. It is specifically designed to demonstrate **five core defense-in-depth security mechanisms** plus crucial bonus controls in a transparent, readable architecture ideal for college evaluations and vivas.

---

## 🛡️ Core Security Architecture & Mechanism Mapping

| Security Mechanism | Implementation File | Key Functions / Constructs | Threat / Attack Mitigated |
| :--- | :--- | :--- | :--- |
| **1. AES-256-GCM Encryption at Rest** | `app/crypto.py`<br>`app/vault.py` | `encrypt()`, `decrypt()`, `derive_user_key()` | Database exfiltration, storage sniffing, ciphertext tampering |
| **2. Salted Password Hashing & Timing Defense** | `app/security.py`<br>`app/auth.py` | `hash_password()`, `verify_password()`, dummy verification in `login()` | Offline rainbow table attacks, user enumeration timing attacks |
| **3. Account Lockout Policy** | `app/auth.py` | `login()` counter & `locked_until` check | Online automated brute-force attacks |
| **4. Tiered Rate Limiting** | `app/security.py`<br>`app/auth.py` | `limiter.limit()`, 429 handler in `app/__init__.py` | Denial of Service (DoS), rapid credential stuffing |
| **5. Parameterized SQL Queries** | `app/db.py` | `query_db()`, `execute_db()` with `?` placeholders | SQL Injection (SQLi) |
| **6. Strict Content Security Policy (CSP) & XSS Defenses** | `app/security.py`<br>`app/static/js/app.js` | `apply_security_headers()`, `textContent` DOM rendering | Stored & Reflected Cross-Site Scripting (XSS), Clickjacking |
| **7. Hardened Session Cookies & Idle Timeout** | `app/security.py`<br>`app/static/js/idle.js` | `enforce_session_timeout()`, `HttpOnly`, `SameSite=Lax` | Session hijacking, unattended workstation theft |
| **8. Anti-CSRF Token Validation** | `app/security.py`<br>`app/__init__.py` | `generate_csrf_token()`, `verify_csrf()` | Cross-Site Request Forgery (CSRF) |
| **9. Session Fixation Defense** | `app/auth.py` | `session.clear()` on successful authentication | Pre-authentication session adoption |
| **10. IDOR Authorization Boundary** | `app/vault.py` | `WHERE id = ? AND user_id = ?` with HTTP 404 | Insecure Direct Object References (IDOR) |
| **11. Tamper-Resistant Security Audit Trail** | `app/security.py`<br>`app/vault.py` | `log_audit()`, `/api/audit` endpoint | Repudiation, unauthorized activity auditing |
| **12. Sanitized Generic Error Handling** | `app/__init__.py` | Error handlers (400, 401, 403, 404, 405, 413, 429, 500) | Information disclosure via stack traces & debuggers |

---

## 💻 Tech Stack

- **Backend**: Python 3.10+, Flask 3.x (Application Factory pattern)
- **Database**: SQLite3 with standard `sqlite3` driver (`PRAGMA foreign_keys = ON;`, **NO ORM**)
- **Cryptography**: Python `cryptography` library (`AESGCM` with random 12-byte nonces, `HKDF-SHA256` key derivation)
- **Password Hashing**: `werkzeug.security` using `scrypt` (fallback to `pbkdf2:sha256:600000`)
- **Rate Limiting**: `Flask-Limiter`
- **Config & Environment**: `python-dotenv`
- **Test Suite**: `pytest`
- **Frontend**: Plain HTML5, CSS3 (Modern dark theme with CSS variables), and vanilla JavaScript.
  - **Zero external dependencies, zero CDN requests, zero node/npm requirements, fully offline.**

---

## 🚀 Setup & Installation

### macOS & Linux
```bash
# 1. Navigate to the project directory
cd securevault

# 2. Create Python virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start the server (runs on 127.0.0.1:5000 with debug OFF)
python run.py
```

### Windows (PowerShell / Command Prompt)
```powershell
# 1. Navigate to the project directory
cd securevault

# 2. Create Python virtual environment
python -m venv venv

# 3. Activate the virtual environment
.\venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start the server
python run.py
```

*Note: On the first launch, SecureVault automatically creates `.env` with a cryptographically secure random `SECRET_KEY` and 256-bit `ENCRYPTION_MASTER_KEY`, and initializes `securevault.db` with the complete schema.*

---

## 🧪 Running the Security Test Suite

Execute the automated test suite with pytest:
```bash
pytest -v tests/test_security.py
```

All 15 security verification tests will execute against an isolated temporary SQLite database, verifying encryption at rest, tamper detection, rate limiting, SQL injection defense, XSS escaping, IDOR protection, CSRF enforcement, session timeouts, and lockout policies.

---

## 🎓 5-Minute Viva & Evaluation Demo Script

Follow this step-by-step workflow during a viva or practical presentation:

1. **Demonstrate Password Policy & Salted Hashing**:
   - Open `http://127.0.0.1:5000/register`.
   - Type a weak password (e.g., `test1234`). Point out the live strength meter and the complexity checklist dynamically verifying length, uppercase, lowercase, digits, and symbols.
   - Enter a compliant password (`DemoVault@2026!`) and submit.
2. **Demonstrate Dashboard & Encryption at Rest**:
   - Log in at `http://127.0.0.1:5000/login`.
   - In the **Secure Notes** tab, create a new note with Title `Project Secret Alpha` and confidential content.
   - In the **Credentials** tab, click **Add Credential**: Site `ProtonMail`, Username `student@proton.me`, Password `SecretEmailPass#99`. Notice that passwords render masked as `••••••••`.
3. **Demonstrate Decryption on Demand & Auto-Masking**:
   - Click **Reveal** on the credential. The password is decrypted in memory and displays a 10-second countdown `Mask (10s)`. Once the timer reaches 0, the UI automatically re-masks the password.
4. **Show Cryptographic Proof in Browser**:
   - Click the **View Ciphertext** button on a note or credential. The application displays the exact stored base64 payload containing `nonce || ciphertext || GCM tag`.
5. **Inspect the Raw SQLite Database (The "Show DB" Proof)**:
   - In a terminal, run:
     ```bash
     python scripts/show_db.py
     ```
   - Show the evaluator the terminal output:
     - The `users` table contains only `scrypt:` salted password hashes and 16-byte random salts.
     - The `notes` and `credentials` tables contain **zero plaintext strings**; every sensitive column is an authenticated AES-256-GCM ciphertext blob.
6. **Demonstrate SQL Injection Resilience**:
   - Log out and attempt to log in with username: `' OR '1'='1` and password: `RandomPassword123!`.
   - The application rejects the attempt with `401 Unauthorized` without crashing (no HTTP 500), proving parameterized SQL protection.
7. **Demonstrate XSS & Content Security Policy (CSP)**:
   - Log back in and create a note with Title `<script>alert(1)</script>`.
   - Notice the script does not execute because the frontend uses `textContent` and the browser enforces `default-src 'self'`.
8. **Demonstrate Rate Limiting**:
   - Log out and submit rapid invalid login attempts 6 times in a row.
   - On the 6th attempt, the application responds with `429 Too Many Requests`.
9. **Show Security Center & Live Status**:
   - Log in and navigate to the **Security Center** (`/security`).
   - Show the evaluator the live status chips (active session minutes remaining, cookie flags, active CSP, and encryption specs) and the threat model summary.

---

## 🔮 Known Limitations & Future Work

While SecureVault implements enterprise-grade software cryptography, production environments in industry often incorporate further enhancements:

1. **Hardware Security Modules (HSM) / Cloud KMS**:
   - *Current*: The master key is stored in the server's `.env` file with restrictive permissions.
   - *Future*: Integrate an external KMS (e.g., AWS KMS, HashiCorp Vault, or Google Cloud KMS) or physical HSM to enforce envelope encryption and avoid storing master keys on the filesystem.
2. **Two-Factor Authentication (2FA / MFA)**:
   - *Future*: Add Time-based One-Time Password (TOTP) using RFC 6238 (e.g., Google Authenticator) for multi-factor login verification.
3. **Distributed Rate Limiting & Session Storage**:
   - *Current*: In-memory rate limiting and signed cookies.
   - *Future*: Utilize Redis for distributed session storage and shared token-bucket rate limiting across load-balanced server clusters.
4. **Transport Layer Security (TLS/HTTPS)**:
   - *Current*: Default `COOKIE_SECURE=False` enables testing on `http://localhost`.
   - *Future*: Deploy behind a reverse proxy (e.g., Nginx or Caddy) with TLS certificates and set `COOKIE_SECURE=True` with HTTP Strict Transport Security (`HSTS`).
5. **Key & Password Rotation**:
   - *Future*: Add automated re-encryption pipelines allowing users to rotate master passwords and migrate records to fresh cryptographic keys.
