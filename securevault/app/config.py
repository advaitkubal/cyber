import os
import secrets
import base64
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Base directory for the securevault package
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

def _ensure_env_file() -> None:
    """Auto-generates a .env file with cryptographically secure random keys if one does not exist."""
    # SECURITY: Key Generation - Cryptographically strong keys generated on first run
    if not ENV_FILE.exists():
        secret_key = secrets.token_hex(32)
        master_key_bytes = os.urandom(32)
        master_key_b64 = base64.b64encode(master_key_bytes).decode("ascii")

        content = (
            "# Auto-generated SecureVault environment configuration\n"
            f"SECRET_KEY={secret_key}\n"
            f"ENCRYPTION_MASTER_KEY={master_key_b64}\n"
            "COOKIE_SECURE=False\n"
            "DATABASE_PATH=securevault.db\n"
            "RATELIMIT_ENABLED=True\n"
        )
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.write(content)

# Ensure .env is present and load variables into the environment
_ensure_env_file()
load_dotenv(dotenv_path=ENV_FILE)

class Config:
    """Application configuration settings."""
    # SECURITY: Session Signing - Secret key used by Flask to sign session cookies
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_hex(32)

    # SECURITY: Master Key - 32-byte AES root key stored outside the database
    ENCRYPTION_MASTER_KEY = os.environ.get("ENCRYPTION_MASTER_KEY", "")

    # Database file path
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "securevault.db"))
    if not os.path.isabs(DATABASE_PATH):
        DATABASE_PATH = str(BASE_DIR / DATABASE_PATH)

    # SECURITY: Cookie Flags - Restrict cookie access to prevent theft via scripts or cross-site requests
    COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = COOKIE_SECURE
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # SECURITY: Rate Limiting - Switchable for test suites
    RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "True").lower() in ("true", "1", "yes")

    # SECURITY: Request Size Limitation - Protects server memory from DoS upload attacks
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB maximum payload
