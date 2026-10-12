import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class DecryptionError(Exception):
    """Raised when decryption or integrity verification fails."""
    pass

def decode_master_key(master_key_b64: str) -> bytes:
    """Decodes and validates the base64-encoded master key from environment."""
    # SECURITY: Master Key Validation - Ensures master key is strictly 32 bytes (256 bits)
    raw = base64.b64decode(master_key_b64)
    if len(raw) != 32:
        raise ValueError("ENCRYPTION_MASTER_KEY must be exactly 32 bytes (256 bits).")
    return raw

def derive_user_key(master_key: bytes, user_salt: bytes) -> bytes:
    """
    Derives a unique 256-bit AES key for a specific user using HKDF-SHA256.
    Ensures cryptographic domain separation between different users.
    """
    # SECURITY: HKDF Key Derivation - Cryptographically binds data to individual users with salt and info
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=user_salt,
        info=b"securevault-user-key-v1",
    )
    return hkdf.derive(master_key)

def encrypt(user_key: bytes, plaintext: Optional[str], user_id: int) -> str:
    """
    Encrypts plaintext using AES-256-GCM.
    Uses a fresh 12-byte cryptographically secure random nonce for every call.
    Binds the ciphertext to the user_id via Associated Authenticated Data (AAD).
    Returns base64(nonce || ciphertext_with_tag).
    """
    if plaintext is None:
        plaintext = ""

    # SECURITY: AES-256-GCM - Authenticated encryption ensuring confidentiality and integrity
    aesgcm = AESGCM(user_key)
    # SECURITY: Unique Nonce - Fresh 12-byte random nonce per encryption prevents nonce-reuse attacks
    nonce = os.urandom(12)
    # SECURITY: Associated Data Binding - Binds record ciphertext to the owner user_id to prevent cross-user swapping
    associated_data = f"user:{user_id}".encode("utf-8")

    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    combined = nonce + ciphertext_with_tag
    return base64.b64encode(combined).decode("ascii")

def decrypt(user_key: bytes, ciphertext_b64: Optional[str], user_id: int) -> str:
    """
    Decrypts base64(nonce || ciphertext_with_tag) using AES-256-GCM.
    Verifies GCM authentication tag against the associated user_id.
    Raises DecryptionError if the ciphertext was tampered with or corrupted.
    """
    if not ciphertext_b64:
        return ""

    try:
        combined = base64.b64decode(ciphertext_b64)
    except Exception as e:
        # SECURITY: Tamper Detection - Invalid base64 indicates malformed or tampered payload
        raise DecryptionError(f"Base64 decoding failed: {e}") from e

    if len(combined) < 12 + 16:  # 12-byte nonce + minimum 16-byte tag
        raise DecryptionError("Ciphertext payload is too short.")

    nonce = combined[:12]
    ciphertext_with_tag = combined[12:]
    associated_data = f"user:{user_id}".encode("utf-8")

    aesgcm = AESGCM(user_key)
    try:
        # SECURITY: Authentication Tag Verification - AES-GCM guarantees integrity; raises InvalidTag on tampering
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag as e:
        raise DecryptionError("GCM authentication tag verification failed. Ciphertext has been tampered with.") from e
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e
