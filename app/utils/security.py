"""
Security utilities: token hashing, file hash computation.
"""
import hashlib
import secrets
from typing import Tuple

from app.config import get_settings


def hash_signing_token(token: str) -> str:
    """
    Hash a signing token using SHA-256 with salt.
    Used to store tokens securely in database.

    Note: Never log raw token or salt - use fingerprints only.
    """
    import logging
    logger = logging.getLogger(__name__)

    settings = get_settings()
    salt = settings.signing_token_salt

    # Safe fingerprints for correlation (no PII)
    salt_fp = hashlib.sha256(salt.encode()).hexdigest()[:8]
    token_fp = hashlib.sha256(token.encode()).hexdigest()[:8]

    salted = f"{salt}{token}"
    result = hashlib.sha256(salted.encode()).hexdigest()

    # Log with fingerprints only
    logger.debug(f"hash_signing_token: salt_fp={salt_fp}, token_fp={token_fp}, hash_fp={result[:8]}")
    return result


def generate_signing_token() -> Tuple[str, str]:
    """
    Generate a new signing token and its hash.

    Returns:
        Tuple of (plain_token, hashed_token)
    """
    token = secrets.token_urlsafe(32)
    token_hash = hash_signing_token(token)
    return token, token_hash


def verify_signing_token(plain_token: str, stored_hash: str) -> bool:
    """
    Verify a signing token against its stored hash.
    """
    computed_hash = hash_signing_token(plain_token)
    return secrets.compare_digest(computed_hash, stored_hash)


def compute_file_hash(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file.
    Reads file in chunks for memory efficiency.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_bytes_hash(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()
