"""Password-based key derivation for file encryption."""

from __future__ import annotations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# PBKDF2 parameters (NIST-recommended minimum iteration count for interactive use).
PBKDF2_ITERATIONS: int = 100_000
KEY_LENGTH_BYTES: int = 32  # AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: User-supplied passphrase (UTF-8 encoded internally).
        salt: Random salt stored with the encrypted file (16 bytes).

    Returns:
        32-byte key suitable for AES-256-GCM.

    Raises:
        ValueError: If salt length is not 16 bytes.
    """
    if len(salt) != 16:
        raise ValueError(f"Salt must be exactly 16 bytes, got {len(salt)}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))
