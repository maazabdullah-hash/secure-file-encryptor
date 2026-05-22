"""AES-256-GCM file encryption and decryption."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_manager import derive_key

# On-disk layout: [salt][nonce][ciphertext][tag]
SALT_SIZE: int = 16
NONCE_SIZE: int = 12
TAG_SIZE: int = 16
HEADER_SIZE: int = SALT_SIZE + NONCE_SIZE
MIN_ENCRYPTED_FILE_SIZE: int = HEADER_SIZE + TAG_SIZE


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class FileFormatError(CryptoError):
    """Raised when an encrypted file is too short or malformed."""


class FileNotFoundCryptoError(CryptoError):
    """Raised when the input path does not exist."""


def _read_file_bytes(path: Path) -> bytes:
    """Read entire file contents.

    Args:
        path: Path to the file.

    Returns:
        Raw file bytes.

    Raises:
        FileNotFoundCryptoError: If the path does not exist.
    """
    if not path.is_file():
        raise FileNotFoundCryptoError(f"File not found: {path}")
    return path.read_bytes()


def _write_file_bytes(path: Path, data: bytes) -> None:
    """Write bytes to a file.

    Args:
        path: Destination path.
        data: Content to write.
    """
    path.write_bytes(data)


def encrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    """Encrypt a file with AES-256-GCM using a password-derived key.

    Output format: 16-byte salt | 12-byte nonce | ciphertext | 16-byte tag.

    Args:
        input_path: Plaintext file to encrypt.
        output_path: Where to write the encrypted blob.
        password: Passphrase for key derivation.

    Raises:
        FileNotFoundCryptoError: If input_path does not exist.
        ValueError: If password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    plaintext = _read_file_bytes(input_path)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext.
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]

    blob = salt + nonce + ciphertext + tag
    _write_file_bytes(output_path, blob)


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    """Decrypt a file produced by encrypt_file.

    Args:
        input_path: Encrypted file (salt + nonce + ciphertext + tag).
        output_path: Where to write decrypted plaintext.
        password: Same passphrase used for encryption.

    Raises:
        FileNotFoundCryptoError: If input_path does not exist.
        FileFormatError: If the file is too short or truncated.
        InvalidTag: If the password is wrong or data was tampered with.
        ValueError: If password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    blob = _read_file_bytes(input_path)
    if len(blob) < MIN_ENCRYPTED_FILE_SIZE:
        raise FileFormatError(
            "File is too small or corrupted: missing header or authentication tag."
        )

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[HEADER_SIZE:-TAG_SIZE]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    except InvalidTag:
        # Re-raise so callers (and tests) see the standard cryptography exception.
        raise

    _write_file_bytes(output_path, plaintext)


# Re-export for convenience and tests.
__all__ = [
    "CryptoError",
    "FileFormatError",
    "FileNotFoundCryptoError",
    "encrypt_file",
    "decrypt_file",
    "SALT_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "HEADER_SIZE",
    "MIN_ENCRYPTED_FILE_SIZE",
    "InvalidTag",
]
