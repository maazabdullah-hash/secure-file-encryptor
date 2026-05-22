"""Tests for AES-256-GCM file encryption and decryption."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from src.crypto import decrypt_file, encrypt_file


@pytest.fixture
def sample_plaintext(tmp_path: Path) -> tuple[Path, bytes]:
    """Create a small plaintext file for round-trip tests."""
    content = b"Sensitive report data: Q4 revenue figures."
    path = tmp_path / "secret.txt"
    path.write_bytes(content)
    return path, content


def test_encrypt_decrypt_roundtrip(
    tmp_path: Path, sample_plaintext: tuple[Path, bytes]
) -> None:
    """Encrypting then decrypting with the same password restores original content."""
    source, original = sample_plaintext
    encrypted = tmp_path / "secret.txt.enc"
    decrypted = tmp_path / "secret_restored.txt"
    password = "correct-horse-battery-staple"

    encrypt_file(source, encrypted, password)
    decrypt_file(encrypted, decrypted, password)

    assert decrypted.read_bytes() == original
    assert encrypted.stat().st_size >= 16 + 12 + 16  # salt + nonce + tag minimum


def test_wrong_password_raises_invalid_tag(
    tmp_path: Path, sample_plaintext: tuple[Path, bytes]
) -> None:
    """Decrypting with the wrong password raises InvalidTag."""
    source, _ = sample_plaintext
    encrypted = tmp_path / "secret.txt.enc"
    output = tmp_path / "out.txt"

    encrypt_file(source, encrypted, "password-one")

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, output, "password-two")


def test_tampered_ciphertext_raises_invalid_tag(
    tmp_path: Path, sample_plaintext: tuple[Path, bytes]
) -> None:
    """Modifying ciphertext bytes causes authentication failure (InvalidTag)."""
    source, _ = sample_plaintext
    encrypted = tmp_path / "secret.txt.enc"
    output = tmp_path / "out.txt"
    password = "tamper-test-password"

    encrypt_file(source, encrypted, password)
    data = bytearray(encrypted.read_bytes())
    # Flip a byte in the ciphertext region (after salt + nonce).
    if len(data) > 30:
        data[28] ^= 0xFF
    encrypted.write_bytes(bytes(data))

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, output, password)
