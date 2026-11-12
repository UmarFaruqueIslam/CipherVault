"""AES-256-GCM authenticated encryption operations."""

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def _validate_bytes(name: str, value: object) -> None:
    """Ensure a value is bytes."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _validate_key(key: bytes) -> None:
    """Validate an AES-256 key."""
    _validate_bytes("key", key)

    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")


def _validate_nonce(nonce: bytes) -> None:
    """Validate the GCM nonce."""
    _validate_bytes("nonce", nonce)

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")


def _validate_aad(aad: bytes | None) -> None:
    """Validate additional authenticated data."""
    if aad is not None:
        _validate_bytes("aad", aad)


def encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Returns:
        A tuple containing (nonce, ciphertext, authentication_tag).
    """
    _validate_key(key)
    _validate_bytes("plaintext", plaintext)
    _validate_aad(aad)

    nonce = secrets.token_bytes(NONCE_SIZE)

    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, plaintext, aad)

    ciphertext = encrypted_data[:-TAG_SIZE]
    tag = encrypted_data[-TAG_SIZE:]

    return nonce, ciphertext, tag


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Authenticate and decrypt AES-256-GCM ciphertext.

    Raises:
        TypeError: If an input has an invalid type.
        ValueError: If an input has an invalid length.
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    _validate_key(key)
    _validate_nonce(nonce)
    _validate_bytes("ciphertext", ciphertext)
    _validate_bytes("tag", tag)
    _validate_aad(aad)

    if len(tag) != TAG_SIZE:
        raise ValueError("AES-GCM authentication tag must be 16 bytes")

    aesgcm = AESGCM(key)

    encrypted_data = ciphertext + tag

    return aesgcm.decrypt(nonce, encrypted_data, aad)
