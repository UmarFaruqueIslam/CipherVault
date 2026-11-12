"""Password-based key derivation using Scrypt."""

import secrets

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Scrypt configuration
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

# Key and salt configuration
SALT_LENGTH = 16
KEY_LENGTH = 32

# Application-level password input limit
MAX_PASSWORD_BYTES = 1024


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_LENGTH)


def _validate_password(password: str) -> bytes:
    """Validate and encode a password as UTF-8 bytes."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if not password:
        raise ValueError("password must not be empty")

    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("password must contain valid UTF-8 text") from exc

    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes")

    return password_bytes


def _validate_salt(salt: bytes) -> None:
    """Validate the salt."""
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be exactly {SALT_LENGTH} bytes")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using Scrypt.

    The caller must generate and preserve the salt for later
    key derivation during decryption.

    Args:
        password: User password as a string.
        salt: A 16-byte random salt.

    Returns:
        A 32-byte derived encryption key.
    """
    password_bytes = _validate_password(password)
    _validate_salt(salt)

    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(password_bytes)
