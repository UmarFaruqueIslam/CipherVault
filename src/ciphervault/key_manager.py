"""Secure RSA private-key and public-key storage."""

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from ciphervault.rsa import RSA_KEY_SIZE

# Application-level input limits
MAX_PASSPHRASE_BYTES = 1024
MAX_KEY_FILE_BYTES = 64 * 1024

# Linux file permissions
PRIVATE_KEY_FILE_MODE = 0o600
PUBLIC_KEY_FILE_MODE = 0o644


def _validate_passphrase(passphrase: str) -> bytes:
    """Validate and encode a private-key passphrase."""
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string")

    if not passphrase:
        raise ValueError("passphrase must not be empty")

    try:
        passphrase_bytes = passphrase.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("passphrase must contain valid UTF-8 text") from exc

    if len(passphrase_bytes) > MAX_PASSPHRASE_BYTES:
        raise ValueError(
            f"passphrase must not exceed {MAX_PASSPHRASE_BYTES} UTF-8 bytes"
        )

    return passphrase_bytes


def _validate_private_key(private_key: RSAPrivateKey) -> None:
    """Validate an RSA private key."""
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")

    if private_key.key_size < RSA_KEY_SIZE:
        raise ValueError("RSA key must be at least 3072 bits")


def _validate_public_key(public_key: RSAPublicKey) -> None:
    """Validate an RSA public key."""
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")

    if public_key.key_size < RSA_KEY_SIZE:
        raise ValueError("RSA key must be at least 3072 bits")


def _atomic_write(
    file_path: str | Path,
    data: bytes,
    mode: int,
) -> None:
    """Create a file atomically without overwriting an existing destination."""
    path = Path(file_path)

    if not path.parent.is_dir():
        raise FileNotFoundError("Parent directory does not exist")

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

            os.fchmod(temporary_file.fileno(), mode)

            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.link(temporary_path, path)

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_key_file(file_path: str | Path) -> bytes:
    """Read a key file with a strict maximum size limit."""
    path = Path(file_path)

    with path.open("rb") as key_file:
        data = key_file.read(MAX_KEY_FILE_BYTES + 1)

    if len(data) > MAX_KEY_FILE_BYTES:
        raise ValueError("Key file exceeds the maximum allowed size")

    return data


def save_private_key(
    private_key: RSAPrivateKey,
    file_path: str | Path,
    passphrase: str,
) -> None:
    """Serialize and save an encrypted RSA private key."""
    _validate_private_key(private_key)
    passphrase_bytes = _validate_passphrase(passphrase)

    encrypted_pem = private_key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.BestAvailableEncryption(
            passphrase_bytes
        ),
    )

    _atomic_write(
        file_path,
        encrypted_pem,
        PRIVATE_KEY_FILE_MODE,
    )


def load_private_key(
    file_path: str | Path,
    passphrase: str,
) -> RSAPrivateKey:
    """Load and decrypt an RSA private key."""
    passphrase_bytes = _validate_passphrase(passphrase)
    encrypted_pem = _read_key_file(file_path)

    private_key = crypto_serialization.load_pem_private_key(
        encrypted_pem,
        password=passphrase_bytes,
    )

    _validate_private_key(private_key)

    return private_key


def save_public_key(
    public_key: RSAPublicKey,
    file_path: str | Path,
) -> None:
    """Serialize and save an RSA public key."""
    _validate_public_key(public_key)

    public_pem = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _atomic_write(
        file_path,
        public_pem,
        PUBLIC_KEY_FILE_MODE,
    )


def load_public_key(
    file_path: str | Path,
) -> RSAPublicKey:
    """Load an RSA public key."""
    public_pem = _read_key_file(file_path)

    public_key = crypto_serialization.load_pem_public_key(public_pem)

    _validate_public_key(public_key)

    return public_key
