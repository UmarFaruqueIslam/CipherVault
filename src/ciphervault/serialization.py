"""Versioned JSON serialization for CipherVault encrypted envelopes."""

import base64
import binascii
import json
from typing import Any

from ciphervault.aes import NONCE_SIZE, TAG_SIZE
from ciphervault.kdf import (
    SALT_LENGTH,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)

FORMAT_NAME = "CipherVault"
FORMAT_VERSION = 1

CIPHER_ALGORITHM = "AES-256-GCM"
KDF_ALGORITHM = "scrypt"
KEY_ENCRYPTION_ALGORITHM = "RSA-OAEP"
KEY_ENCRYPTION_HASH = "SHA-256"
KEY_ENCRYPTION_MGF = "MGF1-SHA256"

MAX_ENVELOPE_SIZE = 16 * 1024 * 1024
MIN_RSA_CIPHERTEXT_SIZE = 384
MAX_RSA_CIPHERTEXT_SIZE = 1024


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate keys while parsing JSON objects."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")

        result[key] = value

    return result


def _reject_json_constant(value: str) -> None:
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise ValueError(f"Invalid JSON constant: {value}")


def _encode_base64(value: bytes) -> str:
    """Encode bytes as standard Base64 ASCII text."""
    if not isinstance(value, bytes):
        raise TypeError("Base64 input must be bytes")

    return base64.b64encode(value).decode("ascii")


def _decode_base64(name: str, value: Any) -> bytes:
    """Decode and validate a Base64 string."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a Base64 string")

    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} contains invalid Base64 data") from exc

    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{name} must use canonical Base64 encoding")

    return decoded


def _require_exact_fields(
    data: dict[str, Any],
    expected_fields: set[str],
) -> None:
    """Reject missing or unexpected object fields."""
    actual_fields = set(data)

    missing = expected_fields - actual_fields
    unexpected = actual_fields - expected_fields

    if missing:
        raise ValueError(f"Missing fields: {sorted(missing)}")

    if unexpected:
        raise ValueError(f"Unexpected fields: {sorted(unexpected)}")


def _validate_header(header: dict[str, Any]) -> None:
    """Validate a version 1 encryption header."""
    if not isinstance(header, dict):
        raise TypeError("header must be a dictionary")

    common_fields = {
        "format",
        "version",
        "mode",
        "cipher",
    }

    if not common_fields.issubset(header):
        raise ValueError("Header is missing required fields")

    if header["format"] != FORMAT_NAME:
        raise ValueError("Unsupported file format")

    if type(header["version"]) is not int:
        raise TypeError("version must be an integer")

    if header["version"] != FORMAT_VERSION:
        raise ValueError("Unsupported CipherVault version")

    if header["cipher"] != CIPHER_ALGORITHM:
        raise ValueError("Unsupported encryption algorithm")

    mode = header["mode"]

    if mode == "password":
        _require_exact_fields(
            header,
            common_fields | {"kdf"},
        )

        kdf = header["kdf"]

        if not isinstance(kdf, dict):
            raise TypeError("kdf must be an object")

        _require_exact_fields(
            kdf,
            {"algorithm", "n", "r", "p", "salt"},
        )

        if kdf["algorithm"] != KDF_ALGORITHM:
            raise ValueError("Unsupported KDF algorithm")

        if type(kdf["n"]) is not int or kdf["n"] != SCRYPT_N:
            raise ValueError("Unsupported Scrypt N parameter")

        if type(kdf["r"]) is not int or kdf["r"] != SCRYPT_R:
            raise ValueError("Unsupported Scrypt r parameter")

        if type(kdf["p"]) is not int or kdf["p"] != SCRYPT_P:
            raise ValueError("Unsupported Scrypt p parameter")

        salt = _decode_base64("salt", kdf["salt"])

        if len(salt) != SALT_LENGTH:
            raise ValueError("Scrypt salt must be exactly 16 bytes")

    elif mode == "rsa":
        _require_exact_fields(
            header,
            common_fields | {"key_encryption"},
        )

        key_encryption = header["key_encryption"]

        if not isinstance(key_encryption, dict):
            raise TypeError("key_encryption must be an object")

        _require_exact_fields(
            key_encryption,
            {"algorithm", "hash", "mgf", "encrypted_key"},
        )

        if key_encryption["algorithm"] != KEY_ENCRYPTION_ALGORITHM:
            raise ValueError("Unsupported RSA key encryption algorithm")

        if key_encryption["hash"] != KEY_ENCRYPTION_HASH:
            raise ValueError("Unsupported RSA-OAEP hash algorithm")

        if key_encryption["mgf"] != KEY_ENCRYPTION_MGF:
            raise ValueError("Unsupported RSA-OAEP mask generation function")

        encrypted_key = _decode_base64(
            "encrypted_key",
            key_encryption["encrypted_key"],
        )

        if not (
            MIN_RSA_CIPHERTEXT_SIZE <= len(encrypted_key) <= MAX_RSA_CIPHERTEXT_SIZE
        ):
            raise ValueError("RSA encrypted key has an unsupported length")

    else:
        raise ValueError("Unsupported encryption mode")


def build_header(
    mode: str,
    *,
    salt: bytes | None = None,
    encrypted_key: bytes | None = None,
) -> dict[str, Any]:
    """Build a validated version 1 encryption header."""
    if mode == "password":
        if not isinstance(salt, bytes):
            raise TypeError("salt must be bytes")

        if len(salt) != SALT_LENGTH:
            raise ValueError("Scrypt salt must be exactly 16 bytes")

        if encrypted_key is not None:
            raise ValueError("encrypted_key is not valid in password mode")

        header = {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "mode": "password",
            "cipher": CIPHER_ALGORITHM,
            "kdf": {
                "algorithm": KDF_ALGORITHM,
                "n": SCRYPT_N,
                "r": SCRYPT_R,
                "p": SCRYPT_P,
                "salt": _encode_base64(salt),
            },
        }

    elif mode == "rsa":
        if not isinstance(encrypted_key, bytes):
            raise TypeError("encrypted_key must be bytes")

        if salt is not None:
            raise ValueError("salt is not valid in RSA mode")

        header = {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "mode": "rsa",
            "cipher": CIPHER_ALGORITHM,
            "key_encryption": {
                "algorithm": KEY_ENCRYPTION_ALGORITHM,
                "hash": KEY_ENCRYPTION_HASH,
                "mgf": KEY_ENCRYPTION_MGF,
                "encrypted_key": _encode_base64(encrypted_key),
            },
        }

    else:
        raise ValueError("mode must be 'password' or 'rsa'")

    _validate_header(header)

    return header


def build_aad(header: dict[str, Any]) -> bytes:
    """Build canonical authenticated additional data from a header."""
    _validate_header(header)

    return json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def extract_salt(header: dict[str, Any]) -> bytes:
    """Extract the validated Scrypt salt from a password header."""
    _validate_header(header)

    if header["mode"] != "password":
        raise ValueError("Header is not password-protected")

    return _decode_base64("salt", header["kdf"]["salt"])


def extract_encrypted_key(header: dict[str, Any]) -> bytes:
    """Extract the validated RSA-encrypted AES key from an RSA header."""
    _validate_header(header)

    if header["mode"] != "rsa":
        raise ValueError("Header is not RSA-protected")

    return _decode_base64(
        "encrypted_key",
        header["key_encryption"]["encrypted_key"],
    )


def serialize_envelope(
    header: dict[str, Any],
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Serialize an encryption header and AES-GCM output into JSON bytes."""
    _validate_header(header)

    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")

    if not isinstance(tag, bytes):
        raise TypeError("tag must be bytes")

    if len(tag) != TAG_SIZE:
        raise ValueError("AES-GCM tag must be exactly 16 bytes")

    envelope = {
        **header,
        "nonce": _encode_base64(nonce),
        "ciphertext": _encode_base64(ciphertext),
        "tag": _encode_base64(tag),
    }

    serialized = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")

    if len(serialized) > MAX_ENVELOPE_SIZE:
        raise ValueError("Serialized envelope exceeds maximum allowed size")

    return serialized


def deserialize_envelope(
    data: bytes,
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Parse and validate a serialized CipherVault encryption envelope.

    Returns:
        A tuple containing:
        (header, nonce, ciphertext, authentication_tag).
    """
    if not isinstance(data, bytes):
        raise TypeError("serialized envelope must be bytes")

    if not data:
        raise ValueError("Serialized envelope must not be empty")

    if len(data) > MAX_ENVELOPE_SIZE:
        raise ValueError("Serialized envelope exceeds maximum allowed size")

    try:
        text = data.decode("utf-8")

        envelope = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise ValueError("Invalid serialized envelope") from exc

    if not isinstance(envelope, dict):
        raise ValueError("Serialized envelope must be a JSON object")

    common_header_fields = {
        "format",
        "version",
        "mode",
        "cipher",
    }

    mode = envelope.get("mode")

    if mode == "password":
        header_fields = common_header_fields | {"kdf"}

    elif mode == "rsa":
        header_fields = common_header_fields | {"key_encryption"}

    else:
        raise ValueError("Unsupported encryption mode")

    _require_exact_fields(
        envelope,
        header_fields | {"nonce", "ciphertext", "tag"},
    )

    header = {field: envelope[field] for field in header_fields}

    _validate_header(header)

    nonce = _decode_base64("nonce", envelope["nonce"])
    ciphertext = _decode_base64("ciphertext", envelope["ciphertext"])
    tag = _decode_base64("tag", envelope["tag"])

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    if len(tag) != TAG_SIZE:
        raise ValueError("AES-GCM tag must be exactly 16 bytes")

    return header, nonce, ciphertext, tag
