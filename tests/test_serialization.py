"""Tests for CipherVault versioned JSON serialization."""

import json

import pytest

from ciphervault import serialization
from ciphervault.serialization import (
    FORMAT_NAME,
    FORMAT_VERSION,
    build_aad,
    build_header,
    deserialize_envelope,
    serialize_envelope,
)


@pytest.fixture
def password_header() -> dict:
    """Provide a valid password-mode header."""
    return build_header(
        "password",
        salt=b"s" * 16,
    )


@pytest.fixture
def rsa_header() -> dict:
    """Provide a valid RSA-mode header."""
    return build_header(
        "rsa",
        encrypted_key=b"k" * 384,
    )


@pytest.fixture
def encrypted_fields() -> tuple[bytes, bytes, bytes]:
    """Provide representative AES-GCM output fields."""
    return (
        b"n" * 12,
        b"example ciphertext",
        b"t" * 16,
    )


@pytest.mark.parametrize("mode", ["password", "rsa"])
def test_build_header_returns_valid_format(mode) -> None:
    """Headers should contain the correct format and version."""
    if mode == "password":
        header = build_header(mode, salt=b"s" * 16)
    else:
        header = build_header(mode, encrypted_key=b"k" * 384)

    assert header["format"] == FORMAT_NAME
    assert header["version"] == FORMAT_VERSION
    assert header["mode"] == mode
    assert header["cipher"] == "AES-256-GCM"


def test_password_header_contains_scrypt_parameters(
    password_header,
) -> None:
    """Password headers should contain the supported Scrypt profile."""
    kdf = password_header["kdf"]

    assert kdf["algorithm"] == "scrypt"
    assert kdf["n"] == 2**17
    assert kdf["r"] == 8
    assert kdf["p"] == 1
    assert len(kdf["salt"]) > 0


def test_rsa_header_contains_oaep_parameters(rsa_header) -> None:
    """RSA headers should identify the supported OAEP configuration."""
    key_encryption = rsa_header["key_encryption"]

    assert key_encryption["algorithm"] == "RSA-OAEP"
    assert key_encryption["hash"] == "SHA-256"
    assert key_encryption["mgf"] == "MGF1-SHA256"


def test_password_envelope_round_trip(
    password_header,
    encrypted_fields,
) -> None:
    """Password-mode envelopes should serialize and deserialize."""
    nonce, ciphertext, tag = encrypted_fields

    serialized = serialize_envelope(
        password_header,
        nonce,
        ciphertext,
        tag,
    )

    header, loaded_nonce, loaded_ciphertext, loaded_tag = deserialize_envelope(
        serialized
    )

    assert header == password_header
    assert loaded_nonce == nonce
    assert loaded_ciphertext == ciphertext
    assert loaded_tag == tag


def test_rsa_envelope_round_trip(
    rsa_header,
    encrypted_fields,
) -> None:
    """RSA-mode envelopes should serialize and deserialize."""
    nonce, ciphertext, tag = encrypted_fields

    serialized = serialize_envelope(
        rsa_header,
        nonce,
        ciphertext,
        tag,
    )

    header, loaded_nonce, loaded_ciphertext, loaded_tag = deserialize_envelope(
        serialized
    )

    assert header == rsa_header
    assert loaded_nonce == nonce
    assert loaded_ciphertext == ciphertext
    assert loaded_tag == tag


def test_empty_ciphertext_round_trip(password_header) -> None:
    """Empty plaintext ciphertext should be accepted."""
    nonce = b"n" * 12
    tag = b"t" * 16

    serialized = serialize_envelope(
        password_header,
        nonce,
        b"",
        tag,
    )

    _, _, ciphertext, _ = deserialize_envelope(serialized)

    assert ciphertext == b""


def test_serialized_envelope_is_json(password_header) -> None:
    """Serialized envelopes should be valid UTF-8 JSON."""
    serialized = serialize_envelope(
        password_header,
        b"n" * 12,
        b"data",
        b"t" * 16,
    )

    parsed = json.loads(serialized.decode("utf-8"))

    assert isinstance(parsed, dict)
    assert parsed["format"] == FORMAT_NAME


def test_aad_is_deterministic(password_header) -> None:
    """The same header should produce identical AAD bytes."""
    first = build_aad(password_header)
    second = build_aad(password_header)

    assert first == second


def test_aad_changes_when_header_changes(password_header) -> None:
    """Different valid headers should produce different AAD."""
    original_aad = build_aad(password_header)

    modified_header = build_header(
        "password",
        salt=b"d" * 16,
    )

    modified_aad = build_aad(modified_header)

    assert original_aad != modified_aad


def test_aad_is_independent_of_dictionary_order(password_header) -> None:
    """Dictionary insertion order should not change canonical AAD."""
    reordered_header = dict(reversed(list(password_header.items())))

    assert build_aad(password_header) == build_aad(reordered_header)


def test_invalid_mode_rejected() -> None:
    """Unsupported encryption modes should be rejected."""
    with pytest.raises(ValueError, match="mode"):
        build_header("unsupported")


def test_invalid_salt_type_rejected() -> None:
    """Salt must be bytes."""
    with pytest.raises(TypeError, match="salt must be bytes"):
        build_header("password", salt="invalid")


def test_invalid_salt_length_rejected() -> None:
    """Salt must contain exactly 16 bytes."""
    with pytest.raises(ValueError, match="16 bytes"):
        build_header("password", salt=b"short")


def test_invalid_rsa_encrypted_key_length_rejected() -> None:
    """RSA ciphertext must meet the configured size limits."""
    with pytest.raises(ValueError, match="unsupported length"):
        build_header("rsa", encrypted_key=b"short")


def test_password_mode_rejects_encrypted_key() -> None:
    """Password mode must not accept RSA key material."""
    with pytest.raises(ValueError, match="encrypted_key"):
        build_header(
            "password",
            salt=b"s" * 16,
            encrypted_key=b"k" * 384,
        )


def test_rsa_mode_rejects_salt() -> None:
    """RSA mode must not accept a Scrypt salt."""
    with pytest.raises(ValueError, match="salt"):
        build_header(
            "rsa",
            salt=b"s" * 16,
            encrypted_key=b"k" * 384,
        )


@pytest.mark.parametrize(
    ("nonce", "ciphertext", "tag", "error"),
    [
        ("invalid", b"data", b"t" * 16, TypeError),
        (b"short", b"data", b"t" * 16, ValueError),
        (b"n" * 12, "invalid", b"t" * 16, TypeError),
        (b"n" * 12, b"data", "invalid", TypeError),
        (b"n" * 12, b"data", b"short", ValueError),
    ],
)
def test_invalid_encryption_fields_rejected(
    password_header,
    nonce,
    ciphertext,
    tag,
    error,
) -> None:
    """Invalid AES-GCM output fields should be rejected."""
    with pytest.raises(error):
        serialize_envelope(
            password_header,
            nonce,
            ciphertext,
            tag,
        )


def test_non_bytes_serialized_input_rejected() -> None:
    """The deserializer must receive bytes."""
    with pytest.raises(TypeError, match="must be bytes"):
        deserialize_envelope("not bytes")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not JSON",
        b"\xff\xfe\xfd",
        b"[]",
        b"null",
        b'{"value": NaN}',
    ],
)
def test_invalid_json_rejected(data) -> None:
    """Malformed or unsupported JSON input should be rejected."""
    with pytest.raises(ValueError):
        deserialize_envelope(data)


def test_json_recursion_error_rejected(monkeypatch) -> None:
    """A JSON parser recursion error must produce a controlled ValueError."""

    def raise_recursion_error(*args, **kwargs):
        raise RecursionError("Simulated JSON recursion error")

    monkeypatch.setattr(
        "ciphervault.serialization.json.loads",
        raise_recursion_error,
    )

    with pytest.raises(ValueError, match="Invalid serialized envelope"):
        deserialize_envelope(b'{"mode":"password"}')


def test_duplicate_json_keys_rejected() -> None:
    """Duplicate JSON object keys must not be silently accepted."""
    data = b'{"format":"CipherVault","format":"Other"}'

    with pytest.raises(ValueError, match="Duplicate JSON key"):
        deserialize_envelope(data)


def test_unknown_mode_rejected() -> None:
    """Unknown encryption modes must be rejected."""
    data = json.dumps({"mode": "unknown"}).encode()

    with pytest.raises(ValueError, match="Unsupported encryption mode"):
        deserialize_envelope(data)


def test_missing_envelope_field_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Missing required envelope fields must be rejected."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    del envelope["tag"]

    with pytest.raises(ValueError, match="Missing fields"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_unexpected_envelope_field_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Unexpected envelope fields must be rejected."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["unexpected"] = "value"

    with pytest.raises(ValueError, match="Unexpected fields"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_invalid_base64_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Invalid Base64 values must be rejected."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["nonce"] = "%%%invalid%%%"

    with pytest.raises(ValueError, match="Base64"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_invalid_nonce_length_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Decoded nonce must contain exactly 12 bytes."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["nonce"] = "c2hvcnQ="

    with pytest.raises(ValueError, match="nonce"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_invalid_tag_length_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Decoded authentication tag must contain exactly 16 bytes."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["tag"] = "c2hvcnQ="

    with pytest.raises(ValueError, match="tag"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_unsupported_version_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Unsupported format versions must be rejected."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["version"] = 999

    with pytest.raises(ValueError, match="version"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_boolean_version_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Boolean values must not be accepted as integer versions."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["version"] = True

    with pytest.raises(TypeError, match="version"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_unsupported_cipher_rejected(
    password_header,
    encrypted_fields,
) -> None:
    """Unsupported cipher identifiers must be rejected."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    envelope = json.loads(serialized)
    envelope["cipher"] = "unsupported"

    with pytest.raises(ValueError, match="encryption algorithm"):
        deserialize_envelope(json.dumps(envelope).encode())


def test_oversized_serialized_envelope_rejected(
    password_header,
    monkeypatch,
) -> None:
    """Serialization must enforce the maximum envelope size."""
    monkeypatch.setattr(serialization, "MAX_ENVELOPE_SIZE", 100)

    with pytest.raises(ValueError, match="maximum allowed size"):
        serialize_envelope(
            password_header,
            b"n" * 12,
            b"x" * 200,
            b"t" * 16,
        )


def test_oversized_input_rejected(
    password_header,
    encrypted_fields,
    monkeypatch,
) -> None:
    """Deserialization must enforce the maximum input size."""
    serialized = serialize_envelope(
        password_header,
        *encrypted_fields,
    )

    monkeypatch.setattr(serialization, "MAX_ENVELOPE_SIZE", 10)

    with pytest.raises(ValueError, match="maximum allowed size"):
        deserialize_envelope(serialized)


def test_invalid_header_type_rejected() -> None:
    """Header must be a dictionary."""
    with pytest.raises(TypeError, match="header"):
        build_aad("invalid")
