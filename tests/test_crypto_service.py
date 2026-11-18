"""End-to-end tests for CipherVault encryption workflows."""

import base64
import json

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from ciphervault.crypto_service import (
    decrypt_with_password,
    decrypt_with_private_key,
    encrypt_for_recipient,
    encrypt_with_password,
)
from ciphervault.rsa import generate_key_pair


@pytest.fixture(scope="module")
def rsa_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair for integration tests."""
    return generate_key_pair()


@pytest.fixture(scope="module")
def second_rsa_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a different RSA key pair for wrong-key tests."""
    return generate_key_pair()


@pytest.fixture
def password() -> str:
    """Provide a test password."""
    return "CipherVault-Integration-Test-2026!"


@pytest.fixture
def plaintext() -> bytes:
    """Provide representative plaintext."""
    return b"CipherVault integration testing."


# ---------------------------------------------------------
# Password-based encryption
# ---------------------------------------------------------


def test_password_encryption_round_trip(password, plaintext) -> None:
    """Password encryption should recover the original plaintext."""
    envelope = encrypt_with_password(plaintext, password)

    recovered = decrypt_with_password(envelope, password)

    assert recovered == plaintext


def test_password_encryption_supports_empty_plaintext(password) -> None:
    """Password encryption should support empty plaintext."""
    envelope = encrypt_with_password(b"", password)

    recovered = decrypt_with_password(envelope, password)

    assert recovered == b""


def test_password_encryption_supports_binary_data(password) -> None:
    """Password encryption should preserve arbitrary binary data."""
    plaintext = bytes(range(256))

    envelope = encrypt_with_password(plaintext, password)

    recovered = decrypt_with_password(envelope, password)

    assert recovered == plaintext


def test_password_encryption_supports_unicode(password) -> None:
    """Password encryption should preserve UTF-8 encoded text."""
    plaintext = "CipherVault — Secure Data".encode()

    envelope = encrypt_with_password(plaintext, password)

    recovered = decrypt_with_password(envelope, password)

    assert recovered == plaintext


def test_wrong_password_rejected(password, plaintext) -> None:
    """An incorrect password must fail AES-GCM authentication."""
    envelope = encrypt_with_password(plaintext, password)

    with pytest.raises(InvalidTag):
        decrypt_with_password(envelope, "incorrect-password")


def test_password_encryption_produces_different_envelopes(
    password,
    plaintext,
) -> None:
    """Repeated encryption should use fresh random salt and nonce."""
    first = encrypt_with_password(plaintext, password)
    second = encrypt_with_password(plaintext, password)

    assert first != second


def test_password_ciphertext_tampering_rejected(
    password,
    plaintext,
) -> None:
    """Modified ciphertext must fail AES-GCM authentication."""
    envelope = encrypt_with_password(plaintext, password)
    parsed = json.loads(envelope)

    ciphertext = bytearray(base64.b64decode(parsed["ciphertext"]))

    ciphertext[0] ^= 1

    parsed["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    tampered_envelope = json.dumps(parsed).encode("utf-8")

    with pytest.raises(InvalidTag):
        decrypt_with_password(tampered_envelope, password)


def test_password_authenticated_metadata_tampering_rejected(
    password,
    plaintext,
) -> None:
    """Changing the salt must invalidate the authenticated message."""
    envelope = encrypt_with_password(plaintext, password)
    parsed = json.loads(envelope)

    parsed["kdf"]["salt"] = base64.b64encode(b"x" * 16).decode("ascii")

    tampered_envelope = json.dumps(parsed).encode("utf-8")

    with pytest.raises(InvalidTag):
        decrypt_with_password(tampered_envelope, password)


# ---------------------------------------------------------
# RSA-based encryption
# ---------------------------------------------------------


def test_rsa_encryption_round_trip(
    rsa_key_pair,
    plaintext,
) -> None:
    """RSA recipient encryption should recover the original plaintext."""
    private_key, public_key = rsa_key_pair

    envelope = encrypt_for_recipient(plaintext, public_key)

    recovered = decrypt_with_private_key(envelope, private_key)

    assert recovered == plaintext


def test_rsa_encryption_supports_empty_plaintext(rsa_key_pair) -> None:
    """RSA recipient encryption should support empty plaintext."""
    private_key, public_key = rsa_key_pair

    envelope = encrypt_for_recipient(b"", public_key)

    recovered = decrypt_with_private_key(envelope, private_key)

    assert recovered == b""


def test_rsa_encryption_supports_binary_data(rsa_key_pair) -> None:
    """RSA recipient encryption should preserve arbitrary binary data."""
    private_key, public_key = rsa_key_pair
    plaintext = bytes(range(256))

    envelope = encrypt_for_recipient(plaintext, public_key)

    recovered = decrypt_with_private_key(envelope, private_key)

    assert recovered == plaintext


def test_rsa_encryption_supports_unicode(rsa_key_pair) -> None:
    """RSA recipient encryption should preserve UTF-8 encoded text."""
    private_key, public_key = rsa_key_pair
    plaintext = "CipherVault — Secure Data".encode()

    envelope = encrypt_for_recipient(plaintext, public_key)

    recovered = decrypt_with_private_key(envelope, private_key)

    assert recovered == plaintext


def test_wrong_rsa_private_key_rejected(
    rsa_key_pair,
    second_rsa_key_pair,
    plaintext,
) -> None:
    """A different RSA private key must not recover the AES key."""
    _, public_key = rsa_key_pair
    wrong_private_key, _ = second_rsa_key_pair

    envelope = encrypt_for_recipient(plaintext, public_key)

    with pytest.raises(ValueError):
        decrypt_with_private_key(envelope, wrong_private_key)


def test_rsa_ciphertext_tampering_rejected(
    rsa_key_pair,
    plaintext,
) -> None:
    """Modified RSA-mode ciphertext must fail AES-GCM authentication."""
    private_key, public_key = rsa_key_pair

    envelope = encrypt_for_recipient(plaintext, public_key)
    parsed = json.loads(envelope)

    ciphertext = bytearray(base64.b64decode(parsed["ciphertext"]))

    ciphertext[0] ^= 1

    parsed["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    tampered_envelope = json.dumps(parsed).encode("utf-8")

    with pytest.raises(InvalidTag):
        decrypt_with_private_key(tampered_envelope, private_key)


def test_rsa_encryption_produces_different_envelopes(
    rsa_key_pair,
    plaintext,
) -> None:
    """Repeated RSA-mode encryption should produce different envelopes."""
    _, public_key = rsa_key_pair

    first = encrypt_for_recipient(plaintext, public_key)
    second = encrypt_for_recipient(plaintext, public_key)

    assert first != second


# ---------------------------------------------------------
# Encryption mode validation
# ---------------------------------------------------------


def test_password_decryption_rejects_rsa_envelope(
    rsa_key_pair,
    password,
    plaintext,
) -> None:
    """Password decryption must reject RSA-mode envelopes."""
    _, public_key = rsa_key_pair

    envelope = encrypt_for_recipient(plaintext, public_key)

    with pytest.raises(ValueError, match="not password-protected"):
        decrypt_with_password(envelope, password)


def test_rsa_decryption_rejects_password_envelope(
    rsa_key_pair,
    password,
    plaintext,
) -> None:
    """RSA decryption must reject password-mode envelopes."""
    private_key, _ = rsa_key_pair

    envelope = encrypt_with_password(plaintext, password)

    with pytest.raises(ValueError, match="not RSA-protected"):
        decrypt_with_private_key(envelope, private_key)


# ---------------------------------------------------------
# Input validation
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "invalid_plaintext",
    [
        "text instead of bytes",
        12345,
        None,
    ],
)
def test_password_encryption_rejects_invalid_plaintext(
    password,
    invalid_plaintext,
) -> None:
    """Password encryption must require bytes."""
    with pytest.raises(TypeError, match="plaintext must be bytes"):
        encrypt_with_password(invalid_plaintext, password)


@pytest.mark.parametrize(
    "invalid_plaintext",
    [
        "text instead of bytes",
        12345,
        None,
    ],
)
def test_rsa_encryption_rejects_invalid_plaintext(
    rsa_key_pair,
    invalid_plaintext,
) -> None:
    """RSA encryption must require bytes."""
    _, public_key = rsa_key_pair

    with pytest.raises(TypeError, match="plaintext must be bytes"):
        encrypt_for_recipient(invalid_plaintext, public_key)


def test_password_aad_authentication_with_original_key(
    password,
    plaintext,
    monkeypatch,
) -> None:
    """Modified AAD must fail even when the original AES key is retained."""
    import ciphervault.crypto_service as crypto_service

    envelope = encrypt_with_password(plaintext, password)

    header, nonce, ciphertext, tag = crypto_service.serialization.deserialize_envelope(
        envelope
    )

    original_key = crypto_service.kdf.derive_key(
        password,
        crypto_service.serialization.extract_salt(header),
    )

    modified_header = {
        **header,
        "kdf": {
            **header["kdf"],
            "salt": base64.b64encode(b"x" * 16).decode("ascii"),
        },
    }

    modified_aad = crypto_service.serialization.build_aad(modified_header)

    with pytest.raises(InvalidTag):
        crypto_service.aes.decrypt(
            original_key,
            nonce,
            ciphertext,
            tag,
            modified_aad,
        )


@pytest.mark.parametrize(
    "invalid_password",
    [
        "",
        12345,
        None,
    ],
)
def test_password_encryption_rejects_invalid_password(
    plaintext,
    invalid_password,
) -> None:
    """Password encryption must reject invalid passwords."""
    with pytest.raises((TypeError, ValueError)):
        encrypt_with_password(plaintext, invalid_password)


@pytest.mark.parametrize(
    "decrypt_function",
    [
        decrypt_with_password,
        decrypt_with_private_key,
    ],
)
def test_decryption_rejects_invalid_envelope_type(
    decrypt_function,
    password,
    rsa_key_pair,
) -> None:
    """Both decryption workflows must require a bytes envelope."""
    private_key, _ = rsa_key_pair

    with pytest.raises(TypeError, match="serialized envelope must be bytes"):
        if decrypt_function is decrypt_with_password:
            decrypt_function("invalid", password)
        else:
            decrypt_function("invalid", private_key)


def test_rsa_encrypted_key_tampering_rejected(
    rsa_key_pair,
    plaintext,
) -> None:
    """Modification of the RSA-wrapped AES key must prevent decryption."""
    private_key, public_key = rsa_key_pair

    envelope = encrypt_for_recipient(plaintext, public_key)
    parsed = json.loads(envelope)

    encrypted_key = bytearray(
        base64.b64decode(parsed["key_encryption"]["encrypted_key"])
    )

    encrypted_key[0] ^= 1

    parsed["key_encryption"]["encrypted_key"] = base64.b64encode(encrypted_key).decode(
        "ascii"
    )

    tampered_envelope = json.dumps(parsed).encode("utf-8")

    with pytest.raises(ValueError):
        decrypt_with_private_key(tampered_envelope, private_key)
