"""Tests for AES-256-GCM authenticated encryption."""

import pytest
from cryptography.exceptions import InvalidTag

from ciphervault.aes import decrypt, encrypt


@pytest.fixture
def key() -> bytes:
    """Provide a deterministic 32-byte test key."""
    return bytes(range(32))


@pytest.fixture
def plaintext() -> bytes:
    """Provide sample plaintext."""
    return b"CipherVault AES-256-GCM test message"


@pytest.fixture
def aad() -> bytes:
    """Provide sample additional authenticated data."""
    return b"CipherVault:v1:AES-256-GCM"


def test_encrypt_returns_expected_components(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
) -> None:
    """Encryption should return a 12-byte nonce, ciphertext and 16-byte tag."""
    nonce, ciphertext, tag = encrypt(key, plaintext, aad)

    assert isinstance(nonce, bytes)
    assert isinstance(ciphertext, bytes)
    assert isinstance(tag, bytes)

    assert len(nonce) == 12
    assert len(tag) == 16
    assert len(ciphertext) == len(plaintext)


def test_encrypt_decrypt_round_trip(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
) -> None:
    """Decryption should recover the original plaintext."""
    nonce, ciphertext, tag = encrypt(key, plaintext, aad)

    recovered = decrypt(key, nonce, ciphertext, tag, aad)

    assert recovered == plaintext


def test_encrypt_decrypt_without_aad(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Encryption and decryption should work without AAD."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    recovered = decrypt(key, nonce, ciphertext, tag)

    assert recovered == plaintext


def test_empty_plaintext(key: bytes) -> None:
    """Empty plaintext should encrypt and decrypt successfully."""
    plaintext = b""

    nonce, ciphertext, tag = encrypt(key, plaintext)

    recovered = decrypt(key, nonce, ciphertext, tag)

    assert ciphertext == b""
    assert len(tag) == 16
    assert recovered == plaintext


def test_empty_aad(key: bytes, plaintext: bytes) -> None:
    """Empty AAD should work as valid additional authenticated data."""
    nonce, ciphertext, tag = encrypt(key, plaintext, b"")

    recovered = decrypt(key, nonce, ciphertext, tag, b"")

    assert recovered == plaintext


def test_empty_plaintext_modified_tag_fails_authentication(
    key: bytes,
) -> None:
    """An altered tag must fail even when plaintext is empty."""
    nonce, ciphertext, tag = encrypt(key, b"")

    modified_tag = bytes([tag[0] ^ 1]) + tag[1:]

    with pytest.raises(InvalidTag):
        decrypt(key, nonce, ciphertext, modified_tag)


def test_unicode_plaintext(key: bytes) -> None:
    """Unicode text should survive encryption and decryption."""
    plaintext = "CipherVault — safe encryption".encode()

    nonce, ciphertext, tag = encrypt(key, plaintext)

    recovered = decrypt(key, nonce, ciphertext, tag)

    assert recovered == plaintext


def test_repeated_encryption_generates_different_nonces(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Separate encryptions should generate fresh random nonces."""
    nonce_one, _, _ = encrypt(key, plaintext)
    nonce_two, _, _ = encrypt(key, plaintext)

    assert nonce_one != nonce_two


def test_wrong_key_fails_authentication(
    key: bytes,
    plaintext: bytes,
) -> None:
    """A different key should not authenticate the encrypted data."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    wrong_key = bytes(reversed(key))

    with pytest.raises(InvalidTag):
        decrypt(wrong_key, nonce, ciphertext, tag)


def test_modified_ciphertext_fails_authentication(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Modified ciphertext should fail authentication."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    modified_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(InvalidTag):
        decrypt(key, nonce, modified_ciphertext, tag)


def test_modified_tag_fails_authentication(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Modified authentication tag should fail verification."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    modified_tag = bytes([tag[0] ^ 1]) + tag[1:]

    with pytest.raises(InvalidTag):
        decrypt(key, nonce, ciphertext, modified_tag)


def test_modified_aad_fails_authentication(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
) -> None:
    """Modified AAD should fail authentication."""
    nonce, ciphertext, tag = encrypt(key, plaintext, aad)

    modified_aad = aad + b"-modified"

    with pytest.raises(InvalidTag):
        decrypt(key, nonce, ciphertext, tag, modified_aad)


def test_modified_nonce_fails_authentication(
    key: bytes,
    plaintext: bytes,
) -> None:
    """A modified nonce should fail authentication."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    modified_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]

    with pytest.raises(InvalidTag):
        decrypt(key, modified_nonce, ciphertext, tag)


def test_invalid_key_length_rejected() -> None:
    """Keys other than 32 bytes should be rejected."""
    invalid_key = b"short"

    with pytest.raises(ValueError, match="32 bytes"):
        encrypt(invalid_key, b"test")


def test_invalid_nonce_length_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Nonces other than 12 bytes should be rejected."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    invalid_nonce = nonce[:-1]

    with pytest.raises(ValueError, match="12 bytes"):
        decrypt(key, invalid_nonce, ciphertext, tag)


def test_invalid_tag_length_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Tags other than 16 bytes should be rejected."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    invalid_tag = tag[:-1]

    with pytest.raises(ValueError, match="16 bytes"):
        decrypt(key, nonce, ciphertext, invalid_tag)


@pytest.mark.parametrize(
    ("invalid_key", "plaintext"),
    [
        ("not-bytes", b"message"),
        (None, b"message"),
        (123, b"message"),
    ],
)
def test_invalid_key_type_rejected(
    invalid_key: object,
    plaintext: bytes,
) -> None:
    """Non-byte keys should be rejected."""
    with pytest.raises(TypeError, match="key must be bytes"):
        encrypt(invalid_key, plaintext)  # type: ignore[arg-type]


def test_invalid_plaintext_type_rejected(key: bytes) -> None:
    """Non-byte plaintext should be rejected."""
    with pytest.raises(TypeError, match="plaintext must be bytes"):
        encrypt(key, "not bytes")  # type: ignore[arg-type]


def test_invalid_aad_type_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """AAD must be bytes or None."""
    with pytest.raises(TypeError, match="aad must be bytes"):
        encrypt(key, plaintext, "not bytes")  # type: ignore[arg-type]


def test_invalid_ciphertext_type_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Non-byte ciphertext should be rejected."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    with pytest.raises(TypeError, match="ciphertext must be bytes"):
        decrypt(
            key,
            nonce,
            "not bytes",  # type: ignore[arg-type]
            tag,
        )


def test_invalid_tag_type_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Non-byte authentication tags should be rejected."""
    nonce, ciphertext, _ = encrypt(key, plaintext)

    with pytest.raises(TypeError, match="tag must be bytes"):
        decrypt(
            key,
            nonce,
            ciphertext,
            "not bytes",  # type: ignore[arg-type]
        )


def test_invalid_nonce_type_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Non-byte nonces should be rejected."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    with pytest.raises(TypeError, match="nonce must be bytes"):
        decrypt(
            key,
            "not bytes",  # type: ignore[arg-type]
            ciphertext,
            tag,
        )


def test_invalid_decryption_aad_type_rejected(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Non-byte AAD should be rejected during decryption."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    with pytest.raises(TypeError, match="aad must be bytes"):
        decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            "not bytes",  # type: ignore[arg-type]
        )


def test_invalid_key_length_rejected_during_decryption(
    key: bytes,
    plaintext: bytes,
) -> None:
    """Decryption must reject AES keys that are not 32 bytes."""
    nonce, ciphertext, tag = encrypt(key, plaintext)

    with pytest.raises(ValueError, match="32 bytes"):
        decrypt(b"short", nonce, ciphertext, tag)


def test_invalid_aad_type_rejected_during_decryption(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
) -> None:
    """Decryption must reject AAD values that are not bytes or None."""
    nonce, ciphertext, tag = encrypt(key, plaintext, aad)

    with pytest.raises(TypeError, match="aad must be bytes"):
        decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            "invalid AAD",  # type: ignore[arg-type]
        )
