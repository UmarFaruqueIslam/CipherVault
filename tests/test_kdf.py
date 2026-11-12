"""Tests for Scrypt-based password key derivation."""

import pytest

from ciphervault.kdf import (
    KEY_LENGTH,
    MAX_PASSWORD_BYTES,
    SALT_LENGTH,
    derive_key,
    generate_salt,
)


@pytest.fixture
def password() -> str:
    """Provide a sample password."""
    return "CipherVault-Test-Password-2026!"


@pytest.fixture
def salt() -> bytes:
    """Provide a deterministic test salt."""
    return bytes(range(SALT_LENGTH))


def test_generate_salt_length() -> None:
    """Generated salts should have the configured length."""
    salt = generate_salt()

    assert isinstance(salt, bytes)
    assert len(salt) == SALT_LENGTH


def test_generate_salt_returns_different_values() -> None:
    """Separate calls should generate different salts."""
    salt_one = generate_salt()
    salt_two = generate_salt()

    assert salt_one != salt_two


def test_derive_key_returns_expected_length(
    password: str,
    salt: bytes,
) -> None:
    """Scrypt should produce a 32-byte key."""
    key = derive_key(password, salt)

    assert isinstance(key, bytes)
    assert len(key) == KEY_LENGTH


def test_same_password_and_salt_produce_same_key(
    password: str,
    salt: bytes,
) -> None:
    """Identical inputs should produce identical derived keys."""
    key_one = derive_key(password, salt)
    key_two = derive_key(password, salt)

    assert key_one == key_two


def test_different_salts_produce_different_keys(
    password: str,
    salt: bytes,
) -> None:
    """Different salts should produce different derived keys."""
    another_salt = bytes(reversed(salt))

    key_one = derive_key(password, salt)
    key_two = derive_key(password, another_salt)

    assert key_one != key_two


def test_different_passwords_produce_different_keys(
    password: str,
    salt: bytes,
) -> None:
    """Different passwords should produce different derived keys."""
    key_one = derive_key(password, salt)
    key_two = derive_key(password + "-different", salt)

    assert key_one != key_two


def test_unicode_password(
    salt: bytes,
) -> None:
    """Unicode passwords should be accepted."""
    password = "CipherVault-নিরাপদ-🔐"

    key = derive_key(password, salt)

    assert isinstance(key, bytes)
    assert len(key) == KEY_LENGTH


def test_empty_password_rejected(salt: bytes) -> None:
    """Empty passwords should be rejected."""
    with pytest.raises(ValueError, match="must not be empty"):
        derive_key("", salt)


@pytest.mark.parametrize(
    "invalid_password",
    [None, 123, b"password"],
)
def test_invalid_password_type_rejected(
    invalid_password: object,
    salt: bytes,
) -> None:
    """Passwords must be strings."""
    with pytest.raises(TypeError, match="password must be a string"):
        derive_key(invalid_password, salt)  # type: ignore[arg-type]


def test_password_exceeding_size_limit_rejected(salt: bytes) -> None:
    """Passwords exceeding the configured byte limit should be rejected."""
    password = "a" * (MAX_PASSWORD_BYTES + 1)

    with pytest.raises(ValueError, match="must not exceed"):
        derive_key(password, salt)


def test_invalid_unicode_password_rejected(salt: bytes) -> None:
    """Invalid Unicode surrogate values should be rejected."""
    password = "\ud800"

    with pytest.raises(ValueError, match="valid UTF-8"):
        derive_key(password, salt)


def test_invalid_salt_type_rejected(password: str) -> None:
    """Salt must be bytes."""
    with pytest.raises(TypeError, match="salt must be bytes"):
        derive_key(password, "invalid-salt")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_salt",
    [
        b"",
        b"short",
        bytes(SALT_LENGTH + 1),
    ],
)
def test_invalid_salt_length_rejected(
    password: str,
    invalid_salt: bytes,
) -> None:
    """Salt must contain exactly 16 bytes."""
    with pytest.raises(ValueError, match="exactly 16 bytes"):
        derive_key(password, invalid_salt)
