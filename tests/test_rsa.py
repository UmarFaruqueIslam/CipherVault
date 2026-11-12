"""Tests for RSA-3072 OAEP encryption and decryption."""

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from ciphervault.rsa import (
    AES_KEY_SIZE,
    RSA_KEY_SIZE,
    decrypt_key,
    encrypt_key,
    generate_key_pair,
)


@pytest.fixture(scope="module")
def key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a reusable RSA key pair for the test module."""
    return generate_key_pair()


@pytest.fixture
def aes_key() -> bytes:
    """Provide a deterministic 32-byte AES test key."""
    return bytes(range(AES_KEY_SIZE))


def test_generate_rsa_key_pair(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
) -> None:
    """Generated keys should have the configured RSA key size."""
    private_key, public_key = key_pair

    assert isinstance(private_key, RSAPrivateKey)
    assert isinstance(public_key, RSAPublicKey)

    assert private_key.key_size == RSA_KEY_SIZE
    assert public_key.key_size == RSA_KEY_SIZE

    assert private_key.public_key().public_numbers() == (public_key.public_numbers())


def test_encrypt_key_returns_expected_length(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    aes_key: bytes,
) -> None:
    """RSA-3072 ciphertext should contain 384 bytes."""
    _, public_key = key_pair

    encrypted_key = encrypt_key(public_key, aes_key)

    assert isinstance(encrypted_key, bytes)
    assert len(encrypted_key) == RSA_KEY_SIZE // 8


def test_rsa_encrypt_decrypt_round_trip(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    aes_key: bytes,
) -> None:
    """The recipient should recover the original AES key."""
    private_key, public_key = key_pair

    encrypted_key = encrypt_key(public_key, aes_key)
    recovered_key = decrypt_key(private_key, encrypted_key)

    assert recovered_key == aes_key


def test_oaep_uses_randomized_encryption(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    aes_key: bytes,
) -> None:
    """Encrypting the same key twice should produce different ciphertext."""
    _, public_key = key_pair

    encrypted_one = encrypt_key(public_key, aes_key)
    encrypted_two = encrypt_key(public_key, aes_key)

    assert encrypted_one != encrypted_two


def test_wrong_private_key_fails_decryption(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    aes_key: bytes,
) -> None:
    """A different private key should not decrypt the encrypted AES key."""
    _, public_key = key_pair
    wrong_private_key, _ = generate_key_pair()

    encrypted_key = encrypt_key(public_key, aes_key)

    with pytest.raises(ValueError):
        decrypt_key(wrong_private_key, encrypted_key)


def test_modified_ciphertext_fails_decryption(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    aes_key: bytes,
) -> None:
    """Modified RSA ciphertext should fail OAEP decryption."""
    private_key, public_key = key_pair

    encrypted_key = encrypt_key(public_key, aes_key)

    modified_ciphertext = bytes([encrypted_key[0] ^ 1]) + encrypted_key[1:]

    with pytest.raises(ValueError):
        decrypt_key(private_key, modified_ciphertext)


def test_invalid_aes_key_length_rejected(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
) -> None:
    """RSA encryption should reject AES keys of the wrong length."""
    _, public_key = key_pair

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        encrypt_key(public_key, b"short")


def test_invalid_aes_key_type_rejected(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
) -> None:
    """Reject an AES key that is not bytes."""
    _, valid_public_key = key_pair

    invalid_aes_key = "invalid"

    with pytest.raises(TypeError, match="aes_key must be bytes"):
        encrypt_key(
            valid_public_key,
            invalid_aes_key,  # type: ignore[arg-type]
        )


def test_invalid_public_key_type_rejected(aes_key: bytes) -> None:
    """Reject a public key that is not an RSA public key."""
    invalid_public_key = "invalid"

    with pytest.raises(TypeError, match="RSA public key"):
        encrypt_key(
            invalid_public_key,  # type: ignore[arg-type]
            aes_key,
        )


def test_invalid_private_key_type_rejected() -> None:
    """Reject a private key that is not an RSA private key."""
    invalid_private_key = "invalid"
    valid_length_ciphertext = bytes(RSA_KEY_SIZE // 8)

    with pytest.raises(TypeError, match="RSA private key"):
        decrypt_key(
            invalid_private_key,  # type: ignore[arg-type]
            valid_length_ciphertext,
        )


def test_invalid_ciphertext_type_rejected(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
) -> None:
    """RSA decryption should reject non-byte ciphertext."""
    private_key, _ = key_pair

    with pytest.raises(TypeError, match="encrypted_key must be bytes"):
        decrypt_key(
            private_key,
            "invalid",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_ciphertext",
    [
        b"",
        b"short",
        bytes((RSA_KEY_SIZE // 8) - 1),
        bytes((RSA_KEY_SIZE // 8) + 1),
    ],
)
def test_invalid_ciphertext_length_rejected(
    key_pair: tuple[RSAPrivateKey, RSAPublicKey],
    invalid_ciphertext: bytes,
) -> None:
    """RSA ciphertext must have the expected modulus length."""
    private_key, _ = key_pair

    expected_length = private_key.key_size // 8

    with pytest.raises(
        ValueError,
        match=f"exactly {expected_length} bytes",
    ):
        decrypt_key(private_key, invalid_ciphertext)
