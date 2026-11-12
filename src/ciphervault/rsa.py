"""RSA-3072 encryption and decryption using OAEP."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE = 32


def generate_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA-3072 private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )

    return private_key, private_key.public_key()


def _validate_public_key(public_key: RSAPublicKey) -> None:
    """Validate an RSA public key."""
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("public_key must be an RSA public key")

    if public_key.key_size < RSA_KEY_SIZE:
        raise ValueError("RSA key must be at least 3072 bits")


def _validate_private_key(private_key: RSAPrivateKey) -> None:
    """Validate an RSA private key."""
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")

    if private_key.key_size < RSA_KEY_SIZE:
        raise ValueError("RSA key must be at least 3072 bits")


def _validate_aes_key(aes_key: bytes) -> None:
    """Validate a 32-byte AES-256 key."""
    if not isinstance(aes_key, bytes):
        raise TypeError("aes_key must be bytes")

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes")


def _oaep_padding() -> padding.OAEP:
    """Create the RSA-OAEP configuration."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_key(
    public_key: RSAPublicKey,
    aes_key: bytes,
) -> bytes:
    """Encrypt an AES-256 key using RSA-OAEP."""
    _validate_public_key(public_key)
    _validate_aes_key(aes_key)

    return public_key.encrypt(
        aes_key,
        _oaep_padding(),
    )


def decrypt_key(
    private_key: RSAPrivateKey,
    encrypted_key: bytes,
) -> bytes:
    """Decrypt an AES-256 key using RSA-OAEP."""
    _validate_private_key(private_key)

    if not isinstance(encrypted_key, bytes):
        raise TypeError("encrypted_key must be bytes")

    expected_length = private_key.key_size // 8

    if len(encrypted_key) != expected_length:
        raise ValueError(f"RSA ciphertext must be exactly {expected_length} bytes")

    aes_key = private_key.decrypt(
        encrypted_key,
        _oaep_padding(),
    )

    _validate_aes_key(aes_key)

    return aes_key
