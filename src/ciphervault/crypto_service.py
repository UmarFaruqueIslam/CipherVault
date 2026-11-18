"""High-level encryption and decryption workflows for CipherVault."""

import secrets

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from ciphervault import aes, kdf, rsa, serialization


def encrypt_with_password(
    plaintext: bytes,
    password: str,
) -> bytes:
    """Encrypt plaintext using a password-derived AES-256 key."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    salt = kdf.generate_salt()
    aes_key = kdf.derive_key(password, salt)

    header = serialization.build_header(
        "password",
        salt=salt,
    )

    aad = serialization.build_aad(header)

    nonce, ciphertext, tag = aes.encrypt(
        aes_key,
        plaintext,
        aad,
    )

    return serialization.serialize_envelope(
        header,
        nonce,
        ciphertext,
        tag,
    )


def decrypt_with_password(
    envelope: bytes,
    password: str,
) -> bytes:
    """Authenticate and decrypt a password-protected envelope."""
    header, nonce, ciphertext, tag = serialization.deserialize_envelope(envelope)

    if header["mode"] != "password":
        raise ValueError("Envelope is not password-protected")

    salt = serialization.extract_salt(header)

    aes_key = kdf.derive_key(password, salt)
    aad = serialization.build_aad(header)

    return aes.decrypt(
        aes_key,
        nonce,
        ciphertext,
        tag,
        aad,
    )


def encrypt_for_recipient(
    plaintext: bytes,
    public_key: RSAPublicKey,
) -> bytes:
    """Encrypt plaintext for an RSA public-key recipient."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    aes_key = secrets.token_bytes(aes.KEY_SIZE)
    encrypted_key = rsa.encrypt_key(public_key, aes_key)

    header = serialization.build_header(
        "rsa",
        encrypted_key=encrypted_key,
    )

    aad = serialization.build_aad(header)

    nonce, ciphertext, tag = aes.encrypt(
        aes_key,
        plaintext,
        aad,
    )

    return serialization.serialize_envelope(
        header,
        nonce,
        ciphertext,
        tag,
    )


def decrypt_with_private_key(
    envelope: bytes,
    private_key: RSAPrivateKey,
) -> bytes:
    """Authenticate and decrypt an RSA-protected envelope."""
    header, nonce, ciphertext, tag = serialization.deserialize_envelope(envelope)

    if header["mode"] != "rsa":
        raise ValueError("Envelope is not RSA-protected")

    encrypted_key = serialization.extract_encrypted_key(header)

    aes_key = rsa.decrypt_key(
        private_key,
        encrypted_key,
    )

    aad = serialization.build_aad(header)

    return aes.decrypt(
        aes_key,
        nonce,
        ciphertext,
        tag,
        aad,
    )
