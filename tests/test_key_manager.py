"""Tests for secure RSA key storage and recovery."""

import stat

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from ciphervault.key_manager import (
    MAX_KEY_FILE_BYTES,
    MAX_PASSPHRASE_BYTES,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from ciphervault.rsa import generate_key_pair


@pytest.fixture(scope="module")
def key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a reusable RSA key pair."""
    return generate_key_pair()


@pytest.fixture
def passphrase() -> str:
    """Provide a test passphrase."""
    return "CipherVault-Test-Passphrase-2026!"


def test_save_private_key_creates_file(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """Saving a private key should create a PEM file."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    save_private_key(private_key, key_path, passphrase)

    assert key_path.exists()
    assert key_path.is_file()
    assert key_path.stat().st_size > 0


def test_private_key_is_encrypted(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """Saved private keys should use encrypted PEM serialization."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    save_private_key(private_key, key_path, passphrase)

    pem_data = key_path.read_bytes()

    assert b"BEGIN ENCRYPTED PRIVATE KEY" in pem_data
    assert b"BEGIN PRIVATE KEY" not in pem_data


def test_private_key_round_trip(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """The original private key should be recoverable."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    save_private_key(private_key, key_path, passphrase)

    loaded_key = load_private_key(key_path, passphrase)

    assert isinstance(loaded_key, RSAPrivateKey)
    assert loaded_key.private_numbers() == private_key.private_numbers()


def test_wrong_passphrase_rejected(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """An incorrect passphrase must not load the private key."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    save_private_key(private_key, key_path, passphrase)

    with pytest.raises((ValueError, TypeError, UnsupportedAlgorithm)):
        load_private_key(key_path, "incorrect-passphrase")


def test_private_key_file_permissions(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """Private-key files should have owner-only permissions."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    save_private_key(private_key, key_path, passphrase)

    permissions = stat.S_IMODE(key_path.stat().st_mode)

    assert permissions == 0o600


def test_save_public_key_creates_file(
    tmp_path,
    key_pair,
) -> None:
    """Saving a public key should create a PEM file."""
    _, public_key = key_pair
    key_path = tmp_path / "public_key.pem"

    save_public_key(public_key, key_path)

    assert key_path.exists()
    assert key_path.is_file()
    assert key_path.stat().st_size > 0


def test_public_key_round_trip(
    tmp_path,
    key_pair,
) -> None:
    """The original public key should be recoverable."""
    _, public_key = key_pair
    key_path = tmp_path / "public_key.pem"

    save_public_key(public_key, key_path)

    loaded_key = load_public_key(key_path)

    assert isinstance(loaded_key, RSAPublicKey)
    assert loaded_key.public_numbers() == public_key.public_numbers()


def test_public_key_file_permissions(
    tmp_path,
    key_pair,
) -> None:
    """Public-key files should have read permissions for other users."""
    _, public_key = key_pair
    key_path = tmp_path / "public_key.pem"

    save_public_key(public_key, key_path)

    permissions = stat.S_IMODE(key_path.stat().st_mode)

    assert permissions == 0o644


@pytest.mark.parametrize(
    "invalid_passphrase",
    [
        "",
        "x" * (MAX_PASSPHRASE_BYTES + 1),
    ],
)
def test_invalid_passphrase_rejected(
    tmp_path,
    key_pair,
    invalid_passphrase,
) -> None:
    """Empty and oversized passphrases should be rejected."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    with pytest.raises(ValueError):
        save_private_key(private_key, key_path, invalid_passphrase)


def test_invalid_passphrase_type_rejected(
    tmp_path,
    key_pair,
) -> None:
    """Passphrases must be strings."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    with pytest.raises(TypeError, match="passphrase must be a string"):
        save_private_key(
            private_key,
            key_path,
            12345,  # type: ignore[arg-type]
        )


def test_invalid_private_key_type_rejected(
    tmp_path,
    passphrase,
) -> None:
    """Private-key saving must reject non-RSA private keys."""
    key_path = tmp_path / "private_key.pem"

    with pytest.raises(TypeError, match="RSA private key"):
        save_private_key(
            "invalid",  # type: ignore[arg-type]
            key_path,
            passphrase,
        )


def test_invalid_public_key_type_rejected(tmp_path) -> None:
    """Public-key saving must reject non-RSA public keys."""
    key_path = tmp_path / "public_key.pem"

    with pytest.raises(TypeError, match="RSA public key"):
        save_public_key(
            "invalid",  # type: ignore[arg-type]
            key_path,
        )


def test_corrupted_private_key_rejected(
    tmp_path,
    passphrase,
) -> None:
    """Corrupted private-key files should not be loaded."""
    key_path = tmp_path / "corrupted.pem"
    key_path.write_bytes(b"invalid PEM content")

    with pytest.raises(ValueError):
        load_private_key(key_path, passphrase)


def test_corrupted_public_key_rejected(tmp_path) -> None:
    """Corrupted public-key files should not be loaded."""
    key_path = tmp_path / "corrupted_public.pem"
    key_path.write_bytes(b"invalid PEM content")

    with pytest.raises(ValueError):
        load_public_key(key_path)


def test_missing_private_key_file_rejected(
    tmp_path,
    passphrase,
) -> None:
    """Loading a missing private-key file should fail."""
    key_path = tmp_path / "missing.pem"

    with pytest.raises(FileNotFoundError):
        load_private_key(key_path, passphrase)


def test_missing_public_key_file_rejected(tmp_path) -> None:
    """Loading a missing public-key file should fail."""
    key_path = tmp_path / "missing.pem"

    with pytest.raises(FileNotFoundError):
        load_public_key(key_path)


def test_oversized_key_file_rejected(tmp_path) -> None:
    """Key files exceeding the size limit should be rejected."""
    key_path = tmp_path / "oversized.pem"
    key_path.write_bytes(b"A" * (MAX_KEY_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="maximum allowed size"):
        load_public_key(key_path)


def test_save_private_key_does_not_overwrite_existing_file(
    tmp_path,
    key_pair,
    passphrase,
) -> None:
    """Saving a private key must not overwrite an existing file."""
    private_key, _ = key_pair
    key_path = tmp_path / "private_key.pem"

    original_content = b"DO NOT OVERWRITE THIS FILE"
    key_path.write_bytes(original_content)

    with pytest.raises(FileExistsError):
        save_private_key(private_key, key_path, passphrase)

    assert key_path.read_bytes() == original_content


def test_save_public_key_does_not_overwrite_existing_file(
    tmp_path,
    key_pair,
) -> None:
    """Saving a public key must not overwrite an existing file."""
    _, public_key = key_pair
    key_path = tmp_path / "public_key.pem"

    original_content = b"DO NOT OVERWRITE THIS FILE"
    key_path.write_bytes(original_content)

    with pytest.raises(FileExistsError):
        save_public_key(public_key, key_path)

    assert key_path.read_bytes() == original_content


def test_oversized_private_key_file_rejected(
    tmp_path,
    passphrase,
) -> None:
    """Private-key files exceeding the size limit must be rejected."""
    key_path = tmp_path / "oversized_private.pem"
    key_path.write_bytes(b"A" * (MAX_KEY_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="maximum allowed size"):
        load_private_key(key_path, passphrase)


def test_atomic_write_cleans_up_after_fsync_failure(
    tmp_path,
    key_pair,
    monkeypatch,
) -> None:
    """Temporary files must be removed when fsync fails."""
    _, public_key = key_pair

    def fail_fsync(descriptor):
        raise OSError("Simulated fsync failure")

    monkeypatch.setattr(
        "ciphervault.key_manager.os.fsync",
        fail_fsync,
    )

    with pytest.raises(OSError, match="Simulated fsync failure"):
        save_public_key(public_key, tmp_path / "public.pem")

    assert list(tmp_path.iterdir()) == []


def test_atomic_write_cleans_up_after_link_failure(
    tmp_path,
    key_pair,
    monkeypatch,
) -> None:
    """Temporary files must be removed when publication fails."""
    _, public_key = key_pair

    def fail_link(source, destination):
        raise OSError("Simulated publication failure")

    monkeypatch.setattr(
        "ciphervault.key_manager.os.link",
        fail_link,
    )

    with pytest.raises(OSError, match="Simulated publication failure"):
        save_public_key(public_key, tmp_path / "public.pem")

    assert list(tmp_path.iterdir()) == []


def test_save_key_rejects_missing_parent_directory(
    tmp_path,
    key_pair,
) -> None:
    """Key storage must fail if the destination directory is missing."""
    _, public_key = key_pair
    key_path = tmp_path / "missing" / "public.pem"

    with pytest.raises(FileNotFoundError, match="Parent directory"):
        save_public_key(public_key, key_path)


def test_load_undersized_public_key_rejected(tmp_path) -> None:
    """Loading an RSA public key smaller than 3072 bits must fail."""
    small_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_pem = small_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_path = tmp_path / "small_public.pem"
    key_path.write_bytes(public_pem)

    with pytest.raises(ValueError, match="at least 3072 bits"):
        load_public_key(key_path)


def test_load_undersized_private_key_rejected(
    tmp_path,
    passphrase,
) -> None:
    """Loading an RSA private key smaller than 3072 bits must fail."""
    small_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    encrypted_pem = small_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )

    key_path = tmp_path / "small_private.pem"
    key_path.write_bytes(encrypted_pem)

    with pytest.raises(ValueError, match="at least 3072 bits"):
        load_private_key(key_path, passphrase)
