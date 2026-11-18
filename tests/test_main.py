"""Tests for the CipherVault command-line interface."""

import stat
import sys

import pytest

from ciphervault.main import (
    APP_VERSION,
    _write_new_file,
    build_parser,
    main,
)


def test_parser_accepts_password_encryption():
    parser = build_parser()

    args = parser.parse_args(
        [
            "encrypt",
            "--input",
            "plain.txt",
            "--output",
            "encrypted.cv",
            "--mode",
            "password",
        ]
    )

    assert args.command == "encrypt"
    assert args.mode == "password"


def test_parser_accepts_rsa_encryption():
    parser = build_parser()

    args = parser.parse_args(
        [
            "encrypt",
            "--input",
            "plain.txt",
            "--output",
            "encrypted.cv",
            "--mode",
            "rsa",
            "--public-key",
            "public.pem",
        ]
    )

    assert args.command == "encrypt"
    assert args.public_key == "public.pem"


def test_parser_accepts_decryption():
    parser = build_parser()

    args = parser.parse_args(
        [
            "decrypt",
            "--input",
            "encrypted.cv",
            "--output",
            "decrypted.txt",
        ]
    )

    assert args.command == "decrypt"


def test_parser_accepts_key_generation():
    parser = build_parser()

    args = parser.parse_args(
        [
            "keygen",
            "--private-key",
            "private.pem",
            "--public-key",
            "public.pem",
        ]
    )

    assert args.command == "keygen"


def test_parser_accepts_info():
    parser = build_parser()

    args = parser.parse_args(
        [
            "info",
            "--input",
            "encrypted.cv",
        ]
    )

    assert args.command == "info"


def test_application_version():
    assert APP_VERSION == "0.1.0"


def test_write_new_file_creates_file(tmp_path):
    output = tmp_path / "output.bin"
    content = b"CipherVault test data"

    _write_new_file(output, content)

    assert output.exists()
    assert output.read_bytes() == content


def test_write_new_file_uses_owner_only_permissions(tmp_path):
    output = tmp_path / "private.bin"

    _write_new_file(output, b"secret")

    permissions = stat.S_IMODE(output.stat().st_mode)

    assert permissions == 0o600


def test_write_new_file_does_not_overwrite_existing_file(tmp_path):
    output = tmp_path / "existing.bin"
    output.write_bytes(b"original data")

    with pytest.raises(FileExistsError):
        _write_new_file(output, b"replacement data")

    assert output.read_bytes() == b"original data"
    assert list(tmp_path.iterdir()) == [output]


def test_write_new_file_rejects_missing_parent(tmp_path):
    output = tmp_path / "missing" / "output.bin"

    with pytest.raises(FileNotFoundError):
        _write_new_file(output, b"data")


def test_write_new_file_cleans_up_after_fsync_failure(
    tmp_path,
    monkeypatch,
):
    """A failed file synchronization must not leave temporary files."""
    output = tmp_path / "output.bin"

    def fail_fsync(descriptor):
        raise OSError("Simulated fsync failure")

    monkeypatch.setattr("ciphervault.main.os.fsync", fail_fsync)

    with pytest.raises(OSError, match="Simulated fsync failure"):
        _write_new_file(output, b"test data")

    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_password_cli_encrypt_decrypt(tmp_path, monkeypatch):
    """Test complete password encryption and decryption through CLI."""
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.cv"
    recovered = tmp_path / "recovered.txt"

    source.write_bytes(b"CipherVault CLI integration test.")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: "Strong-Test-Passphrase-2026!",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(encrypted),
            "--mode",
            "password",
        ],
    )

    assert main() == 0
    assert encrypted.exists()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(encrypted),
            "--output",
            str(recovered),
        ],
    )

    assert main() == 0
    assert recovered.read_bytes() == source.read_bytes()


def test_rsa_cli_keygen_encrypt_decrypt(tmp_path, monkeypatch):
    """Test RSA key generation and complete CLI encryption workflow."""
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.cv"
    recovered = tmp_path / "recovered.txt"

    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    source.write_bytes(b"RSA CipherVault CLI integration test.")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: "Strong-Test-Passphrase-2026!",
    )

    # Generate RSA key pair.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "keygen",
            "--private-key",
            str(private_key),
            "--public-key",
            str(public_key),
        ],
    )

    assert main() == 0
    assert private_key.exists()
    assert public_key.exists()

    # Encrypt for recipient.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(encrypted),
            "--mode",
            "rsa",
            "--public-key",
            str(public_key),
        ],
    )

    assert main() == 0
    assert encrypted.exists()

    # Decrypt using private key.
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(encrypted),
            "--output",
            str(recovered),
            "--private-key",
            str(private_key),
        ],
    )

    assert main() == 0
    assert recovered.read_bytes() == source.read_bytes()


def test_cli_info_command(tmp_path, monkeypatch, capsys):
    """Test metadata inspection through the CLI."""
    from ciphervault.crypto_service import encrypt_with_password

    source = tmp_path / "message.cv"
    source.write_bytes(
        encrypt_with_password(
            b"CipherVault information test.",
            "Strong-Test-Passphrase-2026!",
        )
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "info",
            "--input",
            str(source),
        ],
    )

    assert main() == 0

    output = capsys.readouterr().out

    assert "CipherVault" in output
    assert "AES-256-GCM" in output
    assert "Metadata has not been authenticated" in output


def test_password_decryption_rejects_private_key_argument(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    """Password-mode decryption must reject an RSA private-key argument."""
    import sys

    from ciphervault.crypto_service import encrypt_with_password
    from ciphervault.main import main

    password = "CipherVault-Test-Passphrase-2026!"

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: password,
    )

    envelope = encrypt_with_password(b"Test plaintext", password)

    input_path = tmp_path / "encrypted.cipher"
    output_path = tmp_path / "recovered.txt"
    private_key_path = tmp_path / "private.pem"

    input_path.write_bytes(envelope)
    private_key_path.write_text("unused")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--private-key",
            str(private_key_path),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "only valid for RSA mode" in captured.err
    assert not output_path.exists()


def test_keygen_preserves_private_key_when_public_key_save_fails(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    """A public-key save failure must not delete the private key."""
    import sys

    from ciphervault import main as main_module

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: "CipherVault-Test-Passphrase-2026!",
    )

    def fail_public_key_save(*args, **kwargs):
        raise OSError("Simulated public-key storage failure")

    monkeypatch.setattr(
        main_module,
        "save_public_key",
        fail_public_key_save,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "keygen",
            "--private-key",
            str(private_path),
            "--public-key",
            str(public_path),
        ],
    )

    result = main_module.main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Simulated public-key storage failure" in captured.err
    assert private_path.exists()
    assert not public_path.exists()
    assert "key-pair generation incomplete" in captured.err
    assert str(private_path) in captured.err
    assert str(public_path) in captured.err


def test_encrypt_cli_rejects_oversized_plaintext(
    tmp_path,
    monkeypatch,
    capsys,
):
    """The CLI must reject plaintext exceeding its configured size limit."""
    import sys

    from ciphervault import main as main_module

    source = tmp_path / "large.txt"
    output = tmp_path / "encrypted.cv"

    source.write_bytes(b"12345")

    monkeypatch.setattr(
        main_module,
        "MAX_PLAINTEXT_SIZE",
        4,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(output),
            "--mode",
            "password",
        ],
    )

    result = main_module.main()

    captured = capsys.readouterr()

    assert result == 1
    assert "maximum allowed size" in captured.err
    assert not output.exists()


def test_decrypt_cli_rejects_oversized_envelope(
    tmp_path,
    monkeypatch,
    capsys,
):
    """The CLI must reject envelopes exceeding the configured size limit."""
    import sys

    from ciphervault import main as main_module

    source = tmp_path / "large.cv"
    output = tmp_path / "decrypted.txt"

    source.write_bytes(b"12345")

    monkeypatch.setattr(
        main_module.serialization,
        "MAX_ENVELOPE_SIZE",
        4,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(source),
            "--output",
            str(output),
        ],
    )

    result = main_module.main()

    captured = capsys.readouterr()

    assert result == 1
    assert "maximum allowed size" in captured.err
    assert not output.exists()


def test_encrypt_cli_does_not_overwrite_existing_output(
    tmp_path,
    monkeypatch,
    capsys,
):
    """CLI encryption must preserve an existing output file."""
    import sys

    source = tmp_path / "message.txt"
    output = tmp_path / "encrypted.cv"

    source.write_bytes(b"New plaintext")
    output.write_bytes(b"Original protected content")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: "Strong-Test-Passphrase-2026!",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(output),
            "--mode",
            "password",
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "File exists" in captured.err
    assert output.read_bytes() == b"Original protected content"


def test_decrypt_cli_does_not_overwrite_existing_output(
    tmp_path,
    monkeypatch,
    capsys,
):
    """CLI decryption must preserve an existing output file."""
    import sys

    from ciphervault.crypto_service import encrypt_with_password

    password = "Strong-Test-Passphrase-2026!"

    source = tmp_path / "encrypted.cv"
    output = tmp_path / "recovered.txt"

    source.write_bytes(encrypt_with_password(b"New plaintext", password))
    output.write_bytes(b"Original protected content")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: password,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(source),
            "--output",
            str(output),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "File exists" in captured.err
    assert output.read_bytes() == b"Original protected content"


def test_decrypt_cli_rejects_wrong_password(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Wrong passwords must fail authentication without creating output."""
    import sys

    from ciphervault.crypto_service import encrypt_with_password

    source = tmp_path / "encrypted.cv"
    output = tmp_path / "recovered.txt"

    envelope = encrypt_with_password(
        b"Confidential CipherVault data",
        "Correct-Test-Passphrase-2026!",
    )
    source.write_bytes(envelope)

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: "Wrong-Test-Passphrase-2026!",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(source),
            "--output",
            str(output),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Authentication failed" in captured.err
    assert not output.exists()


def test_rsa_decryption_requires_private_key(
    tmp_path,
    monkeypatch,
    capsys,
):
    """RSA-mode decryption must reject a missing private-key argument."""
    import sys

    from ciphervault.crypto_service import encrypt_for_recipient
    from ciphervault.rsa import generate_key_pair

    _, public_key = generate_key_pair()

    envelope = encrypt_for_recipient(
        b"Confidential RSA test data",
        public_key,
    )

    input_path = tmp_path / "encrypted.cv"
    output_path = tmp_path / "recovered.txt"

    input_path.write_bytes(envelope)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "RSA decryption requires --private-key" in captured.err
    assert not output_path.exists()


def test_keygen_rejects_identical_key_paths(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Key generation must reject identical private and public paths."""
    import sys

    from ciphervault.main import main

    key_path = tmp_path / "same-key.pem"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "keygen",
            "--private-key",
            str(key_path),
            "--public-key",
            str(key_path),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Private and public key paths must be different" in captured.err
    assert not key_path.exists()


def test_keygen_does_not_overwrite_existing_key_files(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Key generation must preserve existing private and public key files."""
    import sys

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    original_private = b"Existing private key content"
    original_public = b"Existing public key content"

    private_path.write_bytes(original_private)
    public_path.write_bytes(original_public)

    def unexpected_password_prompt(_):
        pytest.fail("Passphrase prompt should not occur")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        unexpected_password_prompt,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "keygen",
            "--private-key",
            str(private_path),
            "--public-key",
            str(public_path),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "A key output file already exists" in captured.err
    assert private_path.read_bytes() == original_private
    assert public_path.read_bytes() == original_public


def test_encrypt_cli_handles_missing_input_file(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Missing input files must produce a controlled CLI error."""
    import sys

    source = tmp_path / "missing.txt"
    output = tmp_path / "encrypted.cv"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(output),
            "--mode",
            "password",
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "No such file or directory" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()


def test_rsa_encryption_requires_public_key(
    tmp_path,
    monkeypatch,
    capsys,
):
    """RSA encryption must reject a missing public-key argument."""
    import sys

    source = tmp_path / "message.txt"
    output = tmp_path / "encrypted.cv"

    source.write_bytes(b"CipherVault test data")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(output),
            "--mode",
            "rsa",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "RSA encryption requires --public-key" in captured.err
    assert not output.exists()


def test_password_encryption_rejects_public_key_argument(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Password encryption must reject an RSA public-key argument."""
    import sys

    source = tmp_path / "message.txt"
    output = tmp_path / "encrypted.cv"

    source.write_bytes(b"CipherVault test data")

    monkeypatch.setattr(
        "ciphervault.main.getpass.getpass",
        lambda _: pytest.fail("Passphrase prompt should not occur"),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "encrypt",
            "--input",
            str(source),
            "--output",
            str(output),
            "--mode",
            "password",
            "--public-key",
            "public.pem",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "--public-key is only valid with RSA mode" in captured.err
    assert not output.exists()


def test_decrypt_cli_rejects_malformed_envelope(
    tmp_path,
    monkeypatch,
    capsys,
):
    """Malformed encrypted files must produce a controlled CLI error."""
    import sys

    source = tmp_path / "malformed.cv"
    output = tmp_path / "recovered.txt"

    source.write_bytes(b"This is not a valid CipherVault envelope")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ciphervault",
            "decrypt",
            "--input",
            str(source),
            "--output",
            str(output),
        ],
    )

    result = main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Error:" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()
