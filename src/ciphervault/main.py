"""Command-line interface for CipherVault."""

import argparse
import getpass
import os
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm

from ciphervault import serialization
from ciphervault.crypto_service import (
    decrypt_with_password,
    decrypt_with_private_key,
    encrypt_for_recipient,
    encrypt_with_password,
)
from ciphervault.key_manager import (
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from ciphervault.rsa import generate_key_pair

APP_VERSION = "0.1.0"

# Keep plaintext files small enough for the version 1 JSON envelope.
MAX_PLAINTEXT_SIZE = 11 * 1024 * 1024

# Decrypted files and encrypted output files are private by default.
OUTPUT_FILE_MODE = 0o600


def _read_file(file_path: Path, maximum_size: int) -> bytes:
    """Read a file with a maximum size limit."""
    with file_path.open("rb") as file:
        data = file.read(maximum_size + 1)

    if len(data) > maximum_size:
        raise ValueError("Input file exceeds the maximum allowed size")

    return data


def _write_new_file(file_path: Path, data: bytes) -> None:
    """Atomically create a new file without overwriting an existing file."""
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{file_path.name}.",
        suffix=".tmp",
        dir=file_path.parent,
    )

    try:
        os.fchmod(descriptor, OUTPUT_FILE_MODE)

        with os.fdopen(descriptor, "wb") as file:
            descriptor = -1
            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.link(temporary_path, file_path)

    finally:
        if descriptor != -1:
            os.close(descriptor)

        os.unlink(temporary_path)


def _confirm_passphrase() -> str:
    """Prompt for a new passphrase and confirm it."""
    passphrase = getpass.getpass("Enter passphrase: ")
    confirmation = getpass.getpass("Confirm passphrase: ")

    if passphrase != confirmation:
        raise ValueError("Passphrases do not match")

    return passphrase


def _encrypt_command(args: argparse.Namespace) -> None:
    """Execute the encryption command."""
    input_path = Path(args.input)
    output_path = Path(args.output)

    plaintext = _read_file(input_path, MAX_PLAINTEXT_SIZE)

    if args.mode == "password":
        password = _confirm_passphrase()
        envelope = encrypt_with_password(plaintext, password)

    else:
        public_key_path = Path(args.public_key)

        public_key = load_public_key(public_key_path)
        envelope = encrypt_for_recipient(plaintext, public_key)

    _write_new_file(output_path, envelope)

    print(f"Encryption successful: {output_path}")


def _decrypt_command(args: argparse.Namespace) -> None:
    """Execute the decryption command."""
    input_path = Path(args.input)
    output_path = Path(args.output)

    envelope = _read_file(
        input_path,
        serialization.MAX_ENVELOPE_SIZE,
    )

    header, _, _, _ = serialization.deserialize_envelope(envelope)

    if header["mode"] == "password":
        if args.private_key:
            raise ValueError("--private-key is only valid for RSA mode")

        password = getpass.getpass("Enter passphrase: ")
        plaintext = decrypt_with_password(envelope, password)

    else:
        if not args.private_key:
            raise ValueError("RSA decryption requires --private-key")

        private_key_path = Path(args.private_key)
        passphrase = getpass.getpass("Private-key passphrase: ")

        private_key = load_private_key(
            private_key_path,
            passphrase,
        )

        plaintext = decrypt_with_private_key(
            envelope,
            private_key,
        )

    _write_new_file(output_path, plaintext)

    print(f"Decryption successful: {output_path}")


def _keygen_command(args: argparse.Namespace) -> None:
    """Generate and save an RSA key pair."""
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)

    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must be different")

    if private_path.exists() or public_path.exists():
        raise FileExistsError("A key output file already exists")

    passphrase = _confirm_passphrase()

    private_key, public_key = generate_key_pair()

    save_private_key(
        private_key,
        private_path,
        passphrase,
    )

    try:
        save_public_key(
            public_key,
            public_path,
        )
    except OSError as exc:
        raise OSError(
            "RSA key-pair generation incomplete: "
            f"private key was saved to '{private_path}', "
            f"but public key could not be saved to '{public_path}': {exc}"
        ) from exc

    print("RSA key pair generated successfully.")
    print(f"Private key: {private_path}")
    print(f"Public key: {public_path}")


def _info_command(args: argparse.Namespace) -> None:
    """Display non-secret envelope metadata."""
    envelope = _read_file(
        Path(args.input),
        serialization.MAX_ENVELOPE_SIZE,
    )

    header, _, ciphertext, _ = serialization.deserialize_envelope(envelope)

    print(f"Format: {header['format']}")
    print(f"Version: {header['version']}")
    print(f"Mode: {header['mode']}")
    print(f"Cipher: {header['cipher']}")
    print(f"Ciphertext size: {len(ciphertext)} bytes")

    if header["mode"] == "password":
        kdf = header["kdf"]

        print(f"KDF: {kdf['algorithm']}")
        print(f"Scrypt N: {kdf['n']}")
        print(f"Scrypt r: {kdf['r']}")
        print(f"Scrypt p: {kdf['p']}")

    else:
        key_encryption = header["key_encryption"]

        print(f"Key encryption: {key_encryption['algorithm']}")
        print(f"OAEP hash: {key_encryption['hash']}")
        print(f"OAEP MGF: {key_encryption['mgf']}")

    print()
    print("Warning: Metadata has not been authenticated.")
    print("Authentication occurs only during successful decryption.")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CipherVault argument parser."""
    parser = argparse.ArgumentParser(
        prog="ciphervault",
        description="Cryptographic file protection using AES-256-GCM.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Encryption
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file",
    )

    encrypt_parser.add_argument("--input", required=True)
    encrypt_parser.add_argument("--output", required=True)

    encrypt_parser.add_argument(
        "--mode",
        choices=["password", "rsa"],
        required=True,
    )

    encrypt_parser.add_argument("--public-key")

    # Decryption
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt an encrypted file",
    )

    decrypt_parser.add_argument("--input", required=True)
    decrypt_parser.add_argument("--output", required=True)
    decrypt_parser.add_argument("--private-key")

    # Key generation
    keygen_parser = subparsers.add_parser(
        "keygen",
        help="Generate an RSA key pair",
    )

    keygen_parser.add_argument(
        "--private-key",
        required=True,
    )

    keygen_parser.add_argument(
        "--public-key",
        required=True,
    )

    # Metadata inspection
    info_parser = subparsers.add_parser(
        "info",
        help="Inspect encrypted file metadata",
    )

    info_parser.add_argument("--input", required=True)

    return parser


def main() -> int:
    """Run the CipherVault command-line application."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            if args.mode == "rsa" and not args.public_key:
                parser.error("RSA encryption requires --public-key")

            if args.mode == "password" and args.public_key:
                parser.error("--public-key is only valid with RSA mode")

            _encrypt_command(args)

        elif args.command == "decrypt":
            _decrypt_command(args)

        elif args.command == "keygen":
            _keygen_command(args)

        elif args.command == "info":
            _info_command(args)

        return 0

    except InvalidTag:
        print(
            "Error: Authentication failed. Check the password or file integrity.",
            file=sys.stderr,
        )

    except (ValueError, TypeError, OSError, UnsupportedAlgorithm) as exc:
        print(f"Error: {exc}", file=sys.stderr)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
