# CipherVault

CipherVault is an educational Python-based cryptographic file-protection application. It demonstrates authenticated symmetric encryption, password-based key derivation, public-key hybrid encryption, cryptographic key management, and secure file-handling practices.

**Version:** 0.1.0

**Status:** Under development

**Python:** 3.12+

> **Security notice:** CipherVault is an educational project. It has not undergone an independent security audit and is not recommended for protecting real confidential information or production workloads.

## Features

- Password-based file encryption and decryption.
- RSA-based hybrid encryption for recipients.
- AES-256-GCM authenticated encryption.
- Scrypt password-based key derivation.
- RSA-3072 key generation and RSA-OAEP key wrapping.
- Encrypted private-key storage.
- Strict encrypted-envelope validation.
- Protection against accidental output-file overwriting.
- Owner-only permissions for generated encrypted and decrypted files.
- Metadata inspection.

## Cryptographic Design

| Component | Algorithm or configuration |
|---|---|
| Symmetric encryption | AES-256-GCM |
| AES key size | 256 bits |
| GCM nonce | 96 bits (12 bytes) |
| Authentication tag | 128 bits (16 bytes) |
| Password-based KDF | Scrypt |
| Scrypt N | 2¹⁷ |
| Scrypt r | 8 |
| Scrypt p | 1 |
| Scrypt salt | 16 bytes |
| Public-key algorithm | RSA-3072 |
| RSA padding | OAEP |
| OAEP digest | SHA-256 |
| MGF | MGF1 with SHA-256 |
| Private-key format | Encrypted PKCS#8 PEM |
| Public-key format | SubjectPublicKeyInfo PEM |
| Envelope format | Version 1 JSON |

### Password-based encryption

1. A fresh random salt is generated.
2. Scrypt derives a 256-bit encryption key from the user's passphrase.
3. AES-256-GCM encrypts the file contents.
4. The envelope stores the required encryption metadata, salt, nonce, ciphertext and authentication tag.

### RSA-based hybrid encryption

1. A fresh random 256-bit AES key is generated.
2. RSA-OAEP wraps the AES key using the recipient's public key.
3. AES-256-GCM encrypts the file contents.
4. The encrypted AES key and encrypted file data are stored in the envelope.

The envelope header is authenticated as additional authenticated data (AAD) during AES-GCM encryption and decryption.

## Technology Stack

- Python 3.12+
- cryptography
- pytest
- Ruff
- setuptools
- Git

## Installation

### Requirements

- Python 3.12 or later.
- pip.
- A supported operating system and filesystem.

### Install from the project directory

```bash
python -m pip install .
```

### Install for development

```bash
python -m pip install -e ".[dev]"
```

The development installation includes pytest and Ruff.

## Usage

CipherVault provides four commands:

- `encrypt`
- `decrypt`
- `keygen`
- `info`

### 1. Password-based encryption

```bash
ciphervault encrypt \
    --input message.txt \
    --output message.cv \
    --mode password
```

The application prompts for a passphrase and asks for confirmation.

### 2. Password-based decryption

```bash
ciphervault decrypt \
    --input message.cv \
    --output recovered.txt
```

The application prompts for the passphrase.

### 3. Generate an RSA key pair

```bash
ciphervault keygen \
    --private-key private.pem \
    --public-key public.pem
```

The application prompts for a passphrase to protect the private key.

Keep the private key confidential. Share the public key with parties who need to encrypt files for its owner.

### 4. RSA-based encryption

```bash
ciphervault encrypt \
    --input message.txt \
    --output message.cv \
    --mode rsa \
    --public-key public.pem
```

### 5. RSA-based decryption

```bash
ciphervault decrypt \
    --input message.cv \
    --output recovered.txt \
    --private-key private.pem
```

The application prompts for the private-key passphrase.

### 6. Inspect encrypted-file metadata

```bash
ciphervault info --input message.cv
```

This command displays envelope metadata without decrypting the contents.

**Important:** Displayed metadata has not been authenticated. Authentication occurs only during successful decryption.

### 7. Display the application version

```bash
ciphervault --version
```

## File Handling

- Maximum plaintext input size: 11 MiB.
- Maximum serialized encrypted-envelope size: 16 MiB.
- Generated encrypted and decrypted output files use owner-only permissions (`0600`).
- Existing output files are not intentionally overwritten.
- Output files are staged in temporary files and published without overwriting existing paths using filesystem hard-link creation. This requires filesystem hard-link support.

## Testing

Run the complete test suite:

```bash
pytest -v
```

Run lint checks:

```bash
ruff check .
```

Verify formatting:

```bash
ruff format --check .
```

Compile the source and tests:

```bash
python -m compileall -q src tests
```

## Security Considerations and Limitations

CipherVault demonstrates cryptographic engineering concepts, but several limitations must be understood.

- AES-GCM provides confidentiality and integrity but does not authenticate the identity of the sender.
- RSA-OAEP provides encryption and key wrapping, not digital signatures.
- RSA-based encryption does not provide forward secrecy.
- Password security depends on the strength and secrecy of the chosen passphrase.
- GCM nonce uniqueness under a given key is essential. Random nonce generation does not provide an absolute uniqueness guarantee.
- Metadata inspection does not establish authenticity.
- Private-key protection depends on the security of the passphrase and the host system.
- Filesystem permissions and atomic operations do not protect against a compromised operating system or privileged attacker.

CipherVault has not undergone independent cryptographic review, penetration testing or formal security certification.

**Do not rely on this project as a production security product.**

## Project Structure

```text
CipherVault/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CRYPTOGRAPHY.md
│   ├── SECURITY.md
│   └── THREAT_MODEL.md
├── src/
│   └── ciphervault/
│       ├── aes.py
│       ├── crypto_service.py
│       ├── exceptions.py
│       ├── kdf.py
│       ├── key_manager.py
│       ├── main.py
│       ├── rsa.py
│       └── serialization.py
├── tests/
├── README.md
├── pyproject.toml
└── requirements.txt
```

## Project Goals

CipherVault is intended to demonstrate:

- Correct use of established cryptographic primitives.
- Password-based encryption and hybrid encryption.
- Authenticated encryption and integrity verification.
- Cryptographic key generation and management.
- Strict input validation and defensive programming.
- Security-focused testing and documentation.

## License

License information will be added when the project license is finalized.
