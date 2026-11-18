# CipherVault — Security

## 1. Security Status

CipherVault is an educational cryptographic file-protection application.

- Project version: 0.1.0
- Development status: Experimental
- Security audit status: Not independently audited
- Production readiness: Not recommended for protecting real confidential information

The project demonstrates cryptographic file protection using authenticated symmetric encryption and RSA-based hybrid encryption.

Although it implements several security controls, its current implementation has not undergone an independent security audit or formal penetration test.

**Do not rely on CipherVault as the sole protection for sensitive, confidential, financial, personal, or business-critical information.**

## 2. Implemented Security Controls

### 2.1 Cryptographic Protection

CipherVault implements the following cryptographic mechanisms:

- AES-256-GCM for authenticated symmetric encryption.
- Scrypt for password-based key derivation.
- RSA-3072 with RSA-OAEP for hybrid encryption.
- SHA-256 for RSA-OAEP hashing.
- MGF1 with SHA-256 for RSA-OAEP mask generation.
- Cryptographically secure random generation through Python's `secrets` module.

### 2.2 Password Handling

- Passwords and passphrases are collected through `getpass` prompts.
- Passwords are not accepted as ordinary command-line arguments.
- Passwords are encoded using UTF-8 before key derivation.
- Password-based encryption uses a randomly generated 16-byte salt.
- Scrypt derives a 32-byte encryption key.
- The application limits password input to 1024 UTF-8 bytes.
- New private-key passphrases are requested twice for confirmation.

Password strength and secrecy remain the user's responsibility.

### 2.3 AES-GCM Nonce Handling

- AES-GCM uses a 12-byte nonce.
- Nonces are generated using `secrets.token_bytes()`.
- Each encryption operation generates a new random nonce.
- The nonce is stored in the encrypted envelope for later decryption.

Random nonce generation makes accidental collisions unlikely, but does not guarantee absolute uniqueness. A nonce must never be intentionally reused with the same AES-GCM key.

### 2.4 RSA Private-Key Protection

- Private keys are serialized using PEM encoding and PKCS#8 format.
- Private-key serialization uses the cryptography library's `BestAvailableEncryption`.
- Private-key files are created with permission mode `0600`.
- Passphrases are validated before private-key serialization and loading.
- Key files are subject to a 64 KiB input-size limit.

Private-key security depends on the passphrase, filesystem permissions, operating-system security, and protection of the computer where the key is stored.

### 2.5 File Handling

- Plaintext input is limited to 11 MiB.
- Encrypted envelope input is limited to 16 MiB.
- Key-file input is limited to 64 KiB.
- Encrypted and decrypted output files are created with permission mode `0600`.
- Key files are written through temporary files.
- Output files are written through temporary files.
- File publication uses hard links to avoid overwriting an existing destination.
- Temporary files are removed after publication attempts.

The file-publication approach requires filesystem hard-link support. File flushing and `fsync()` are performed on the temporary file; the containing directory is not explicitly synchronized.

### 2.6 Input Validation and Authentication

- Cryptographic inputs are checked for expected types and lengths.
- Encrypted envelopes are checked against the expected structure and format.
- Invalid authentication tags cause decryption to fail.
- Existing output files are not intentionally overwritten.
- File-size limits are applied before processing file contents.

AES-GCM authentication protects ciphertext and associated authenticated data under the encryption key. It does not establish the identity of the sender.

## 3. Security Responsibilities

Users are responsible for:

1. Choosing strong, unique passwords and passphrases.
2. Keeping passwords and private keys confidential.
3. Protecting the computer and operating-system account used to run CipherVault.
4. Verifying the authenticity of recipients' public keys through a trusted process.
5. Keeping appropriate backups of important private keys.
6. Avoiding the storage of private keys in public repositories.
7. Protecting plaintext files and decrypted output files.
8. Updating project dependencies when security fixes become available.

## 4. Known Security Limitations

CipherVault currently does not provide:

- Digital signatures.
- Sender identity verification.
- Forward secrecy.
- Public-key authenticity verification or a public-key infrastructure.
- Automatic private-key revocation.
- Enterprise key lifecycle management.
- Hardware-backed key storage.
- Protection against malware or attackers controlling the host computer.
- Protection against privileged operating-system attackers.
- A mechanism that guarantees absolute AES-GCM nonce uniqueness.
- Independent security-audit or penetration-test assurance.

RSA-OAEP is used to encrypt the AES key. It does not authenticate the sender or provide a digital signature.

## 5. Dependency Management

The application uses the Python `cryptography` library for its cryptographic operations.

- Runtime dependency versions are bounded in `pyproject.toml`.
- Development dependencies include pytest and Ruff.
- `requirements.txt` contains pinned dependency versions.
- Dependencies should be reviewed and updated when relevant security fixes are released.

Passing automated tests, linting, and formatting checks does not establish that the application is free from security vulnerabilities.

## 6. Security Reporting

CipherVault is an educational project and does not currently publish a dedicated security-response process or security-reporting contact.

Do not assume that this project has a monitored vulnerability-disclosure channel.

## 7. Final Security Notice

CipherVault is intended for educational use and for demonstrating cryptographic engineering concepts.

Its implemented controls should not be interpreted as proof of production-grade security. The application has not been independently audited, and its limitations must be considered before any real-world use.
