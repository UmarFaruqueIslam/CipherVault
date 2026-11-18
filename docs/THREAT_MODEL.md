# CipherVault — Threat Model

## 1. Project Overview

CipherVault is an educational cryptographic file-protection application designed to protect plaintext files through encryption.

It implements two encryption workflows:

1. Password-based encryption using AES-256-GCM and Scrypt.
2. Public-key hybrid encryption using AES-256-GCM and RSA-OAEP.

The application aims to protect the confidentiality and integrity of encrypted file contents against unauthorized access and unauthorized modification.

This threat model identifies the assets, potential threat actors, security objectives, requirements, assumptions, and limitations of the current application.

## 2. Scope and Trust Boundaries

### 2.1 In Scope

The threat model covers:

1. Password-based encryption and decryption.
2. RSA-based hybrid encryption and decryption.
3. Cryptographic key generation and handling.
4. Private-key storage and loading.
5. Encrypted envelope serialization and validation.
6. Input and output file handling.
7. Password and private-key passphrase handling.

### 2.2 Trust Boundaries

CipherVault relies on the following components and processes:

1. The operating system and Python runtime.
2. The installed cryptographic library.
3. User-supplied passwords and private-key passphrases.
4. The filesystem used to store plaintext files, encrypted envelopes, and keys.
5. The process used to obtain and verify recipients' public keys.

A compromise of these trusted components or processes may undermine the security of the application.

## 3. Assets to Protect

1. **Plaintext files:** Original data that must remain confidential.
2. **AES encryption keys:** Symmetric keys used to encrypt and decrypt file contents.
3. **RSA private keys:** Private keys used to recover encrypted AES keys.
4. **User passwords:** Passwords used for password-based encryption.
5. **Private-key passphrases:** Passphrases used to protect encrypted RSA private keys.
6. **Encrypted envelopes:** Serialized files containing ciphertext and cryptographic metadata.
7. **Cryptographic metadata:** Information such as salts, nonces, authentication tags, and encryption parameters.
8. **Public keys:** Public-key material whose authenticity must be established before use.

## 4. Potential Threat Actors

1. **Unauthorized users:** Individuals attempting to access protected files without permission.
2. **Encrypted-file thieves:** Attackers who obtain copies of encrypted envelopes.
3. **Ciphertext manipulators:** Attackers attempting to modify encrypted files or their metadata.
4. **Password attackers:** Individuals attempting offline password guessing against password-protected files.
5. **Private-key thieves:** Attackers attempting to obtain RSA private keys or their passphrases.
6. **Malicious input providers:** Individuals supplying malformed or excessively large files to exploit application weaknesses.
7. **Public-key impersonators:** Attackers attempting to substitute their own public key for the intended recipient's key.
8. **Local attackers:** Individuals with access to the computer, filesystem, or user account running CipherVault.

## 5. Potential Threats and Attack Scenarios

### 5.1 Unauthorized Plaintext Access

An attacker obtains an encrypted envelope and attempts to recover its original plaintext.

**Security considerations:**
- AES-256-GCM provides authenticated encryption.
- Password-based encryption derives its AES key using Scrypt.
- RSA-based encryption uses a randomly generated AES key wrapped with RSA-OAEP.
- Confidentiality depends on the security of the relevant encryption key and the cryptographic implementation.

### 5.2 Offline Password Guessing

An attacker obtains a password-encrypted envelope and attempts to guess its password offline.

**Security considerations:**
- Scrypt increases the computational and memory cost of password guessing.
- A random salt is generated for password-based encryption.
- Weak or predictable passwords remain vulnerable to guessing attacks.

### 5.3 Ciphertext or Metadata Modification

An attacker modifies encrypted data or associated cryptographic metadata.

**Security considerations:**
- AES-GCM authenticates ciphertext and associated authenticated data.
- Authentication failure causes decryption to fail.
- Structurally invalid envelopes may be rejected during validation before decryption.
- The `info` command displays metadata without authenticating it.

### 5.4 Private-Key Theft

An attacker obtains an RSA private-key file and attempts to use it.

**Security considerations:**
- Private keys are stored using encrypted PKCS#8 PEM serialization.
- Private-key files are created with permission mode `0600`.
- Protection depends on the strength and secrecy of the private-key passphrase and the security of the host.

### 5.5 Public-Key Substitution

An attacker supplies a public key belonging to an attacker instead of the intended recipient's public key.

**Security considerations:**
- RSA encryption protects the AES key for the public key supplied to CipherVault.
- The application does not independently verify the identity or authenticity of the public-key owner.
- Public keys must be obtained and verified through a trusted process.

### 5.6 Malformed Input and Resource Exhaustion

An attacker supplies malformed or excessively large input files.

**Security considerations:**
- The application validates cryptographic input types and lengths.
- Encrypted envelopes and key files have maximum input-size limits.
- Plaintext input has a maximum size limit.
- These controls reduce certain input-handling risks but do not guarantee protection against every denial-of-service attack.

## 6. Security Objectives

1. **Confidentiality:** Protect plaintext file contents from unauthorized disclosure.
2. **Integrity:** Detect unauthorized modification of encrypted data and authenticated metadata.
3. **Key protection:** Protect encryption keys, RSA private keys, and user passphrases.
4. **Safe input handling:** Reject invalid, malformed, and excessively large inputs.
5. **Secure randomness:** Use cryptographically secure random generation for salts, AES keys, and nonces.
6. **Safe file handling:** Avoid unintentionally overwriting existing output files and restrict permissions on newly created files.
7. **Public-key trust:** Require a trusted process for verifying the recipient's public key.

**Important distinction:** AES-GCM provides authentication of encrypted data under the secret key. CipherVault does not currently provide sender identity authentication or digital signatures.

## 7. Security Requirements

1. Use AES-256-GCM for authenticated symmetric encryption.
2. Use Scrypt for password-based key derivation.
3. Use RSA-OAEP for hybrid encryption.
4. Generate cryptographic randomness using a trusted cryptographic random source.
5. Generate a fresh random nonce for each encryption operation and never intentionally reuse a nonce with the same AES-GCM key.
6. Never hardcode encryption keys or passwords.
7. Never commit private keys or passwords to Git.
8. Reject encrypted data that fails AES-GCM authentication.
9. Validate input types, lengths, envelope structure, and file sizes.
10. Protect RSA private keys using encrypted serialization and restrictive file permissions.
11. Avoid overwriting existing output files unintentionally.
12. Do not treat unauthenticated metadata as verified information.
13. Obtain recipient public keys through a trusted process.

These requirements describe the intended security properties of the application. They should not be interpreted as proof that every possible attack is prevented.

## 8. Security Assumptions

1. The application uses trusted and appropriately maintained cryptographic libraries.
2. The operating system and Python environment are trusted.
3. Users are responsible for protecting their passwords and private-key passphrases.
4. The recipient's public key must be obtained and verified through a trusted process.
5. The filesystem and user account provide the expected access-control protections.
6. Users protect their private keys and maintain appropriate backups.
7. The application cannot protect plaintext from malware or attackers who already control the computer running it.

## 9. Project Limitations

1. CipherVault is an educational prototype.
2. It has not undergone an independent security audit or formal penetration test.
3. It does not provide digital signatures.
4. It does not automatically establish the identity of the file sender.
5. It does not independently verify public-key authenticity.
6. It does not provide forward secrecy.
7. It does not guarantee absolute AES-GCM nonce uniqueness.
8. It does not protect against compromised endpoints or privileged operating-system attackers.
9. It cannot guarantee confidentiality if encryption keys or passwords are compromised.
10. It does not provide automatic key revocation or enterprise key lifecycle management.
11. It does not provide hardware-backed key storage.
12. It does not guarantee protection against every denial-of-service attack.

## 10. Security Status

CipherVault implements several cryptographic and file-handling safeguards, but its security properties are limited by its current architecture and implementation.

The project is intended for educational use and demonstration of cryptographic engineering concepts.

It should not be considered production-ready or used as the sole protection for real confidential information without further security engineering, independent review, and testing.
