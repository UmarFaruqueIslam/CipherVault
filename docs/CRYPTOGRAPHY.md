# CipherVault — Cryptographic Design

## 1. Overview

CipherVault uses established cryptographic algorithms to provide confidentiality and integrity protection for encrypted files.

Its cryptographic design combines:

- AES-256-GCM for authenticated symmetric encryption.
- Scrypt for password-based key derivation.
- RSA-3072 for public-key cryptography.
- RSA-OAEP with SHA-256 for AES key wrapping.
- Cryptographically secure random number generation for salts, AES keys and nonces.

CipherVault supports two encryption modes:

1. Password-based encryption.
2. RSA-based hybrid encryption.

The application uses the Python `cryptography` library for its cryptographic operations.

## 2. AES-256-GCM

### 2.1 Introduction

AES (Advanced Encryption Standard) is a symmetric block cipher.

Symmetric encryption uses the same secret key for encryption and decryption.

CipherVault uses AES-256-GCM to encrypt file contents.

GCM stands for Galois/Counter Mode. It provides authenticated encryption with associated data (AEAD).

This means that AES-GCM provides:

- Confidentiality of plaintext.
- Integrity protection for ciphertext.
- Authentication of ciphertext and associated data under the secret key.

AES-GCM does not establish the identity of the person who encrypted the data.

### 2.2 CipherVault Configuration

| Parameter | Configuration |
|---|---|
| Algorithm | AES-256-GCM |
| Key size | 256 bits |
| Key length | 32 bytes |
| Nonce size | 96 bits |
| Nonce length | 12 bytes |
| Authentication tag | 128 bits |
| Tag length | 16 bytes |

### 2.3 Encryption Process

CipherVault uses the `AESGCM` implementation provided by the Python `cryptography` library.

The encryption function:

1. Validates the AES key.
2. Validates the plaintext and associated data.
3. Generates a random 12-byte nonce.
4. Encrypts the plaintext using AES-GCM.
5. Separates the resulting ciphertext and authentication tag.
6. Returns the nonce, ciphertext and authentication tag.

The encryption operation is conceptually represented as:

`(ciphertext, tag) = AES-GCM-Encrypt(key, nonce, plaintext, AAD)`

The nonce is stored alongside the encrypted data because it is required for decryption.

### 2.4 Decryption and Authentication

During decryption:

1. The application retrieves the AES key.
2. The stored nonce is supplied.
3. The ciphertext and authentication tag are combined.
4. The original AAD is reconstructed.
5. AES-GCM verifies the authentication tag.
6. Plaintext is returned only when authentication succeeds.

If authentication fails, the cryptographic library raises an `InvalidTag` exception.

This can occur when:

- The encryption key is incorrect.
- The ciphertext has been modified.
- The nonce has been modified.
- The authentication tag has been modified.
- The associated data has been modified.

### 2.5 Nonce Management

A nonce is a value used once within a cryptographic operation.

CipherVault generates nonces using Python's `secrets.token_bytes()` function.

The implementation generates a 12-byte random nonce for every AES-GCM encryption operation.

Nonce uniqueness under a given key is a critical GCM security requirement.

Random generation makes collisions unlikely, but it does not guarantee uniqueness.

The application must therefore avoid reusing the same nonce with the same AES key.

## 3. Scrypt Key Derivation Function

### 3.1 Introduction

Scrypt is a password-based key derivation function.

A password is generally not suitable for direct use as an AES encryption key because passwords are often shorter and less random than cryptographic keys.

Scrypt transforms a password and a salt into a derived cryptographic key.

It is designed to impose configurable computational and memory costs, making large-scale password guessing more expensive.

### 3.2 CipherVault Configuration

| Parameter | Value |
|---|---|
| Algorithm | Scrypt |
| N | 2^17 (131,072) |
| r | 8 |
| p | 1 |
| Salt length | 16 bytes |
| Derived key length | 32 bytes |
| Password encoding | UTF-8 |
| Maximum password input | 1,024 UTF-8 bytes |

### 3.3 Scrypt Parameters

**N — CPU and memory cost parameter**

N controls the principal computational and memory cost of Scrypt.

CipherVault uses:

`N = 2^17 = 131072`

N must be greater than 1 and a power of two.

**r — Block size parameter**

r controls the block size used by Scrypt.

CipherVault uses:

`r = 8`

**p — Parallelization parameter**

p controls the parallelization parameter and contributes to computational cost.

CipherVault uses:

`p = 1`

### 3.4 Approximate Memory Requirement

The principal Scrypt memory requirement can be approximated using:

`Memory ≈ 128 × N × r bytes`

For CipherVault:

`Memory ≈ 128 × 131072 × 8`

`Memory ≈ 134217728 bytes`

This is approximately 128 MiB.

The actual total memory consumption may be higher because of implementation overhead and other application operations.

### 3.5 Salt Generation

A salt is a random value supplied to a key derivation function.

CipherVault generates a fresh 16-byte salt using:

`secrets.token_bytes(16)`

The salt:

- Is not a secret.
- Is stored in the encrypted envelope.
- Is required to derive the same AES key during decryption.
- Makes identical passwords produce different derived keys when different salts are used.

### 3.6 Key Derivation Workflow

Password-based encryption follows this process:

1. Receive the user's password.
2. Validate the password.
3. Convert the password to UTF-8 bytes.
4. Generate a random 16-byte salt.
5. Initialize Scrypt using the configured parameters.
6. Derive a 32-byte encryption key.
7. Use the derived key for AES-256-GCM encryption.

During decryption, the stored salt and supplied password are used with the same Scrypt parameters to reproduce the AES key.

## 4. RSA Public-Key Cryptography

### 4.1 Introduction

RSA is an asymmetric cryptographic algorithm.

Asymmetric cryptography uses two mathematically related keys:

- A public key.
- A private key.

The public key can be distributed to other users, while the private key must remain protected.

CipherVault uses RSA to protect the AES encryption key in its hybrid encryption workflow.

It does not use RSA to encrypt the complete file.

### 4.2 CipherVault Configuration

| Parameter | Value |
|---|---|
| Algorithm | RSA |
| Key size | 3,072 bits |
| Public exponent | 65,537 |
| Key wrapping scheme | RSA-OAEP |
| OAEP digest | SHA-256 |
| Mask generation function | MGF1 |
| MGF1 digest | SHA-256 |
| OAEP label | None |

### 4.3 RSA Key Generation

CipherVault generates RSA key pairs using the `cryptography` library.

The generated key pair contains:

- An RSA private key.
- Its corresponding RSA public key.

The implementation uses a 3,072-bit RSA key and public exponent 65,537.

### 4.4 RSA-OAEP

RSA-OAEP is an encryption scheme used with RSA.

OAEP stands for Optimal Asymmetric Encryption Padding.

CipherVault uses RSA-OAEP with SHA-256 and MGF1 with SHA-256.

The OAEP scheme provides randomized encryption. Encrypting the same AES key multiple times does not necessarily produce the same RSA ciphertext.

CipherVault uses RSA-OAEP to encrypt a 32-byte AES key.

## 5. Hybrid Encryption

### 5.1 Introduction

Hybrid encryption combines symmetric and asymmetric cryptography.

Symmetric encryption is suitable for encrypting large amounts of data, while asymmetric cryptography can be used to protect the symmetric encryption key.

CipherVault uses this approach in RSA mode.

### 5.2 Encryption Workflow

1. Generate a fresh random 32-byte AES key.
2. Encrypt the AES key using the recipient's RSA public key and RSA-OAEP.
3. Generate a random AES-GCM nonce.
4. Encrypt the file using AES-256-GCM.
5. Construct the encrypted envelope.
6. Store the RSA-encrypted AES key and AES-GCM encryption components in the envelope.

### 5.3 Decryption Workflow

1. Read the encrypted envelope.
2. Extract the RSA-encrypted AES key.
3. Load the recipient's RSA private key.
4. Decrypt the wrapped AES key using RSA-OAEP.
5. Recover the original 32-byte AES key.
6. Authenticate and decrypt the file using AES-256-GCM.

## 6. Authenticated Additional Data

### 6.1 Introduction

Authenticated Additional Data (AAD) is information authenticated by an AEAD encryption algorithm without being encrypted.

AES-GCM can authenticate both ciphertext and additional associated data.

AAD is useful when metadata must remain readable but should not be modifiable without detection.

### 6.2 CipherVault Implementation

CipherVault uses the encryption metadata header as AAD.

The header is converted into deterministic JSON using:

- Sorted object keys.
- Compact separators.
- ASCII escaping.
- Rejection of non-standard JSON numeric constants.

The resulting JSON bytes are supplied to AES-GCM during encryption and reconstructed during decryption.

### 6.3 Security Purpose

AAD protects the authenticated metadata against undetected modification.

If metadata is modified while remaining structurally valid and the application proceeds to AES-GCM decryption, the reconstructed AAD will differ from the original AAD. Authentication will therefore fail.

Some modifications may instead be rejected earlier during envelope validation or encryption-mode checking.

AAD is not encrypted and does not prove the sender's identity.

## 7. Cryptographic Randomness

CipherVault uses Python's `secrets` module to generate cryptographic random values.

The implementation uses cryptographic randomness for:

- Scrypt salts.
- AES-GCM nonces.
- AES keys in RSA hybrid encryption.

Randomness is important because predictable cryptographic values can weaken security.

The application does not hardcode AES encryption keys or salts.

## 8. Cryptographic Key Storage

CipherVault uses PEM serialization for RSA keys.

Private keys are stored using encrypted PKCS#8 PEM serialization.

Public keys are stored using SubjectPublicKeyInfo PEM serialization.

The private-key serialization is protected using a user-supplied passphrase.

The key-management implementation also applies file permissions when saving key files.

Private-key protection depends on passphrase strength and the security of the host operating system.

## 9. Security Properties and Limitations

### 9.1 Security Properties

CipherVault's cryptographic design provides:

- Confidentiality through AES-256-GCM.
- Ciphertext and AAD integrity protection through AES-GCM authentication.
- Password-based encryption keys through Scrypt.
- Public-key protection of AES keys through RSA-OAEP.
- Cryptographically secure random generation for salts, nonces and AES keys.

### 9.2 Limitations

The current implementation has important limitations:

1. AES-GCM does not authenticate the identity of the sender.
2. RSA-OAEP does not provide digital signatures.
3. RSA-based encryption does not provide forward secrecy.
4. Random nonce generation does not mathematically guarantee nonce uniqueness.
5. Password-based encryption depends on password strength and secrecy.
6. Private-key protection depends on passphrase security and endpoint security.
7. Public-key authenticity depends on obtaining the recipient's public key through a trusted process.
8. The application has not undergone an independent security audit.

CipherVault is an educational prototype and should not be considered production-ready cryptographic software.

## 10. References

1. [NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final).

2. [RFC 7914 — The scrypt Password-Based Key Derivation Function](https://www.rfc-editor.org/rfc/rfc7914.html).

3. [RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2](https://www.rfc-editor.org/rfc/rfc8017.html).

4. [Python Cryptography Documentation — AESGCM](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/).

5. [Python Cryptography Documentation — Scrypt](https://cryptography.io/en/50.0.2/hazmat/primitives/key-derivation-functions/).

6. [Python Cryptography Documentation — RSA](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/rsa/).
