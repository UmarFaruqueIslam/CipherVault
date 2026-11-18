# CipherVault — System Architecture

## 1. Overview

CipherVault is an educational cryptographic file-protection application written in Python.

It uses a modular architecture that separates command-line interaction, application workflows, cryptographic operations, data serialization, and key management.

The application supports two encryption workflows:

- Password-based encryption using Scrypt and AES-256-GCM.
- Public-key hybrid encryption using RSA-OAEP and AES-256-GCM.

The application is organized so that each module has a specific responsibility.

## 2. Architectural Components

### 2.1 Command-Line Interface Layer

**Module:** `main.py`

The command-line interface is the primary user interaction layer.

Responsibilities:

- Parse command-line arguments.
- Provide the `encrypt`, `decrypt`, `keygen`, and `info` commands.
- Read input files.
- Write encrypted and decrypted output files.
- Prompt users for passwords and passphrases.
- Load the required RSA keys.
- Display application information and errors.
- Coordinate user requests with the application workflow layer.

The CLI does not implement the cryptographic algorithms itself.

### 2.2 Application Workflow Layer

**Module:** `crypto_service.py`

This layer coordinates the application's encryption and decryption operations.

It connects the cryptographic modules and serialization module to implement complete encryption workflows.

Responsibilities:

- Coordinate password-based encryption and decryption.
- Coordinate RSA-based hybrid encryption and decryption.
- Generate or obtain the required encryption keys.
- Coordinate password-based key derivation.
- Coordinate RSA-OAEP key wrapping and unwrapping.
- Construct authenticated additional data.
- Coordinate AES-GCM encryption and decryption.
- Serialize and deserialize encrypted envelopes.

The workflow layer coordinates cryptographic operations rather than implementing the underlying cryptographic primitives.

### 2.3 Cryptographic Operations Layer

This layer contains the modules responsible for individual cryptographic operations.

#### `aes.py`

Implements authenticated symmetric encryption using AES-256-GCM.

Responsibilities:

- Validate AES keys and input parameters.
- Generate a 12-byte random nonce.
- Encrypt plaintext using AES-GCM.
- Decrypt ciphertext using AES-GCM.
- Verify the authentication tag during decryption.

#### `kdf.py`

Implements password-based key derivation using Scrypt.

Responsibilities:

- Generate random salts.
- Validate passwords and salt values.
- Derive 256-bit encryption keys using Scrypt.

#### `rsa.py`

Implements RSA key generation and RSA-OAEP key wrapping.

Responsibilities:

- Generate RSA key pairs.
- Validate RSA key parameters.
- Encrypt AES keys using RSA-OAEP.
- Recover AES keys using RSA-OAEP.

RSA is used to protect the AES encryption key, not to encrypt the complete file directly.

### 2.4 Data Serialization Layer

**Module:** `serialization.py`

This layer manages the structure and validation of encrypted data envelopes.

Responsibilities:

- Define the CipherVault envelope format.
- Construct encryption metadata headers.
- Validate envelope structure and required fields.
- Encode and decode binary data using Base64.
- Generate canonical JSON authenticated additional data.
- Serialize encrypted data into JSON.
- Deserialize and validate encrypted JSON envelopes.
- Enforce envelope size and cryptographic parameter constraints.

The serialization layer is used by both the application workflow layer and the command-line interface.

### 2.5 Key Management Layer

**Module:** `key_manager.py`

This layer handles RSA public and private key storage.

Responsibilities:

- Serialize RSA private keys using encrypted PKCS#8 PEM.
- Serialize RSA public keys using SubjectPublicKeyInfo PEM.
- Save public and private keys to files.
- Load and validate stored RSA keys.
- Apply file permissions when saving key files.
- Use temporary files and no-overwrite publication when writing keys.

Private-key protection depends on the user's passphrase and the security of the operating system.

## 3. High-Level Architecture

```text
                    USER
                      |
                      v
              COMMAND-LINE INTERFACE
                   main.py
                      |
          +-----------+-----------+
          |                       |
          v                       v
   APPLICATION WORKFLOW      KEY MANAGEMENT
    crypto_service.py        key_manager.py
          |
          |
    +-----+----------------------+
    |             |              |
    v             v              v
  aes.py         kdf.py         rsa.py
    |             |              |
    +-------------+--------------+
                  |
                  v
             SERIALIZATION
             serialization.py
```

The diagram represents logical responsibilities and major dependencies. It is not intended to show every individual function call.

## 4. Encryption Workflows

### 4.1 Password-Based Encryption

1. The user invokes the encryption command through the CLI.
2. The CLI reads the input file.
3. The workflow layer receives the plaintext and password.
4. The KDF module generates a fresh random salt.
5. Scrypt derives a 256-bit AES key from the password and salt.
6. The serialization module constructs the password-mode metadata header.
7. The header is converted into authenticated additional data (AAD).
8. The AES module generates a random 12-byte nonce.
9. AES-256-GCM encrypts the plaintext and produces ciphertext and an authentication tag.
10. The serialization module constructs the encrypted envelope.
11. The CLI writes the resulting envelope to the output file.

### 4.2 RSA Hybrid Encryption

1. The user invokes RSA-mode encryption through the CLI.
2. The CLI loads the recipient's public key.
3. The workflow layer generates a fresh random 256-bit AES key.
4. The RSA module wraps the AES key using RSA-OAEP.
5. The serialization module constructs the RSA-mode metadata header.
6. The header is converted into authenticated additional data (AAD).
7. The AES module generates a random 12-byte nonce.
8. AES-256-GCM encrypts the plaintext.
9. The serialization module constructs an envelope containing the metadata, wrapped AES key, nonce, ciphertext, and authentication tag.
10. The CLI writes the resulting envelope to the output file.

## 5. Decryption Workflows

### 5.1 Password-Based Decryption

1. The CLI reads the encrypted envelope.
2. The serialization module deserializes and validates its structure.
3. The workflow layer verifies that the envelope uses password mode.
4. The salt is extracted from the metadata.
5. Scrypt derives the AES key from the supplied password and salt.
6. The authenticated additional data is reconstructed.
7. AES-256-GCM verifies the authentication tag and decrypts the ciphertext.
8. The CLI writes the recovered plaintext to the output file.

### 5.2 RSA Hybrid Decryption

1. The CLI reads the encrypted envelope.
2. The serialization module deserializes and validates its structure.
3. The workflow layer verifies that the envelope uses RSA mode.
4. The recipient's private key is loaded.
5. The wrapped AES key is extracted from the metadata.
6. The RSA module unwraps the AES key using RSA-OAEP.
7. The authenticated additional data is reconstructed.
8. AES-256-GCM verifies the authentication tag and decrypts the ciphertext.
9. The CLI writes the recovered plaintext to the output file.

## 6. Encrypted Envelope

CipherVault stores encrypted data in a structured JSON envelope.

The envelope contains:

- Format identifier.
- Format version.
- Encryption mode.
- Cipher identifier.
- Mode-specific key derivation or key-encryption metadata.
- AES-GCM nonce.
- Ciphertext.
- Authentication tag.

The password mode stores Scrypt parameters and salt.

The RSA mode stores RSA-OAEP parameters and the wrapped AES key.

The metadata header is used as authenticated additional data during AES-GCM encryption and decryption.

## 7. File Handling

The CLI layer is responsible for reading input files and publishing output files.

The implementation includes:

- Maximum input and envelope size checks.
- File-size validation before processing.
- Temporary-file-based output writing.
- Restrictive output permissions.
- No-overwrite publication using filesystem hard links.

The no-overwrite publication mechanism requires filesystem support for hard links.

## 8. Security Boundaries and Limitations

CipherVault is an educational prototype and has not undergone an independent security audit.

Important limitations:

- AES-GCM authenticates encrypted data but does not establish the sender's identity.
- RSA-OAEP key wrapping does not provide digital signatures.
- RSA-based encryption does not provide forward secrecy.
- Random nonce generation makes AES-GCM nonce collisions unlikely but does not mathematically guarantee uniqueness.
- Password-based encryption depends on password strength and secrecy.
- Private-key protection depends on passphrase security and endpoint security.
- The application cannot protect plaintext from malware or an attacker controlling the user's operating system.

## 9. Project Modules

```text
src/
└── ciphervault/
    ├── __init__.py
    ├── aes.py
    ├── crypto_service.py
    ├── exceptions.py
    ├── kdf.py
    ├── key_manager.py
    ├── main.py
    ├── rsa.py
    └── serialization.py
```

Each module is intended to maintain a clearly defined responsibility, helping keep the implementation modular and easier to test and maintain.
