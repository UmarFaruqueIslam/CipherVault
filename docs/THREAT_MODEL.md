# CipherVault — Threat Model

## 1. Project Overview

CipherVault is an educational cryptographic application
designed to protect confidential text messages.

It implements authenticated symmetric encryption
and public-key hybrid encryption.

## 2. Assets to Protect

1. Plaintext messages.
2. Encryption keys.
3. RSA private keys.
4. User passwords.
5. Encrypted message packages.
6. Cryptographic metadata.

## 3. Potential Threat Actors

1. Unauthorized users.
2. Attackers who steal encrypted files.
3. Attackers who modify ciphertext.
4. Attackers attempting password guessing.
5. Attackers attempting to steal private keys.
6. Attackers attempting to exploit malformed inputs.

## 4. Security Objectives

1. Confidentiality of plaintext messages.
2. Integrity of encrypted data.
3. Secure cryptographic key handling.
4. Authentication of encrypted data.
5. Safe input validation.
6. Protection against accidental secret disclosure.

## 5. Security Requirements

1. Use AES-256-GCM for authenticated encryption.
2. Use Scrypt for password-based key derivation.
3. Use RSA-OAEP for hybrid encryption.
4. Generate cryptographic randomness securely.
5. Never hardcode encryption keys or passwords.
6. Never commit private keys to Git.
7. Reject modified ciphertext.
8. Handle invalid inputs safely.
9. Prevent AES-GCM nonce reuse with the same key.
10. Protect RSA private keys with appropriate safeguards.

## 6. Security Assumptions

1. The application uses trusted cryptographic libraries.
2. The operating system and Python environment are trusted.
3. Users are responsible for protecting their passwords.
4. The recipient's public key must be obtained through a
   trusted process.
5. The application cannot protect plaintext from malware
   that already controls the user's computer.

## 7. Project Limitations

1. This is an educational prototype.
2. It is not independently security audited.
3. It does not automatically establish the identity
   of the message sender.
4. It does not protect against compromised endpoints.
5. It cannot guarantee confidentiality if encryption
   keys are compromised.
6. It does not provide automatic key revocation
   or enterprise key lifecycle management.
