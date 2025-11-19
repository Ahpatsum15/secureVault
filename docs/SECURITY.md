# Security Architecture & Cryptographic Protocols

This document provides detailed information about the security architecture, cryptographic protocols, threat model, and design decisions for secureVault.

## Table of Contents

- [Cryptographic Primitives](#cryptographic-primitives)
- [Security Architecture](#security-architecture)
- [Key Derivation Flow](#key-derivation-flow)
- [Threat Model](#threat-model)
- [Security Guarantees](#security-guarantees)
- [Limitations & Non-Goals](#limitations--non-goals)
- [References & Resources](#references--resources)

---

## Cryptographic Primitives

secureVault uses industry-standard, well-vetted cryptographic algorithms recommended by NIST, IETF, and cryptography experts.

### 1. Argon2id - Master Password Hashing

**Purpose**: Hash the master password for authentication and resist brute-force attacks.

**Algorithm**: Argon2id (RFC 9106)

**Parameters** (RFC 9106 High Memory):
- **Type**: Argon2id (hybrid mode - combines data-dependent and data-independent memory access)
- **Memory Cost**: 2,097,152 KiB (2 GiB) - Requires significant memory to compute
- **Time Cost**: 1 iteration
- **Parallelism**: 4 threads
- **Salt Length**: 16 bytes (128 bits)
- **Hash Length**: 32 bytes (256 bits)

**Why Argon2id?**
- Winner of the Password Hashing Competition (2015)
- Resistant to GPU/ASIC attacks (high memory cost)
- Resistant to side-channel attacks (hybrid mode)
- Recommended by OWASP and security experts
- Configurable parameters allow future-proofing

**Resources**:
- [RFC 9106 - Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
- [Argon2 Official Repository](https://github.com/P-H-C/phc-winner-argon2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

### 2. HKDF - Key Derivation Function

**Purpose**: Derive a cryptographically strong encryption key from the master password.

**Algorithm**: HKDF (HMAC-based Key Derivation Function) with SHA-256

**Parameters**:
- **Hash Function**: SHA-256
- **Salt**: 32 bytes (256 bits) - randomly generated per vault
- **Info**: `b'securevault-encryption-key-v1'` - context string for domain separation
- **Output Length**: 32 bytes (256 bits) - for AES-256

**Why HKDF?**
- Standardized in RFC 5869
- Cryptographically sound key derivation
- Allows deriving multiple keys from one secret
- Domain separation via info parameter
- Recommended by NIST SP 800-108

**Key Derivation Process**:
```
Master Password → UTF-8 Encoding → HKDF(salt, info) → 256-bit Encryption Key
```

**Resources**:
- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-108 - Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final)

---

### 3. AES-256-GCM - Authenticated Encryption

**Purpose**: Encrypt password entries with confidentiality and integrity protection.

**Algorithm**: AES-256 in Galois/Counter Mode (GCM)

**Parameters**:
- **Key Size**: 256 bits
- **Nonce Size**: 96 bits (12 bytes) - recommended for GCM
- **Tag Size**: 128 bits (16 bytes) - authentication tag
- **Associated Data**: None (could be used for metadata in future versions)

**Why AES-256-GCM?**
- **Confidentiality**: AES-256 is the gold standard for symmetric encryption
- **Integrity**: GCM provides authentication tag to detect tampering
- **Performance**: Hardware-accelerated on modern CPUs (AES-NI)
- **NIST Approved**: NIST SP 800-38D
- **Unique Nonces**: Each encryption uses a fresh random nonce

**Encryption Process**:
```
Plaintext Password → AES-256-GCM(key, nonce) → (Ciphertext, Authentication Tag)
```

**Security Properties**:
- **IND-CPA**: Indistinguishable under chosen-plaintext attack
- **INT-CTXT**: Integrity of ciphertext (detects tampering)
- **AEAD**: Authenticated Encryption with Associated Data

**Resources**:
- [NIST SP 800-38D - GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [AES-GCM Security Analysis](https://eprint.iacr.org/2016/475.pdf)

---

### 4. Cryptographically Secure Random Number Generation

**Purpose**: Generate salts, nonces, and random passwords.

**Algorithm**: Python's `secrets` module (CSPRNG)

**Implementation**:
- Uses OS-provided randomness (`/dev/urandom` on Unix, `CryptGenRandom` on Windows)
- Suitable for cryptographic use
- Non-deterministic and unpredictable

**Resources**:
- [Python secrets Module Documentation](https://docs.python.org/3/library/secrets.html)
- [PEP 506 - secrets Module](https://peps.python.org/pep-0506/)

---

## Security Architecture

### Two-Tier Key System

secureVault uses a **two-tier key system** that separates authentication from encryption:

```
┌─────────────────────────────────────────────────────────────┐
│                     Master Password                          │
│                  (User's Secret Input)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
        ▼                             ▼
┌──────────────┐              ┌──────────────┐
│   Argon2id   │              │     HKDF     │
│   Hashing    │              │ Key Derivation│
└──────┬───────┘              └──────┬───────┘
       │                             │
       ▼                             ▼
┌──────────────┐              ┌──────────────┐
│ Master Hash  │              │ Encryption   │
│  (Stored)    │              │ Key (Memory) │
└──────────────┘              └──────┬───────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │  AES-256-GCM │
                              │  Encryption  │
                              └──────┬───────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │  Encrypted   │
                              │   Entries    │
                              └──────────────┘
```

**Tier 1 - Authentication**:
- Master password is hashed with Argon2id
- Hash is stored in vault metadata
- Used to verify user identity when unlocking vault

**Tier 2 - Encryption**:
- Master password is used with HKDF to derive encryption key
- Encryption key exists **only in memory** during vault operations
- Used to encrypt/decrypt password entries with AES-256-GCM

**Benefits of Separation**:
1. **Defense in Depth**: Compromising the Argon2id hash doesn't reveal the encryption key
2. **Key Rotation**: Can change master password without re-encrypting (though we do for security)
3. **Future Flexibility**: Can derive multiple keys for different purposes

---

## Key Derivation Flow

### Vault Initialization

```
1. User enters master password
2. Generate random salt (32 bytes)
3. Hash master password with Argon2id → master_hash
4. Derive encryption key with HKDF(master_password, salt) → encryption_key
5. Store: {salt, master_hash, encrypted_entries: []}
6. Clear encryption_key from memory
```

### Vault Unlock

```
1. User enters master password
2. Load vault metadata (salt, master_hash)
3. Verify: Argon2id.verify(master_hash, master_password)
4. If valid: Derive encryption_key with HKDF(master_password, salt)
5. Keep encryption_key in memory for operations
```

### Entry Encryption

```
1. Generate unique nonce (12 bytes)
2. Encrypt: AES-256-GCM(plaintext_password, encryption_key, nonce)
3. Store: {ciphertext, nonce, metadata}
```

### Entry Decryption

```
1. Load: {ciphertext, nonce}
2. Decrypt: AES-256-GCM.decrypt(ciphertext, encryption_key, nonce)
3. Verify authentication tag (automatic in GCM)
4. Return plaintext password
```

---

## Threat Model

### Assumptions

**What we protect against**:
- ✅ **Offline attacks**: Vault file stolen, attacker tries to crack master password
- ✅ **Brute-force attacks**: High Argon2id memory cost makes this infeasible
- ✅ **Dictionary attacks**: Strong master password requirement
- ✅ **Data tampering**: GCM authentication tag detects modifications
- ✅ **Weak passwords**: Secure password generator available
- ✅ **Accidental exposure**: File permissions set to 600

**What we DON'T protect against**:
- ❌ **Malware on user's system**: Keyloggers, memory dumps, etc.
- ❌ **Physical access to unlocked vault**: If vault is unlocked, passwords are accessible
- ❌ **Side-channel attacks**: Timing attacks, power analysis (out of scope)
- ❌ **Quantum computers**: AES-256 and SHA-256 have reduced security against quantum attacks
- ❌ **Social engineering**: Tricking user into revealing master password

### Attack Scenarios

#### Scenario 1: Vault File Stolen

**Attack**: Attacker obtains `vault.enc` file.

**Defense**:
1. Master password is not stored (only Argon2id hash)
2. Argon2id with 2 GiB memory cost makes brute-force extremely expensive
3. Even if Argon2id hash is cracked, encryption key requires HKDF derivation
4. Each entry encrypted with unique nonce prevents pattern analysis

**Estimated Cost**: With 2 GiB memory cost, each password attempt requires ~2 GiB of RAM and significant computation. For a 12-character random password (~78 bits entropy), brute-force is computationally infeasible.

#### Scenario 2: Data Tampering

**Attack**: Attacker modifies encrypted entries in vault file.

**Defense**:
1. AES-GCM authentication tag detects any modification
2. Decryption fails if ciphertext or nonce is altered
3. User is alerted to corruption

#### Scenario 3: Weak Master Password

**Attack**: User chooses weak master password like "password123".

**Defense**:
1. CLI warns if password is too short
2. Documentation emphasizes strong password importance
3. Argon2id still provides some protection, but weak password is weak

**Mitigation**: User education and password strength indicators.

---

## Security Guarantees

### What secureVault Guarantees

1. **Confidentiality**: Passwords are encrypted with AES-256-GCM
   - Ciphertext reveals no information about plaintext
   - Unique nonce per encryption prevents pattern analysis

2. **Integrity**: GCM authentication tag ensures data hasn't been tampered
   - Any modification to ciphertext is detected
   - Prevents malicious vault modifications

3. **Authentication**: Argon2id hash verifies master password
   - Only correct master password can unlock vault
   - High memory cost resists brute-force attacks

4. **Forward Secrecy**: Changing master password re-encrypts all entries
   - Old master password cannot decrypt new vault
   - Compromised old password doesn't affect new vault

5. **No Password Recovery**: Master password is never stored
   - Cannot be recovered if forgotten
   - This is a security feature, not a bug

### What secureVault Does NOT Guarantee

1. **Protection against malware**: If your system is compromised, all bets are off
2. **Protection against physical access**: If someone has your unlocked vault, they can access passwords
3. **Quantum resistance**: AES-256 and SHA-256 have reduced security against quantum computers
4. **Side-channel resistance**: Timing attacks and power analysis are out of scope
5. **Professional audit**: This is an educational project, not professionally audited

---

## Limitations & Non-Goals

### Limitations

1. **Memory Requirements**: Argon2id with 2 GiB memory cost requires significant RAM
   - May not work on low-memory systems
   - Can be adjusted in `crypto.py` if needed

2. **Single User**: Designed for single-user, local use
   - No multi-user support
   - No synchronization across devices

3. **No Cloud Sync**: Vault is stored locally only
   - User must manually backup and sync
   - This is intentional for security

4. **No Password Recovery**: If master password is forgotten, vault is lost
   - No backdoor or recovery mechanism
   - This is a security feature

### Non-Goals

1. **Enterprise Features**: No role-based access, audit logs, or compliance features
2. **Mobile Apps**: CLI only, no mobile or GUI versions
3. **Browser Integration**: No browser extensions or auto-fill
4. **Cloud Storage**: No built-in cloud sync or backup
5. **Password Sharing**: No secure sharing with other users

---

## Best Practices for Users

### Master Password

1. **Use a strong, unique master password**:
   - Minimum 12 characters (20+ recommended)
   - Mix of uppercase, lowercase, numbers, symbols
   - Or use a passphrase with 6+ words

2. **Never reuse your master password**: Don't use it anywhere else

3. **Memorize it**: Don't write it down or store it digitally

4. **Consider a passphrase**: Easier to remember, harder to crack
   - Example: `correct-horse-battery-staple-mountain-river`

### Vault Management

1. **Regular backups**: Backup `~/.securevault/vault.enc` to secure location
   - External drive, encrypted USB, etc.
   - Test backups periodically

2. **Secure your system**: 
   - Keep OS and software updated
   - Use full-disk encryption
   - Use antivirus/antimalware

3. **Lock when not in use**: Vault auto-locks when CLI exits

4. **Delete export files**: If you export to JSON, delete immediately after use

### Password Generation

1. **Use generated passwords**: Let secureVault create strong passwords
2. **Unique per service**: Never reuse passwords across services
3. **Longer is better**: 20+ characters for sensitive accounts
4. **Passphrases for memorability**: Use `--passphrase` for accounts you need to type

---

## References & Resources

### Standards & RFCs

- [RFC 9106 - Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications](https://datatracker.ietf.org/doc/html/rfc9106)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-38D - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST SP 800-108 - Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final)
- [NIST FIPS 197 - Advanced Encryption Standard (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)

### Security Guidelines

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines (SP 800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Academic Papers

- [Argon2: The Memory-Hard Function for Password Hashing and Other Applications](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
- [The Security of the Cipher Block Chaining Message Authentication Code](https://cseweb.ucsd.edu/~mihir/papers/cbc.pdf)
- [Authentication Failures in NIST version of GCM](https://eprint.iacr.org/2016/475.pdf)

### Cryptography Libraries

- [Python cryptography library](https://cryptography.io/)
- [argon2-cffi Documentation](https://argon2-cffi.readthedocs.io/)

### Learning Resources

- [Cryptography I - Stanford Online (Coursera)](https://www.coursera.org/learn/crypto)
- [The Cryptopals Crypto Challenges](https://cryptopals.com/)
- [Serious Cryptography by Jean-Philippe Aumasson](https://nostarch.com/seriouscrypto)
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied-cryptography/)

### Tools & Testing

- [CyberChef - Crypto Swiss Army Knife](https://gchq.github.io/CyberChef/)
- [Have I Been Pwned - Password Breach Database](https://haveibeenpwned.com/)
- [zxcvbn - Password Strength Estimator](https://github.com/dropbox/zxcvbn)

---

## Security Disclosure

If you discover a security vulnerability in secureVault, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly (see README for contact)
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix before public disclosure

---

## Changelog & Security Updates

### Version 1.0.0 (2025-11-19)

**Initial Release**:
- Argon2id password hashing (RFC 9106, 2 GiB memory cost)
- HKDF key derivation (RFC 5869, SHA-256)
- AES-256-GCM authenticated encryption
- Secure password generation (CSPRNG)
- CLI with 10 commands
- 65 comprehensive tests

**Known Issues**: None

---

## Conclusion

secureVault implements modern, industry-standard cryptographic protocols to provide a secure, offline password manager. While it uses the same cryptographic primitives as professional password managers, it is primarily an educational project and has not undergone professional security audits.

**Use at your own risk**, and always maintain backups of your vault file.

For questions or concerns about security, please refer to the resources above or contact the maintainer.
