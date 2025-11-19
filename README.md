# SecureVault 🔐

**A cryptographically secure, offline password manager built with modern encryption protocols**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Project Goals

This project was created with two main objectives:

1. **Learning & Skill Development**: I've always wanted to learn how to implement cryptographic algorithms properly. Cryptography is my favorite area in computer science, and building a password manager from scratch is an excellent way to deepen my understanding of security protocols and best practices.

2. **Privacy & Transparency**: I want to build a personal password manager that doesn't require trusting third-party companies with sensitive data. By implementing the latest cryptography recommendations and keeping the codebase open and transparent, users can verify the security themselves.

---

## ✨ Features

- 🔒 **Military-Grade Encryption**: AES-256-GCM authenticated encryption
- 🛡️ **Argon2id Password Hashing**: RFC 9106 compliant with 2 GiB memory cost
- 🔑 **HKDF Key Derivation**: Secure key derivation from master password
- 💾 **100% Offline**: No network calls, all data stored locally
- 🎲 **Secure Password Generator**: Cryptographically secure random passwords and passphrases
- 📋 **Clipboard Integration**: Auto-copy with configurable timeout
- 🎨 **Beautiful CLI**: Rich terminal UI with colors and tables
- ✅ **Fully Tested**: 65 comprehensive tests covering all functionality
- 📚 **Well Documented**: Extensive documentation and security analysis

---

## 🔐 Security Overview

secureVault uses industry-standard cryptographic protocols:

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| **Master Password** | Argon2id (2 GiB memory) | RFC 9106 |
| **Key Derivation** | HKDF-SHA256 | RFC 5869 |
| **Encryption** | AES-256-GCM | NIST SP 800-38D |
| **Random Generation** | Python secrets (CSPRNG) | PEP 506 |

**Key Security Features**:
- ✅ Master password never stored (only Argon2id hash)
- ✅ Encryption keys exist only in memory during operations
- ✅ Unique nonce for every encryption operation
- ✅ Authenticated encryption prevents tampering
- ✅ File permissions set to 600 (owner only)
- ✅ Two-tier key system (authentication + encryption)

For detailed security analysis, see [docs/SECURITY.md](docs/SECURITY.md).

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Step 1: Clone the Repository

```bash
git clone https://github.com/Ahpatsum15/secureVault.git
cd secureVault
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install secureVault

```bash
# Install in development mode
pip install -e .
```

### Step 5: Verify Installation

```bash
securevault --version
```

You should see: `securevault, version 1.0.0`

---

## 🚀 Quick Start

### 1. Initialize Your Vault

```bash
securevault init
```

You'll be prompted to create a **master password**. Choose a strong, memorable password - it cannot be recovered if forgotten!

### 2. Add Your First Password

```bash
# Add with manual password
securevault add -s github.com -u your_username

# Or generate a random password
securevault add -s github.com -u your_username --generate --length 24
```

### 3. Retrieve a Password

```bash
securevault get github.com
```

The password will be copied to your clipboard and automatically cleared after 30 seconds.

### 4. List All Entries

```bash
securevault list
```

### 5. Generate a Password

```bash
# Generate 24-character password
securevault generate --length 24

# Generate passphrase
securevault generate --passphrase --words 6
```

---

## 📖 Usage

### Available Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new password vault |
| `add` | Add a new password entry |
| `get` | Retrieve a password (copies to clipboard) |
| `list` | List all stored services |
| `update` | Update an existing entry |
| `delete` | Delete an entry |
| `generate` | Generate a password without storing |
| `change-master` | Change master password |
| `export` | Export vault to JSON (⚠️ plaintext) |
| `import` | Import entries from JSON |

### Common Examples

```bash
# Add entry with URL and notes
securevault add -s example.com -u admin \
  --url https://example.com \
  --notes "Admin account"

# Generate 32-character password
securevault add -s gitlab.com -u myuser --generate --length 32

# Show password on screen instead of clipboard
securevault get github.com --show

# Search for entries
securevault list --search git

# Update password
securevault update github.com --generate --length 30

# Delete entry (with confirmation)
securevault delete old-service.com
```

For complete usage guide, see [docs/USAGE.md](docs/USAGE.md).

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
./venv/bin/pytest tests/ -v

# Run with coverage
./venv/bin/pytest tests/ --cov=src --cov-report=term-missing

# Run specific test file
./venv/bin/pytest tests/test_crypto.py -v
```

**Test Coverage**:
- ✅ 65 tests covering all functionality
- ✅ Cryptography (Argon2id, HKDF, AES-256-GCM)
- ✅ Vault operations (CRUD, persistence, master password change)
- ✅ Password generation (passwords, passphrases, entropy)
- ✅ Edge cases and error handling

---

## 📚 Documentation

- **[USAGE.md](docs/USAGE.md)**: Complete usage guide with examples
- **[SECURITY.md](docs/SECURITY.md)**: Detailed security architecture and cryptographic protocols
- **[Implementation Plan](/.gemini/antigravity/brain/0558b9c7-4eb5-4b3d-98bb-8c932ab969a4/implementation_plan.md)**: Original design document

---

## 🔒 Security Best Practices

### For Users

1. **Strong Master Password**: Use 20+ characters or a 6+ word passphrase
2. **Regular Backups**: Backup `~/.securevault/vault.enc` to a secure location
3. **Secure Your System**: Use full-disk encryption and keep software updated
4. **Unique Passwords**: Use generated passwords for each service
5. **Delete Exports**: If you export to JSON, delete the file immediately

### For Developers

1. **Code Review**: All cryptographic code should be reviewed
2. **Dependency Updates**: Keep cryptography libraries updated
3. **Test Coverage**: Maintain comprehensive test suite
4. **Security Audits**: Consider professional security audits for production use

---

## ⚠️ Limitations

This is an **educational project** and has the following limitations:

- ❌ **Not Professionally Audited**: Use at your own risk
- ❌ **No Password Recovery**: If you forget your master password, your vault is lost
- ❌ **Single User**: No multi-user or synchronization features
- ❌ **No Cloud Sync**: Vault is stored locally only
- ❌ **High Memory Requirements**: Argon2id requires 2 GiB RAM

For detailed threat model and limitations, see [docs/SECURITY.md](docs/SECURITY.md).

---

## 🛠️ Technology Stack

- **Language**: Python 3.8+
- **Cryptography**: [cryptography](https://cryptography.io/) library
- **Password Hashing**: [argon2-cffi](https://argon2-cffi.readthedocs.io/)
- **CLI Framework**: [Click](https://click.palletsprojects.com/)
- **Terminal UI**: [Rich](https://rich.readthedocs.io/)
- **Clipboard**: [pyperclip](https://pypi.org/project/pyperclip/)
- **Testing**: [pytest](https://pytest.org/)

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

For security vulnerabilities, please report privately (see [docs/SECURITY.md](docs/SECURITY.md)).

---

## 📧 Contact

**Author**: Ahpatsum15

For questions, suggestions, or security concerns, please open an issue on GitHub.

---

## 🙏 Acknowledgments

- **Argon2 Team**: For the Password Hashing Competition winner
- **Python Cryptography Authority**: For excellent cryptography libraries
- **NIST & IETF**: For cryptographic standards and RFCs
- **Security Community**: For continuous research and best practices

---

## 📖 References

### Standards & Specifications
- [RFC 9106 - Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-38D - GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

### Learning Resources
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Cryptography I - Stanford (Coursera)](https://www.coursera.org/learn/crypto)
- [The Cryptopals Crypto Challenges](https://cryptopals.com/)

For more resources, see [docs/SECURITY.md](docs/SECURITY.md).

---

**⭐ If you find this project useful, please consider giving it a star!**
