# secureVault - Usage Guide

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Ahpatsum15/secureVault.git
   cd secureVault
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install secureVault**:
   ```bash
   pip install -e .
   ```

## Quick Start

### 1. Initialize Your Vault

```bash
securevault init
```

You'll be prompted to create a master password. **Choose a strong, memorable password - it cannot be recovered if forgotten!**

### 2. Add a Password

```bash
securevault add -s github.com -u your_username
```

You can also generate a random password:

```bash
securevault add -s github.com -u your_username --generate --length 24
```

### 3. Retrieve a Password

```bash
securevault get github.com
```

The password will be copied to your clipboard and cleared after 30 seconds.

### 4. List All Entries

```bash
securevault list
```

Filter by search term:

```bash
securevault list --search git
```

## Command Reference

### `init` - Initialize a new vault

```bash
securevault init [--vault-path PATH]
```

Creates a new encrypted vault file at `~/.securevault/vault.enc` (or custom path).

### `add` - Add a new password entry

```bash
securevault add [OPTIONS]
```

**Options:**
- `-s, --service TEXT`: Service name (required)
- `-u, --username TEXT`: Username or email (required)
- `-p, --password TEXT`: Password (optional, will prompt if not provided)
- `-g, --generate`: Generate a random password
- `-l, --length INTEGER`: Password length for generation (default: 20)
- `--url TEXT`: Service URL
- `--notes TEXT`: Additional notes

**Examples:**
```bash
# Add with manual password
securevault add -s github.com -u myuser -p MySecretPass123

# Generate a 32-character password
securevault add -s gitlab.com -u myuser --generate --length 32

# Add with URL and notes
securevault add -s example.com -u admin --url https://example.com --notes "Admin account"
```

### `get` - Retrieve a password

```bash
securevault get SERVICE [OPTIONS]
```

**Options:**
- `-u, --username TEXT`: Username (if multiple entries for service)
- `-s, --show`: Show password on screen
- `--no-copy`: Don't copy to clipboard

**Examples:**
```bash
# Get password (copies to clipboard)
securevault get github.com

# Show password on screen
securevault get github.com --show

# Get specific username
securevault get github.com -u myuser
```

### `list` - List all stored services

```bash
securevault list [OPTIONS]
```

**Options:**
- `-s, --search TEXT`: Filter by service name

**Examples:**
```bash
# List all entries
securevault list

# Search for specific services
securevault list --search github
```

### `update` - Update an existing entry

```bash
securevault update SERVICE [OPTIONS]
```

**Options:**
- `-u, --username TEXT`: Username (if multiple entries)
- `-p, --new-password TEXT`: New password
- `-g, --generate`: Generate new password
- `-l, --length INTEGER`: Password length for generation
- `--new-username TEXT`: New username
- `--new-url TEXT`: New URL
- `--new-notes TEXT`: New notes

**Examples:**
```bash
# Update password
securevault update github.com -p NewPassword123

# Generate new password
securevault update github.com --generate --length 30

# Update multiple fields
securevault update github.com --new-username newuser --new-url https://github.com
```

### `delete` - Delete an entry

```bash
securevault delete SERVICE [OPTIONS]
```

**Options:**
- `-u, --username TEXT`: Username (if multiple entries)

**Examples:**
```bash
# Delete entry (will ask for confirmation)
securevault delete github.com
```

### `generate` - Generate a password without storing

```bash
securevault generate [OPTIONS]
```

**Options:**
- `-l, --length INTEGER`: Password length (default: 20)
- `--no-lowercase`: Exclude lowercase letters
- `--no-uppercase`: Exclude uppercase letters
- `--no-digits`: Exclude digits
- `--no-special`: Exclude special characters
- `-pp, --passphrase`: Generate passphrase instead
- `-w, --words INTEGER`: Number of words in passphrase (default: 6)

**Examples:**
```bash
# Generate 24-character password
securevault generate --length 24

# Generate password without special characters
securevault generate --length 20 --no-special

# Generate passphrase
securevault generate --passphrase --words 5
```

### `change-master` - Change master password

```bash
securevault change-master
```

Re-encrypts all entries with a new master password.

### `export` - Export vault to JSON

```bash
securevault export OUTPUT_FILE
```

**⚠️ WARNING:** Exports passwords in **plaintext**! Use with caution.

**Example:**
```bash
securevault export backup.json
```

### `import` - Import entries from JSON

```bash
securevault import INPUT_FILE
```

**Example:**
```bash
securevault import backup.json
```

## Security Best Practices

1. **Strong Master Password**: Use a long, unique master password. Consider using a passphrase.

2. **Backup Your Vault**: Regularly backup `~/.securevault/vault.enc` to a secure location.

3. **Never Share Master Password**: Your master password should never be shared or written down.

4. **Secure Your System**: Keep your operating system and software updated.

5. **Delete Export Files**: If you export your vault, delete the plaintext file immediately after use.

6. **Use Generated Passwords**: Let secureVault generate strong, unique passwords for each service.

## Troubleshooting

### Clipboard not working

If clipboard functionality doesn't work, install clipboard support:

- **Linux**: `sudo apt-get install xclip` or `sudo apt-get install xsel`
- **macOS**: Should work out of the box
- **Windows**: Should work out of the box

Alternatively, use `--show` flag to display passwords on screen:

```bash
securevault get github.com --show
```

### Forgot master password

Unfortunately, there is no way to recover your master password. This is by design for security. You will need to:

1. Delete the old vault
2. Initialize a new vault
3. Re-add your passwords (if you have backups)

### Vault file corrupted

If your vault file is corrupted:

1. Restore from backup if available
2. If no backup, the vault cannot be recovered

Always keep backups of `~/.securevault/vault.enc`!

## Advanced Usage

### Custom Vault Location

You can use a custom vault location with the `--vault-path` option:

```bash
securevault init --vault-path /path/to/my/vault.enc
securevault add --vault-path /path/to/my/vault.enc -s github.com -u myuser
```

### Scripting

You can use secureVault in scripts by providing passwords via command-line arguments:

```bash
# Add entry with password in command
securevault add -s example.com -u user -p "MyPassword123"

# Generate and add
securevault add -s example.com -u user --generate --length 32
```

**Note**: Be careful with passwords in command-line arguments as they may be visible in shell history.

## Technical Details

### Cryptographic Primitives

- **Master Password Hashing**: Argon2id (RFC 9106) with 2 GiB memory cost
- **Key Derivation**: HKDF with SHA-256
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Random Generation**: Python's `secrets` module (CSPRNG)

### Storage Format

The vault is stored as JSON with:
- Metadata (version, salt, master password hash, timestamps)
- Encrypted entries (each with unique nonce)

Each password is encrypted individually with AES-256-GCM, providing:
- Confidentiality (encryption)
- Integrity (authentication tag)
- Unique nonce per encryption

### File Permissions

The vault file is automatically set to mode 600 (owner read/write only) for security.
