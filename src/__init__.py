"""
secureVault - Secure Offline Password Manager

A cryptographically secure, offline password manager using:
- Argon2id for master password hashing (RFC 9106)
- HKDF for key derivation
- AES-256-GCM for authenticated encryption
"""

__version__ = "1.0.0"
__author__ = "Ahpatsum15"

from . import crypto, vault, password_gen, clipboard, config, cli

__all__ = ['crypto', 'vault', 'password_gen', 'clipboard', 'config', 'cli']
