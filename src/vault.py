"""
Vault storage and management module.

Handles encrypted storage of password entries, vault initialization,
and CRUD operations on the vault.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, UTC
from dataclasses import dataclass, asdict
import base64

from . import crypto


# Default vault location
DEFAULT_VAULT_DIR = Path.home() / ".securevault"
DEFAULT_VAULT_FILE = DEFAULT_VAULT_DIR / "vault.enc"
VAULT_VERSION = "1.0"


@dataclass
class VaultEntry:
    """Represents a single password entry in the vault."""
    service: str
    username: str
    password: str  # Will be encrypted when stored
    url: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VaultEntry':
        """Create VaultEntry from dictionary."""
        return cls(**data)


@dataclass
class VaultMetadata:
    """Metadata for the vault."""
    version: str
    salt: str  # Base64 encoded
    master_hash: str  # Argon2id hash of master password
    created_at: str
    modified_at: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VaultMetadata':
        """Create VaultMetadata from dictionary."""
        return cls(**data)


class Vault:
    """
    Manages the encrypted password vault.
    
    The vault stores encrypted password entries and metadata.
    Each entry's password is encrypted individually with a unique nonce.
    """
    
    def __init__(self, vault_path: Path = DEFAULT_VAULT_FILE):
        """
        Initialize vault manager.
        
        Args:
            vault_path: Path to the vault file
        """
        self.vault_path = vault_path
        self.metadata: Optional[VaultMetadata] = None
        self.entries: List[Dict[str, Any]] = []  # Encrypted entries
        self._encryption_key: Optional[bytes] = None
    
    def initialize(self, master_password: str) -> None:
        """
        Initialize a new vault with a master password.
        
        Args:
            master_password: The master password for the vault
            
        Raises:
            FileExistsError: If vault already exists
        """
        if self.vault_path.exists():
            raise FileExistsError(f"Vault already exists at {self.vault_path}")
        
        # Create vault directory if it doesn't exist
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate salt for key derivation
        salt = crypto.generate_salt()
        
        # Hash master password for authentication
        master_hash = crypto.hash_master_key(master_password)
        
        # Create metadata
        now = datetime.now(UTC).isoformat()
        self.metadata = VaultMetadata(
            version=VAULT_VERSION,
            salt=base64.b64encode(salt).decode('utf-8'),
            master_hash=master_hash,
            created_at=now,
            modified_at=now
        )
        
        # Initialize empty entries list
        self.entries = []
        
        # Save vault
        self._save()
        
        # Set file permissions to 600 (owner read/write only)
        os.chmod(self.vault_path, 0o600)
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock the vault with the master password.
        
        Args:
            master_password: The master password
            
        Returns:
            True if unlocked successfully, False otherwise
            
        Raises:
            FileNotFoundError: If vault doesn't exist
        """
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault not found at {self.vault_path}")
        
        # Load vault
        self._load()
        
        # Verify master password
        if not crypto.verify_master_key(self.metadata.master_hash, master_password):
            self._encryption_key = None
            return False
        
        # Derive encryption key
        salt = base64.b64decode(self.metadata.salt)
        self._encryption_key = crypto.derive_encryption_key(master_password, salt)
        
        return True
    
    def lock(self) -> None:
        """Lock the vault by clearing the encryption key from memory."""
        self._encryption_key = None
        self.entries = []
        self.metadata = None
    
    def is_unlocked(self) -> bool:
        """Check if vault is currently unlocked."""
        return self._encryption_key is not None
    
    def add_entry(self, entry: VaultEntry) -> None:
        """
        Add a new entry to the vault.
        
        Args:
            entry: The entry to add
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        # Set timestamps
        now = datetime.now(UTC).isoformat()
        entry.created_at = now
        entry.updated_at = now
        
        # Encrypt password
        encrypted_entry = self._encrypt_entry(entry)
        
        # Add to entries
        self.entries.append(encrypted_entry)
        
        # Update metadata
        self.metadata.modified_at = now
        
        # Save vault
        self._save()
    
    def get_entry(self, service: str, username: Optional[str] = None) -> Optional[VaultEntry]:
        """
        Retrieve an entry from the vault.
        
        Args:
            service: Service name to search for
            username: Optional username to filter by
            
        Returns:
            Decrypted VaultEntry if found, None otherwise
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        for encrypted_entry in self.entries:
            # Decrypt to check service/username
            entry = self._decrypt_entry(encrypted_entry)
            
            if entry.service.lower() == service.lower():
                if username is None or entry.username.lower() == username.lower():
                    return entry
        
        return None
    
    def list_entries(self, search: Optional[str] = None) -> List[Dict[str, str]]:
        """
        List all entries (service and username only, no passwords).
        
        Args:
            search: Optional search term to filter services
            
        Returns:
            List of dictionaries with service, username, and url
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        results = []
        for encrypted_entry in self.entries:
            entry = self._decrypt_entry(encrypted_entry)
            
            # Filter by search term if provided
            if search and search.lower() not in entry.service.lower():
                continue
            
            results.append({
                "service": entry.service,
                "username": entry.username,
                "url": entry.url or ""
            })
        
        return results
    
    def update_entry(self, service: str, username: Optional[str], updated_entry: VaultEntry) -> bool:
        """
        Update an existing entry.
        
        Args:
            service: Service name to find
            username: Username to find (optional)
            updated_entry: New entry data
            
        Returns:
            True if updated, False if not found
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        for i, encrypted_entry in enumerate(self.entries):
            entry = self._decrypt_entry(encrypted_entry)
            
            if entry.service.lower() == service.lower():
                if username is None or entry.username.lower() == username.lower():
                    # Preserve created_at, update updated_at
                    updated_entry.created_at = entry.created_at
                    updated_entry.updated_at = datetime.now(UTC).isoformat()
                    
                    # Encrypt and replace
                    self.entries[i] = self._encrypt_entry(updated_entry)
                    
                    # Update metadata
                    self.metadata.modified_at = updated_entry.updated_at
                    
                    # Save vault
                    self._save()
                    return True
        
        return False
    
    def delete_entry(self, service: str, username: Optional[str] = None) -> bool:
        """
        Delete an entry from the vault.
        
        Args:
            service: Service name to find
            username: Username to find (optional)
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        for i, encrypted_entry in enumerate(self.entries):
            entry = self._decrypt_entry(encrypted_entry)
            
            if entry.service.lower() == service.lower():
                if username is None or entry.username.lower() == username.lower():
                    # Remove entry
                    self.entries.pop(i)
                    
                    # Update metadata
                    self.metadata.modified_at = datetime.now(UTC).isoformat()
                    
                    # Save vault
                    self._save()
                    return True
        
        return False
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password and re-encrypt all entries.
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Returns:
            True if successful, False if old password is incorrect
        """
        # Verify old password
        if not crypto.verify_master_key(self.metadata.master_hash, old_password):
            return False
        
        # Decrypt all entries with old key
        decrypted_entries = []
        for encrypted_entry in self.entries:
            decrypted_entries.append(self._decrypt_entry(encrypted_entry))
        
        # Generate new salt and hash
        new_salt = crypto.generate_salt()
        new_hash = crypto.hash_master_key(new_password)
        
        # Update metadata
        self.metadata.salt = base64.b64encode(new_salt).decode('utf-8')
        self.metadata.master_hash = new_hash
        self.metadata.modified_at = datetime.now(UTC).isoformat()
        
        # Derive new encryption key
        self._encryption_key = crypto.derive_encryption_key(new_password, new_salt)
        
        # Re-encrypt all entries with new key
        self.entries = []
        for entry in decrypted_entries:
            self.entries.append(self._encrypt_entry(entry))
        
        # Save vault
        self._save()
        
        return True
    
    def export_unencrypted(self) -> List[Dict[str, Any]]:
        """
        Export all entries in unencrypted format.
        
        WARNING: This exports passwords in plaintext!
        
        Returns:
            List of entry dictionaries
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        return [self._decrypt_entry(e).to_dict() for e in self.entries]
    
    def import_entries(self, entries_data: List[Dict[str, Any]]) -> int:
        """
        Import entries from unencrypted data.
        
        Args:
            entries_data: List of entry dictionaries
            
        Returns:
            Number of entries imported
            
        Raises:
            RuntimeError: If vault is not unlocked
        """
        if not self.is_unlocked():
            raise RuntimeError("Vault is locked")
        
        count = 0
        for entry_dict in entries_data:
            entry = VaultEntry.from_dict(entry_dict)
            
            # Set timestamps if not present
            now = datetime.now(UTC).isoformat()
            if not entry.created_at:
                entry.created_at = now
            if not entry.updated_at:
                entry.updated_at = now
            
            # Encrypt and add
            self.entries.append(self._encrypt_entry(entry))
            count += 1
        
        # Update metadata
        self.metadata.modified_at = datetime.now(UTC).isoformat()
        
        # Save vault
        self._save()
        
        return count
    
    def _encrypt_entry(self, entry: VaultEntry) -> Dict[str, Any]:
        """
        Encrypt an entry's password field.
        
        Args:
            entry: The entry to encrypt
            
        Returns:
            Dictionary with encrypted password
        """
        # Encrypt password
        ciphertext, nonce = crypto.encrypt_data(entry.password, self._encryption_key)
        
        # Create encrypted entry dict
        encrypted = entry.to_dict()
        encrypted['password'] = base64.b64encode(ciphertext).decode('utf-8')
        encrypted['nonce'] = base64.b64encode(nonce).decode('utf-8')
        
        return encrypted
    
    def _decrypt_entry(self, encrypted_entry: Dict[str, Any]) -> VaultEntry:
        """
        Decrypt an entry's password field.
        
        Args:
            encrypted_entry: Dictionary with encrypted password
            
        Returns:
            Decrypted VaultEntry
        """
        # Decode encrypted data
        ciphertext = base64.b64decode(encrypted_entry['password'])
        nonce = base64.b64decode(encrypted_entry['nonce'])
        
        # Decrypt password
        password = crypto.decrypt_data(ciphertext, nonce, self._encryption_key)
        
        # Create entry (remove nonce from dict)
        entry_dict = encrypted_entry.copy()
        entry_dict['password'] = password
        del entry_dict['nonce']
        
        return VaultEntry.from_dict(entry_dict)
    
    def _save(self) -> None:
        """Save vault to disk."""
        vault_data = {
            "metadata": self.metadata.to_dict(),
            "entries": self.entries
        }
        
        # Write atomically using a temporary file
        temp_path = self.vault_path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            json.dump(vault_data, f, indent=2)
        
        # Atomic rename
        temp_path.replace(self.vault_path)
        
        # Ensure permissions
        os.chmod(self.vault_path, 0o600)
    
    def _load(self) -> None:
        """Load vault from disk."""
        with open(self.vault_path, 'r') as f:
            vault_data = json.load(f)
        
        self.metadata = VaultMetadata.from_dict(vault_data['metadata'])
        self.entries = vault_data['entries']
