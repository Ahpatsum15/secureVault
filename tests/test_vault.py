"""
Tests for vault storage and management.
"""

import pytest
import tempfile
import os
from pathlib import Path
from src.vault import Vault, VaultEntry


@pytest.fixture
def temp_vault_path():
    """Create a temporary vault file path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_vault.enc"


@pytest.fixture
def initialized_vault(temp_vault_path):
    """Create and initialize a vault."""
    vault = Vault(temp_vault_path)
    vault.initialize("test_master_password_123")
    return vault


class TestVaultInitialization:
    """Test vault initialization."""
    
    def test_initialize_vault(self, temp_vault_path):
        """Test creating a new vault."""
        vault = Vault(temp_vault_path)
        vault.initialize("test_master_password_123")
        
        # Check vault file exists
        assert temp_vault_path.exists()
        
        # Check file permissions (600)
        stat_info = os.stat(temp_vault_path)
        permissions = oct(stat_info.st_mode)[-3:]
        assert permissions == "600"
    
    def test_initialize_vault_already_exists(self, initialized_vault, temp_vault_path):
        """Test that initializing existing vault raises error."""
        vault = Vault(temp_vault_path)
        
        with pytest.raises(FileExistsError):
            vault.initialize("another_password")
    
    def test_unlock_vault_correct_password(self, initialized_vault, temp_vault_path):
        """Test unlocking vault with correct password."""
        vault = Vault(temp_vault_path)
        
        assert vault.unlock("test_master_password_123") is True
        assert vault.is_unlocked() is True
    
    def test_unlock_vault_wrong_password(self, initialized_vault, temp_vault_path):
        """Test unlocking vault with wrong password."""
        vault = Vault(temp_vault_path)
        
        assert vault.unlock("wrong_password") is False
        assert vault.is_unlocked() is False
    
    def test_lock_vault(self, initialized_vault, temp_vault_path):
        """Test locking vault."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        assert vault.is_unlocked() is True
        
        vault.lock()
        
        assert vault.is_unlocked() is False


class TestVaultEntries:
    """Test vault entry operations."""
    
    def test_add_entry(self, initialized_vault, temp_vault_path):
        """Test adding an entry to vault."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        entry = VaultEntry(
            service="github.com",
            username="testuser",
            password="secret_password_123",
            url="https://github.com",
            notes="My GitHub account"
        )
        
        vault.add_entry(entry)
        
        # Verify entry was added
        retrieved = vault.get_entry("github.com")
        assert retrieved is not None
        assert retrieved.service == "github.com"
        assert retrieved.username == "testuser"
        assert retrieved.password == "secret_password_123"
        assert retrieved.url == "https://github.com"
        assert retrieved.notes == "My GitHub account"
    
    def test_add_entry_vault_locked(self, initialized_vault, temp_vault_path):
        """Test that adding entry to locked vault raises error."""
        vault = Vault(temp_vault_path)
        # Don't unlock
        
        entry = VaultEntry(
            service="github.com",
            username="testuser",
            password="secret_password_123"
        )
        
        with pytest.raises(RuntimeError):
            vault.add_entry(entry)
    
    def test_get_entry_not_found(self, initialized_vault, temp_vault_path):
        """Test getting non-existent entry."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        result = vault.get_entry("nonexistent.com")
        assert result is None
    
    def test_get_entry_case_insensitive(self, initialized_vault, temp_vault_path):
        """Test that service search is case-insensitive."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        entry = VaultEntry(
            service="GitHub.com",
            username="testuser",
            password="secret_password_123"
        )
        vault.add_entry(entry)
        
        # Search with different case
        retrieved = vault.get_entry("github.com")
        assert retrieved is not None
        assert retrieved.service == "GitHub.com"
    
    def test_list_entries(self, initialized_vault, temp_vault_path):
        """Test listing all entries."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add multiple entries
        vault.add_entry(VaultEntry("github.com", "user1", "pass1"))
        vault.add_entry(VaultEntry("gitlab.com", "user2", "pass2"))
        vault.add_entry(VaultEntry("bitbucket.org", "user3", "pass3"))
        
        entries = vault.list_entries()
        
        assert len(entries) == 3
        services = [e['service'] for e in entries]
        assert "github.com" in services
        assert "gitlab.com" in services
        assert "bitbucket.org" in services
    
    def test_list_entries_with_search(self, initialized_vault, temp_vault_path):
        """Test listing entries with search filter."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        vault.add_entry(VaultEntry("github.com", "user1", "pass1"))
        vault.add_entry(VaultEntry("gitlab.com", "user2", "pass2"))
        vault.add_entry(VaultEntry("bitbucket.org", "user3", "pass3"))
        
        entries = vault.list_entries(search="git")
        
        assert len(entries) == 2
        services = [e['service'] for e in entries]
        assert "github.com" in services
        assert "gitlab.com" in services
        assert "bitbucket.org" not in services
    
    def test_update_entry(self, initialized_vault, temp_vault_path):
        """Test updating an entry."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add entry
        vault.add_entry(VaultEntry("github.com", "user1", "old_password"))
        
        # Update entry
        updated = VaultEntry("github.com", "user1", "new_password", notes="Updated")
        result = vault.update_entry("github.com", None, updated)
        
        assert result is True
        
        # Verify update
        retrieved = vault.get_entry("github.com")
        assert retrieved.password == "new_password"
        assert retrieved.notes == "Updated"
    
    def test_update_entry_not_found(self, initialized_vault, temp_vault_path):
        """Test updating non-existent entry."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        updated = VaultEntry("nonexistent.com", "user", "password")
        result = vault.update_entry("nonexistent.com", None, updated)
        
        assert result is False
    
    def test_delete_entry(self, initialized_vault, temp_vault_path):
        """Test deleting an entry."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add entry
        vault.add_entry(VaultEntry("github.com", "user1", "password"))
        
        # Delete entry
        result = vault.delete_entry("github.com")
        
        assert result is True
        
        # Verify deletion
        retrieved = vault.get_entry("github.com")
        assert retrieved is None
    
    def test_delete_entry_not_found(self, initialized_vault, temp_vault_path):
        """Test deleting non-existent entry."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        result = vault.delete_entry("nonexistent.com")
        
        assert result is False


class TestVaultPersistence:
    """Test vault persistence and reloading."""
    
    def test_vault_persists_after_lock(self, initialized_vault, temp_vault_path):
        """Test that entries persist after locking and unlocking."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add entry
        vault.add_entry(VaultEntry("github.com", "user1", "password123"))
        vault.lock()
        
        # Unlock again
        vault.unlock("test_master_password_123")
        
        # Verify entry still exists
        retrieved = vault.get_entry("github.com")
        assert retrieved is not None
        assert retrieved.password == "password123"
    
    def test_vault_persists_across_instances(self, initialized_vault, temp_vault_path):
        """Test that entries persist across different vault instances."""
        # First instance
        vault1 = Vault(temp_vault_path)
        vault1.unlock("test_master_password_123")
        vault1.add_entry(VaultEntry("github.com", "user1", "password123"))
        vault1.lock()
        
        # Second instance
        vault2 = Vault(temp_vault_path)
        vault2.unlock("test_master_password_123")
        
        # Verify entry exists
        retrieved = vault2.get_entry("github.com")
        assert retrieved is not None
        assert retrieved.password == "password123"


class TestMasterPasswordChange:
    """Test changing master password."""
    
    def test_change_master_password(self, initialized_vault, temp_vault_path):
        """Test changing master password."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add entry
        vault.add_entry(VaultEntry("github.com", "user1", "password123"))
        
        # Change master password
        vault._load()  # Reload to get metadata
        result = vault.change_master_password("test_master_password_123", "new_master_password_456")
        
        assert result is True
        
        # Verify old password doesn't work
        vault2 = Vault(temp_vault_path)
        assert vault2.unlock("test_master_password_123") is False
        
        # Verify new password works
        assert vault2.unlock("new_master_password_456") is True
        
        # Verify entry still accessible
        retrieved = vault2.get_entry("github.com")
        assert retrieved is not None
        assert retrieved.password == "password123"
    
    def test_change_master_password_wrong_old(self, initialized_vault, temp_vault_path):
        """Test changing master password with wrong old password."""
        vault = Vault(temp_vault_path)
        vault._load()
        
        result = vault.change_master_password("wrong_password", "new_password")
        
        assert result is False


class TestImportExport:
    """Test import and export functionality."""
    
    def test_export_unencrypted(self, initialized_vault, temp_vault_path):
        """Test exporting entries in unencrypted format."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Add entries
        vault.add_entry(VaultEntry("github.com", "user1", "pass1"))
        vault.add_entry(VaultEntry("gitlab.com", "user2", "pass2"))
        
        # Export
        exported = vault.export_unencrypted()
        
        assert len(exported) == 2
        assert any(e['service'] == 'github.com' for e in exported)
        assert any(e['service'] == 'gitlab.com' for e in exported)
    
    def test_import_entries(self, initialized_vault, temp_vault_path):
        """Test importing entries."""
        vault = Vault(temp_vault_path)
        vault.unlock("test_master_password_123")
        
        # Import data
        import_data = [
            {
                "service": "github.com",
                "username": "user1",
                "password": "pass1",
                "url": "https://github.com",
                "notes": "Test"
            },
            {
                "service": "gitlab.com",
                "username": "user2",
                "password": "pass2",
                "url": None,
                "notes": None
            }
        ]
        
        count = vault.import_entries(import_data)
        
        assert count == 2
        
        # Verify entries
        assert vault.get_entry("github.com") is not None
        assert vault.get_entry("gitlab.com") is not None
