"""
Configuration management for secureVault.
"""

from pathlib import Path
from typing import Optional


class Config:
    """Configuration settings for secureVault."""
    
    # Vault settings
    VAULT_DIR: Path = Path.home() / ".securevault"
    VAULT_FILE: Path = VAULT_DIR / "vault.enc"
    
    # Clipboard settings
    CLIPBOARD_TIMEOUT: int = 30  # seconds
    
    # Password generation defaults
    DEFAULT_PASSWORD_LENGTH: int = 20
    DEFAULT_PASSPHRASE_WORDS: int = 6
    DEFAULT_PASSPHRASE_SEPARATOR: str = "-"
    
    # Display settings
    SHOW_ENTROPY: bool = True
    
    @classmethod
    def get_vault_path(cls, custom_path: Optional[str] = None) -> Path:
        """
        Get the vault file path.
        
        Args:
            custom_path: Optional custom vault path
            
        Returns:
            Path to vault file
        """
        if custom_path:
            return Path(custom_path)
        return cls.VAULT_FILE
