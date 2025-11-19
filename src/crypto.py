# Import
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from typing import Tuple
import secrets
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Parameters from RFC 9106, this is the highest values possible. 
# Quite possible I need to tweak it to not have some problem, but from security standpoint this is good!
RFC_9106_HIGH_MEMORY = {
    "type": Type.ID,
    "salt_len": 16,
    "hash_len": 32,
    "time_cost": 1,
    "memory_cost": 2097152,  # 2 GiB
    "parallelism": 4,
}

ph = PasswordHasher(**RFC_9106_HIGH_MEMORY)  # PasswordHasher function will always use the parameters cited above

# Constants for cryptographic operations
SALT_LENGTH = 32  # 256 bits for HKDF salt
NONCE_LENGTH = 12  # 96 bits for AES-GCM nonce (recommended)
KEY_LENGTH = 32  # 256 bits for AES-256


# ============================================================================
# Master Password Functions (Argon2id)
# ============================================================================

def hash_master_key(password: str) -> str:
    """
    Hash the master password using Argon2id.
    
    Args:
        password: The master password to hash
        
    Returns:
        Encoded hash string containing salt and hash
        
    Raises:
        TypeError: If password is not a string
    """
    if not isinstance(password, str):
        raise TypeError("Master key must be a str")
    return ph.hash(password)


def verify_master_key(encoded_hash: str, password: str) -> bool:
    """
    Verify that the password matches the encoded hash.
    
    Args:
        encoded_hash: The Argon2id encoded hash
        password: The password to verify
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return ph.verify(encoded_hash, password)
    except VerifyMismatchError:
        return False


# ============================================================================
# Key Derivation Functions (HKDF)
# ============================================================================

def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        Random bytes of length SALT_LENGTH
    """
    return secrets.token_bytes(SALT_LENGTH)


def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from the master password using HKDF.
    
    This creates a separate encryption key from the master password,
    following the principle of separation between authentication and encryption.
    
    Args:
        master_password: The master password
        salt: Random salt for key derivation
        
    Returns:
        Derived encryption key of KEY_LENGTH bytes
        
    Raises:
        TypeError: If inputs are of wrong type
        ValueError: If salt is wrong length
    """
    if not isinstance(master_password, str):
        raise TypeError("Master password must be a str")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be {SALT_LENGTH} bytes")
    
    # Convert password to bytes
    password_bytes = master_password.encode('utf-8')
    
    # Use HKDF with SHA-256 to derive encryption key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=b'securevault-encryption-key-v1',  # Context info for key derivation
        backend=default_backend()
    )
    
    return hkdf.derive(password_bytes)


# ============================================================================
# Encryption/Decryption Functions (AES-256-GCM)
# ============================================================================

def generate_nonce() -> bytes:
    """
    Generate a cryptographically secure random nonce for AES-GCM.
    
    Returns:
        Random bytes of length NONCE_LENGTH
    """
    return secrets.token_bytes(NONCE_LENGTH)


def encrypt_data(data: str, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM authenticated encryption.
    
    Args:
        data: The plaintext string to encrypt
        key: The encryption key (must be KEY_LENGTH bytes)
        
    Returns:
        Tuple of (ciphertext, nonce)
        
    Raises:
        TypeError: If inputs are of wrong type
        ValueError: If key is wrong length
    """
    if not isinstance(data, str):
        raise TypeError("Data must be a str")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    
    # Generate unique nonce for this encryption
    nonce = generate_nonce()
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt the data
    plaintext = data.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    return ciphertext, nonce


def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """
    Decrypt data using AES-256-GCM authenticated encryption.
    
    Args:
        ciphertext: The encrypted data
        nonce: The nonce used during encryption
        key: The encryption key (must be KEY_LENGTH bytes)
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        TypeError: If inputs are of wrong type
        ValueError: If key or nonce is wrong length
        cryptography.exceptions.InvalidTag: If authentication fails (data tampered)
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(nonce, bytes):
        raise TypeError("Nonce must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"Nonce must be {NONCE_LENGTH} bytes")
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt and verify authentication tag
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')


# ============================================================================
# Utility Functions
# ============================================================================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    return secrets.compare_digest(a, b)




