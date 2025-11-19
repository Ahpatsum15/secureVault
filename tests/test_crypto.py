"""
Tests for cryptographic functions.
"""

import pytest
from src import crypto


class TestMasterPasswordFunctions:
    """Test Argon2id master password hashing and verification."""
    
    def test_hash_master_key(self):
        """Test that hashing produces a valid Argon2id hash."""
        password = "test_password_123"
        hash_result = crypto.hash_master_key(password)
        
        # Check it's a string
        assert isinstance(hash_result, str)
        # Check it starts with Argon2id identifier
        assert hash_result.startswith("$argon2id$")
    
    def test_hash_master_key_different_hashes(self):
        """Test that same password produces different hashes (due to random salt)."""
        password = "test_password_123"
        hash1 = crypto.hash_master_key(password)
        hash2 = crypto.hash_master_key(password)
        
        # Different hashes due to different salts
        assert hash1 != hash2
    
    def test_verify_master_key_correct(self):
        """Test verification with correct password."""
        password = "test_password_123"
        hash_result = crypto.hash_master_key(password)
        
        assert crypto.verify_master_key(hash_result, password) is True
    
    def test_verify_master_key_incorrect(self):
        """Test verification with incorrect password."""
        password = "test_password_123"
        wrong_password = "wrong_password"
        hash_result = crypto.hash_master_key(password)
        
        assert crypto.verify_master_key(hash_result, wrong_password) is False
    
    def test_hash_master_key_type_error(self):
        """Test that non-string input raises TypeError."""
        with pytest.raises(TypeError):
            crypto.hash_master_key(12345)


class TestKeyDerivation:
    """Test HKDF key derivation functions."""
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt = crypto.generate_salt()
        
        assert isinstance(salt, bytes)
        assert len(salt) == crypto.SALT_LENGTH
    
    def test_generate_salt_uniqueness(self):
        """Test that generated salts are unique."""
        salt1 = crypto.generate_salt()
        salt2 = crypto.generate_salt()
        
        assert salt1 != salt2
    
    def test_derive_encryption_key(self):
        """Test key derivation from password and salt."""
        password = "test_password_123"
        salt = crypto.generate_salt()
        
        key = crypto.derive_encryption_key(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == crypto.KEY_LENGTH
    
    def test_derive_encryption_key_deterministic(self):
        """Test that same password and salt produce same key."""
        password = "test_password_123"
        salt = crypto.generate_salt()
        
        key1 = crypto.derive_encryption_key(password, salt)
        key2 = crypto.derive_encryption_key(password, salt)
        
        assert key1 == key2
    
    def test_derive_encryption_key_different_salts(self):
        """Test that different salts produce different keys."""
        password = "test_password_123"
        salt1 = crypto.generate_salt()
        salt2 = crypto.generate_salt()
        
        key1 = crypto.derive_encryption_key(password, salt1)
        key2 = crypto.derive_encryption_key(password, salt2)
        
        assert key1 != key2
    
    def test_derive_encryption_key_wrong_salt_length(self):
        """Test that wrong salt length raises ValueError."""
        password = "test_password_123"
        wrong_salt = b"short"
        
        with pytest.raises(ValueError):
            crypto.derive_encryption_key(password, wrong_salt)


class TestEncryptionDecryption:
    """Test AES-256-GCM encryption and decryption."""
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = crypto.generate_nonce()
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == crypto.NONCE_LENGTH
    
    def test_generate_nonce_uniqueness(self):
        """Test that generated nonces are unique."""
        nonce1 = crypto.generate_nonce()
        nonce2 = crypto.generate_nonce()
        
        assert nonce1 != nonce2
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption round-trip."""
        plaintext = "This is a secret password!"
        key = crypto.generate_salt()[:crypto.KEY_LENGTH]  # Use salt as key for testing
        
        ciphertext, nonce = crypto.encrypt_data(plaintext, key)
        decrypted = crypto.decrypt_data(ciphertext, nonce, key)
        
        assert decrypted == plaintext
    
    def test_encrypt_produces_different_ciphertext(self):
        """Test that encrypting same plaintext produces different ciphertext (unique nonces)."""
        plaintext = "This is a secret password!"
        key = crypto.generate_salt()[:crypto.KEY_LENGTH]
        
        ciphertext1, nonce1 = crypto.encrypt_data(plaintext, key)
        ciphertext2, nonce2 = crypto.encrypt_data(plaintext, key)
        
        # Different nonces
        assert nonce1 != nonce2
        # Different ciphertexts
        assert ciphertext1 != ciphertext2
    
    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        plaintext = "This is a secret password!"
        key1 = crypto.generate_salt()[:crypto.KEY_LENGTH]
        key2 = crypto.generate_salt()[:crypto.KEY_LENGTH]
        
        ciphertext, nonce = crypto.encrypt_data(plaintext, key1)
        
        # Should raise exception (authentication failure)
        with pytest.raises(Exception):
            crypto.decrypt_data(ciphertext, nonce, key2)
    
    def test_decrypt_with_tampered_ciphertext_fails(self):
        """Test that decryption with tampered ciphertext fails."""
        plaintext = "This is a secret password!"
        key = crypto.generate_salt()[:crypto.KEY_LENGTH]
        
        ciphertext, nonce = crypto.encrypt_data(plaintext, key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits
        tampered = bytes(tampered)
        
        # Should raise exception (authentication failure)
        with pytest.raises(Exception):
            crypto.decrypt_data(tampered, nonce, key)
    
    def test_encrypt_wrong_key_length(self):
        """Test that wrong key length raises ValueError."""
        plaintext = "This is a secret password!"
        wrong_key = b"short"
        
        with pytest.raises(ValueError):
            crypto.encrypt_data(plaintext, wrong_key)
    
    def test_decrypt_wrong_nonce_length(self):
        """Test that wrong nonce length raises ValueError."""
        ciphertext = b"encrypted"
        key = crypto.generate_salt()[:crypto.KEY_LENGTH]
        wrong_nonce = b"short"
        
        with pytest.raises(ValueError):
            crypto.decrypt_data(ciphertext, wrong_nonce, key)


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        a = b"test_value_123"
        b = b"test_value_123"
        
        assert crypto.constant_time_compare(a, b) is True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison with different values."""
        a = b"test_value_123"
        b = b"different_value"
        
        assert crypto.constant_time_compare(a, b) is False
