"""
Tests for password generation.
"""

import pytest
from src import password_gen


class TestPasswordGeneration:
    """Test password generation functions."""
    
    def test_generate_password_default(self):
        """Test password generation with default settings."""
        password = password_gen.generate_password()
        
        assert isinstance(password, str)
        assert len(password) == 20  # Default length
    
    def test_generate_password_custom_length(self):
        """Test password generation with custom length."""
        password = password_gen.generate_password(length=30)
        
        assert len(password) == 30
    
    def test_generate_password_only_lowercase(self):
        """Test password with only lowercase letters."""
        password = password_gen.generate_password(
            length=50,
            use_lowercase=True,
            use_uppercase=False,
            use_digits=False,
            use_special=False
        )
        
        assert all(c in password_gen.LOWERCASE for c in password)
    
    def test_generate_password_only_uppercase(self):
        """Test password with only uppercase letters."""
        password = password_gen.generate_password(
            length=50,
            use_lowercase=False,
            use_uppercase=True,
            use_digits=False,
            use_special=False
        )
        
        assert all(c in password_gen.UPPERCASE for c in password)
    
    def test_generate_password_only_digits(self):
        """Test password with only digits."""
        password = password_gen.generate_password(
            length=50,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=True,
            use_special=False
        )
        
        assert all(c in password_gen.DIGITS for c in password)
    
    def test_generate_password_mixed(self):
        """Test password with mixed character sets."""
        # Generate many passwords to ensure all character types appear
        for _ in range(10):
            password = password_gen.generate_password(
                length=100,
                use_lowercase=True,
                use_uppercase=True,
                use_digits=True,
                use_special=True
            )
            
            # At least one of each type should appear in a 100-char password
            has_lowercase = any(c in password_gen.LOWERCASE for c in password)
            has_uppercase = any(c in password_gen.UPPERCASE for c in password)
            has_digits = any(c in password_gen.DIGITS for c in password)
            has_special = any(c in password_gen.SPECIAL for c in password)
            
            # With 100 characters, we should get all types
            if has_lowercase and has_uppercase and has_digits and has_special:
                return  # Test passed
        
        # If we get here, something is wrong
        assert False, "Failed to generate password with all character types"
    
    def test_generate_password_no_charset_error(self):
        """Test that generating password with no character sets raises error."""
        with pytest.raises(ValueError):
            password_gen.generate_password(
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=False
            )
    
    def test_generate_password_invalid_length(self):
        """Test that invalid length raises error."""
        with pytest.raises(ValueError):
            password_gen.generate_password(length=0)
    
    def test_generate_password_uniqueness(self):
        """Test that generated passwords are unique."""
        passwords = [password_gen.generate_password() for _ in range(100)]
        
        # All should be unique
        assert len(set(passwords)) == 100


class TestPassphraseGeneration:
    """Test passphrase generation functions."""
    
    def test_generate_passphrase_default(self):
        """Test passphrase generation with default settings."""
        passphrase = password_gen.generate_passphrase()
        
        assert isinstance(passphrase, str)
        # Should have 6 words with 5 separators
        assert passphrase.count("-") == 5
    
    def test_generate_passphrase_custom_words(self):
        """Test passphrase with custom word count."""
        passphrase = password_gen.generate_passphrase(num_words=4)
        
        # Should have 4 words with 3 separators
        assert passphrase.count("-") == 3
    
    def test_generate_passphrase_custom_separator(self):
        """Test passphrase with custom separator."""
        passphrase = password_gen.generate_passphrase(separator=" ")
        
        # Should have spaces as separator
        assert " " in passphrase
        assert "-" not in passphrase
    
    def test_generate_passphrase_custom_wordlist(self):
        """Test passphrase with custom word list."""
        custom_words = ["alpha", "beta", "gamma", "delta"]
        passphrase = password_gen.generate_passphrase(
            num_words=3,
            word_list=custom_words
        )
        
        words = passphrase.split("-")
        assert len(words) == 3
        assert all(word in custom_words for word in words)
    
    def test_generate_passphrase_invalid_num_words(self):
        """Test that invalid word count raises error."""
        with pytest.raises(ValueError):
            password_gen.generate_passphrase(num_words=0)
    
    def test_generate_passphrase_uniqueness(self):
        """Test that generated passphrases are unique."""
        passphrases = [password_gen.generate_passphrase() for _ in range(100)]
        
        # Most should be unique (small chance of collision with limited wordlist)
        unique_count = len(set(passphrases))
        assert unique_count > 90  # At least 90% unique


class TestEntropyCalculation:
    """Test entropy calculation."""
    
    def test_calculate_entropy_empty(self):
        """Test entropy of empty string."""
        entropy = password_gen.calculate_entropy("")
        
        assert entropy == 0.0
    
    def test_calculate_entropy_lowercase_only(self):
        """Test entropy calculation for lowercase-only password."""
        password = "abcdefgh"  # 8 characters, 26 possible
        entropy = password_gen.calculate_entropy(password)
        
        # Entropy = 8 * log2(26) ≈ 37.6
        assert 37 < entropy < 38
    
    def test_calculate_entropy_mixed(self):
        """Test entropy calculation for mixed password."""
        password = "Abc123!@"  # 8 characters, ~88 possible (actual charset)
        entropy = password_gen.calculate_entropy(password)
        
        # Entropy = 8 * log2(88) ≈ 51.7
        assert 51 < entropy < 53
    
    def test_calculate_entropy_custom_charset_size(self):
        """Test entropy with custom charset size."""
        password = "12345678"
        entropy = password_gen.calculate_entropy(password, charset_size=10)
        
        # Entropy = 8 * log2(10) ≈ 26.6
        assert 26 < entropy < 27


class TestCharsetDetection:
    """Test character set detection."""
    
    def test_detect_charset_lowercase(self):
        """Test detection of lowercase charset."""
        size = password_gen._detect_charset_size("abcdefgh")
        
        assert size == 26  # Lowercase letters
    
    def test_detect_charset_uppercase(self):
        """Test detection of uppercase charset."""
        size = password_gen._detect_charset_size("ABCDEFGH")
        
        assert size == 26  # Uppercase letters
    
    def test_detect_charset_digits(self):
        """Test detection of digits charset."""
        size = password_gen._detect_charset_size("12345678")
        
        assert size == 10  # Digits
    
    def test_detect_charset_mixed(self):
        """Test detection of mixed charset."""
        size = password_gen._detect_charset_size("Abc123!@")
        
        # Lowercase (26) + Uppercase (26) + Digits (10) + Special (26 from our set)
        assert size == 88
