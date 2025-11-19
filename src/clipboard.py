"""
Cross-platform clipboard operations with auto-clear functionality.
"""

import time
import threading
from typing import Optional

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


def copy_to_clipboard(text: str, auto_clear_seconds: Optional[int] = 30) -> bool:
    """
    Copy text to clipboard with optional auto-clear.
    
    Args:
        text: Text to copy to clipboard
        auto_clear_seconds: Seconds before auto-clearing (None to disable)
        
    Returns:
        True if successful, False if clipboard not available
    """
    if not CLIPBOARD_AVAILABLE:
        return False
    
    try:
        pyperclip.copy(text)
        
        # Start auto-clear timer if requested
        if auto_clear_seconds is not None and auto_clear_seconds > 0:
            timer = threading.Timer(auto_clear_seconds, _clear_clipboard, args=[text])
            timer.daemon = True
            timer.start()
        
        return True
    except Exception:
        return False


def _clear_clipboard(original_text: str) -> None:
    """
    Clear clipboard if it still contains the original text.
    
    Args:
        original_text: The text that was originally copied
    """
    try:
        # Only clear if clipboard still contains our text
        current = pyperclip.paste()
        if current == original_text:
            pyperclip.copy('')
    except Exception:
        pass


def is_available() -> bool:
    """
    Check if clipboard functionality is available.
    
    Returns:
        True if clipboard is available, False otherwise
    """
    return CLIPBOARD_AVAILABLE
