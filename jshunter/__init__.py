"""jshunter package."""
from .hunter import hunt
from .patterns import scan_text, PATTERNS
from .endpoints import extract_endpoints

__version__ = "0.1.0"
__all__ = ["hunt", "scan_text", "PATTERNS", "extract_endpoints"]
