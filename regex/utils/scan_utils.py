import os
import re
from docx import Document
from ..patterns import ALL_REGEX_PATTERNS_BACKEND

# Önceden derlenmiş regex cache'i - Kategorilere göre
compiled_patterns = {}
for category, patterns in ALL_REGEX_PATTERNS_BACKEND.items():
    compiled_patterns[category] = {
        pattern['subcategory']: re.compile(pattern['pattern'], re.IGNORECASE | re.MULTILINE)
        for pattern in patterns
    }

def normalize_path(path):
    """Dosya yolunu normalize eder."""
    return os.path.normpath(path)

def is_safe_path(path):
    """Sadece /mnt/ ile başlayan yolları güvenli kabul eder."""
    return path.startswith('/mnt/')

# scan_text_file ve scan_docx_file fonksiyonlarını kaldırıyorum.
# ... existing code ... 