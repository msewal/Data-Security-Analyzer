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
    """Güvenli dosya yollarını kontrol eder - Ubuntu subsystem için."""
    # Ubuntu subsystem ve Linux yolları için güvenli dizinleri kontrol et
    safe_prefixes = ['/home/', '/tmp/', '/var/tmp/', '/opt/', '/usr/local/']
    unsafe_prefixes = ['/etc/', '/var/', '/root/', '/proc/', '/sys/', '/dev/', '/boot/', '/bin/', '/sbin/']
    
    # Güvenli ön eklerden biriyle başlıyorsa izin ver
    for prefix in safe_prefixes:
        if path.startswith(prefix):
            return True
    
    # Güvenli olmayan ön eklerden biriyle başlıyorsa reddet
    for prefix in unsafe_prefixes:
        if path.startswith(prefix):
            return False
    
    # Diğer durumlar için false döndür
    return False

# scan_text_file ve scan_docx_file fonksiyonlarını kaldırıyorum.
# ... existing code ... 