import re
import os
from django.conf import settings
from typing import Dict, List, Pattern, Tuple, Optional, Union
from dataclasses import dataclass
from collections import defaultdict

# Ana kategoriler ve alt kategoriler
CATEGORIES = {
    'personal': {
        'name': 'Kişisel Veriler',
        'description': 'Kişisel bilgileri içeren veriler',
        'subcategories': {
            'tc_kimlik': {
                'name': 'TC Kimlik Numarası',
                'description': '11 haneli TC kimlik numarası',
                'patterns': [
                    r'\b[1-9][0-9]{10}\b'
                ]
            },
            'email': {
                'name': 'E-posta Adresi',
                'description': 'Geçerli e-posta adresleri',
                'patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                ]
            },
            'phone': {
                'name': 'Telefon Numarası',
                'description': 'Türkiye telefon numaraları',
                'patterns': [
                    r'\b(?:0|90|\+90)?[ ]?(?:5[0-9]{2}|[1-4][0-9]{2})[ ]?[0-9]{3}[ ]?[0-9]{2}[ ]?[0-9]{2}\b'
                ]
            },
            'address': {
                'name': 'Adres Bilgisi',
                'description': 'Türkiye adres bilgileri',
                'patterns': [
                    r'\b(?:Mahalle|Sokak|Cadde|Bulvar|Avenue|Street|Road|Lane|Boulevard)[\s\w]+(?:No|No:|Numara|Numara:)?[\s\d]+(?:Kat|Daire|Blok|Apt|Apartment)?[\s\d]*\b',
                    r'\b(?:İl|İlçe|Semt|Mahalle)[\s\w]+(?:No|No:|Numara|Numara:)?[\s\d]+(?:Kat|Daire|Blok|Apt|Apartment)?[\s\d]*\b'
                ]
            }
        }
    },
    'financial': {
        'name': 'Finansal Veriler',
        'description': 'Finansal bilgileri içeren veriler',
        'subcategories': {
            'credit_card': {
                'name': 'Kredi Kartı Numarası',
                'description': 'Kredi kartı numaraları',
                'patterns': [
                    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b'
                ]
            },
            'iban': {
                'name': 'IBAN Numarası',
                'description': 'Türkiye IBAN numaraları',
                'patterns': [
                    r'\bTR[0-9]{2}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{2}\b'
                ]
            },
            'bank_account': {
                'name': 'Banka Hesap Numarası',
                'description': 'Banka hesap numaraları',
                'patterns': [
                    r'\b[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}\b'
                ]
            }
        }
    },
    'security': {
        'name': 'Güvenlik Verileri',
        'description': 'Güvenlik bilgilerini içeren veriler',
        'subcategories': {
            'password': {
                'name': 'Şifre',
                'description': 'Şifre bilgileri',
                'patterns': [
                    r'\b(?:password|şifre|parola|sifre)[\s]*[:=][\s]*[\w@#$%^&*()_+\-=\[\]{};\'\\:"|,.<>\/?]{8,}\b'
                ]
            },
            'api_key': {
                'name': 'API Anahtarı',
                'description': 'API anahtarları',
                'patterns': [
                    r'\b(?:api[_-]?key|api[_-]?token|apikey|apitoken)[\s]*[:=][\s]*[a-zA-Z0-9]{32,}\b'
                ]
            },
            'ssh_key': {
                'name': 'SSH Anahtarı',
                'description': 'SSH anahtarları',
                'patterns': [
                    r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
                ]
            }
        }
    },
    'health': {
        'name': 'Sağlık Verileri',
        'description': 'Sağlık bilgilerini içeren veriler',
        'subcategories': {
            'health_insurance': {
                'name': 'Sağlık Sigortası Numarası',
                'description': 'Sağlık sigortası numaraları',
                'patterns': [
                    r'\b[0-9]{11}\b'
                ]
            },
            'medical_record': {
                'name': 'Tıbbi Kayıt Numarası',
                'description': 'Tıbbi kayıt numaraları',
                'patterns': [
                    r'\b(?:Hasta No|Hasta ID|Kayıt No)[\s]*[:=][\s]*[A-Z0-9]{6,}\b'
                ]
            }
        }
    },
    'corporate': {
        'name': 'Kurumsal Veriler',
        'description': 'Kurumsal bilgileri içeren veriler',
        'subcategories': {
            'tax_number': {
                'name': 'Vergi Numarası',
                'description': 'Vergi numaraları',
                'patterns': [
                    r'\b[0-9]{10}\b'
                ]
            },
            'company_registry': {
                'name': 'Şirket Sicil Numarası',
                'description': 'Şirket sicil numaraları',
                'patterns': [
                    r'\b[A-Z]{1}[0-9]{5}\b'
                ]
            },
            'employee_id': {
                'name': 'Çalışan Numarası',
                'description': 'Çalışan numaraları',
                'patterns': [
                    r'\b(?:Çalışan No|Personel No|Employee ID)[\s]*[:=][\s]*[A-Z0-9]{6,}\b'
                ]
            }
        }
    }
}

# Dosya türleri
FILE_TYPES = {
    'text': {
        'name': 'Metin Dosyaları',
        'extensions': ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties']
    },
    'office': {
        'name': 'Ofis & Doküman',
        'extensions': ['docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'pdf']
    },
    'data': {
        'name': 'Tablolar & Veri',
        'extensions': ['csv', 'tsv', 'json', 'xml', 'yaml', 'yml']
    },
    'web': {
        'name': 'Web Dosyaları',
        'extensions': ['html', 'htm', 'css', 'js']
    },
    'archive': {
        'name': 'Arşiv Dosyaları',
        'extensions': ['zip', 'rar']
    },
    'image': {
        'name': 'Görsel Dosyalar',
        'extensions': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']
    }
}

class RegexPatterns:
    def __init__(self):
        self.categories = CATEGORIES
        self.file_types = FILE_TYPES

    def get_patterns_by_category(self, category: str) -> List[str]:
        """Belirli bir kategoriye ait desenleri döndürür."""
        patterns = []
        if category in self.categories:
            for subcategory in self.categories[category]['subcategories'].values():
                patterns.extend(subcategory['patterns'])
        return patterns

    def get_category_names(self) -> Dict:
        """Kategori isimlerini döndürür."""
        return {
            category: {
                'name': data['name'],
                'description': data['description'],
                'subcategories': {
                    subcategory: {
                        'name': subdata['name'],
                        'description': subdata['description']
                    }
                    for subcategory, subdata in data['subcategories'].items()
                }
            }
            for category, data in self.categories.items()
        }

# Singleton instance
ALL_REGEX_PATTERNS_BACKEND = RegexPatterns()

def get_all_patterns() -> List[str]:
    """Tüm regex desenlerini döndürür."""
    patterns = []
    for category in CATEGORIES.values():
        for subcategory in category.get('subcategories', {}).values():
            patterns.extend(subcategory.get('patterns', []))
    return patterns

def get_patterns_by_category(category: str, subcategories: Optional[List[str]] = None) -> List[str]:
    """Belirli bir kategori ve alt kategorilere ait regex desenlerini döndürür."""
    patterns = []
    if category in CATEGORIES:
        if subcategories:
            for subcategory in subcategories:
                if subcategory in CATEGORIES[category].get('subcategories', {}):
                    patterns.extend(CATEGORIES[category]['subcategories'][subcategory].get('patterns', []))
        else:
            for subcategory in CATEGORIES[category].get('subcategories', {}).values():
                patterns.extend(subcategory.get('patterns', []))
    return patterns

def validate_regex_pattern(pattern: str) -> bool:
    """Regex deseninin geçerli olup olmadığını kontrol eder."""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

def compile_patterns(patterns: List[str], case_sensitive: bool = True, multiline: bool = False) -> List[re.Pattern]:
    """Regex desenlerini derler."""
    flags = 0
    if not case_sensitive:
        flags |= re.IGNORECASE
    if multiline:
        flags |= re.MULTILINE
        
    compiled_patterns = []
    for pattern in patterns:
        if validate_regex_pattern(pattern):
            compiled_patterns.append(re.compile(pattern, flags))
    return compiled_patterns

# Derlenmiş pattern'leri sakla
COMPILED_PATTERNS = compile_patterns(get_all_patterns())

# Global regex patterns for sensitive data detection
sensitive_patterns = {
    'TC Kimlik': r'\b[1-9][0-9]{10}\b',
    'Telefon': r'(?:\+90|0)?\s*?\(?5\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}',
    'E-posta': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Kredi Kartı': r'\b(?:\d[ -]*?){13,16}\b',
    'IBAN': r'TR\d{2}\s?(\d{4}[ ]?){5}\d{2}',
    'Şifre': r'(?:password|şifre|parola)[\s]*[:=][\s]*[\w@#$%^&*()_+\-=\[\]{};\'\\|,.<>\/?]{8,}',
    'API Anahtarı': r'(?:api[_-]?key|api[_-]?token)[\s]*[:=][\s]*[a-zA-Z0-9]{32,}',
    'Gizli Anahtar': r'(?:secret[_-]?key|private[_-]?key)[\s]*[:=][\s]*["\']?[^"\']+["\']?',
    'AWS Anahtarı': r'AKIA[0-9A-Z]{16}',
    'Google API Anahtarı': r'AIza[0-9A-Za-z-_]{35}',
    'SSH Anahtarı': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'SSL Sertifikası': r'-----BEGIN CERTIFICATE-----',
    'Veritabanı Bağlantısı': r'(?:mysql|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@[^:\s]+:\d+',
    'JWT Token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    'OAuth Token': r'ya29\.[0-9A-Za-z\-_]+',
    'IPv4 Adresi': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'IPv6 Adresi': r'(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}',
    'MAC Adresi': r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})',
    'Kurum Sicil No': r'\b[0-9]{10}\b',
    'Vergi No': r'\b[0-9]{10}\b',
    'SGK No': r'\b[0-9]{10}\b',
    'Pasaport No': r'[A-Z][0-9]{8}',
    'Ehliyet No': r'[A-Z][0-9]{8}',
    'Kredi Kartı CVV': r'\b[0-9]{3,4}\b',
    'Kredi Kartı Son Kullanma': r'\b(?:0[1-9]|1[0-2])/(?:[0-9]{2})\b',
    'Adres': r'(?:Mahalle|Sokak|Cadde|Bulvar|Avenue|Street|Road)\s+[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:No|No\.)?\s*[0-9]+',
    'Doğum Tarihi': r'\b(?:0[1-9]|[12][0-9]|3[01])/(?:0[1-9]|1[0-2])/(?:19|20)[0-9]{2}\b',
    'Hesap Numarası': r'\b[0-9]{10,26}\b',
    'SWIFT Kodu': r'[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?',
    'BIC Kodu': r'[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?'
}

# Regex pattern cache
_regex_pattern_cache = {}

def compile_regex_pattern(pattern_str):
    """Compile and cache regex pattern for better performance."""
    if pattern_str not in _regex_pattern_cache:
        try:
            _regex_pattern_cache[pattern_str] = re.compile(pattern_str)
        except re.error as e:
            print(f"Invalid regex pattern: {pattern_str} - {e}")
            return None
    return _regex_pattern_cache[pattern_str]

def validate_regex_pattern(pattern_str):
    """Validate regex pattern for security and correctness."""
    if not pattern_str or len(pattern_str) > 1000:  # Prevent extremely long patterns
        return False, "Pattern is empty or too long"
    
    # Check for potentially dangerous patterns
    dangerous_patterns = [
        r'\.\.\/',  # Directory traversal
        r'\/etc\/',  # System files
        r'\/var\/',  # System files
        r'\/root\/',  # Root directory
        r'\/proc\/',  # Process information
        r'\/sys\/',   # System information
        r'\/dev\/',   # Device files
        r'\/boot\/',  # Boot files
        r'\/bin\/',   # Binary files
        r'\/sbin\/',  # System binary files
    ]
    
    for dangerous in dangerous_patterns:
        if re.search(dangerous, pattern_str):
            return False, f"Pattern contains potentially dangerous path: {dangerous}"
    
    try:
        re.compile(pattern_str)
        return True, "Pattern is valid"
    except re.error as e:
        return False, f"Invalid regex pattern: {str(e)}"

def get_context_lines(content, line_number, context=3):
    """Get context lines around a specific line number from content string."""
    try:
        if isinstance(content, str):
            lines = content.splitlines()
        else:
            # Backward compatibility - if file path is passed
            with open(content, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                lines = [line.rstrip('\n') for line in lines]
            
        start_line = max(0, line_number - context - 1)
        end_line = min(len(lines), line_number + context)
        
        context_lines = []
        for i in range(start_line, end_line):
            if i < len(lines):
                context_lines.append({
                    'line_number': i + 1,
                    'text': lines[i],
                    'is_match_line': i + 1 == line_number
                })
            
        return context_lines
    except Exception as e:
        return [{'line_number': line_number, 'text': f'Error reading context: {str(e)}', 'is_match_line': True}]

def should_scan_file(file_path):
    """Determine if a file should be scanned based on its extension"""
    text_extensions = {
        '.txt', '.log', '.md', '.rst', '.ini', '.conf', '.config', '.cfg',
        '.json', '.xml', '.yaml', '.yml', '.toml', '.csv', '.tsv',
        '.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.php',
        '.rb', '.go', '.rs', '.swift', '.kt', '.ts', '.dart',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        '.sql', '.sh', '.bash', '.bat', '.cmd', '.ps1',
        '.env', '.properties', '.config', '.cfg', '.ini',
        '.dockerfile', '.dockerignore', '.gitignore',
        '.editorconfig', '.eslintrc', '.prettierrc',
        '.babelrc', '.webpack', '.rollup', '.vscode',
        '.idea', '.eclipse', '.project', '.classpath',
        '.gradle', '.mvn', '.pom', '.sln', '.csproj',
        '.xcodeproj', '.pbxproj', '.plist', '.strings',
        '.xib', '.storyboard', '.nib', '.xcdatamodel',
        '.xcscheme', '.xcworkspace', '.xcuserstate',
        '.xcconfig', '.entitlements', '.mobileprovision',
        '.cer', '.p12', '.pem', '.key', '.crt', '.csr',
        '.der', '.p7b', '.p7c', '.pfx', '.p12', '.key',
        '.keystore', '.jks', '.truststore', '.jceks',
        '.bks', '.pem', '.crt', '.cer', '.der', '.p7b',
        '.p7c', '.pfx', '.p12', '.key', '.keystore',
        '.jks', '.truststore', '.jceks', '.bks',
        '.docx'  # Added support for Word documents
    }
    return os.path.splitext(file_path)[1].lower() in text_extensions 