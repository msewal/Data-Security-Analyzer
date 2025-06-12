import re
import os
from django.conf import settings

# Global regex patterns for sensitive data detection
sensitive_patterns = {
    'TC Kimlik': r'\b[1-9][0-9]{10}\b',
    'Telefon': r'(?:\+90|0)?\s*?\(?5\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}',
    'E-posta': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Kredi Kartı': r'\b(?:\d[ -]*?){13,16}\b',
    'IBAN': r'TR\d{2}\s?(\d{4}\s?){5}\d{2}',
    'Şifre': r'(?:password|passwd|pwd)\s*=\s*["\']?[^"\']+["\']?',
    'API Anahtarı': r'(?:api[_-]?key|apikey)\s*=\s*["\']?[^"\']+["\']?',
    'Gizli Anahtar': r'(?:secret[_-]?key|private[_-]?key)\s*=\s*["\']?[^"\']+["\']?',
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

# Centralized regex patterns in Python dictionary format (Comprehensive)
ALL_REGEX_PATTERNS_BACKEND = {
    'personalInfo': [
        # TC Kimlik Numarası: 11 haneli, ilk rakam 0 olamaz
        {'subcategory': 'TC Kimlik Numarası', 'pattern': r'\b[1-9][0-9]{10}\b'},
        # Vergi Kimlik Numarası: 10 haneli
        {'subcategory': 'Vergi Kimlik Numarası', 'pattern': r'\b[0-9]{10}\b'},
        # Telefon Numarası (Mobil): 05xx xxx xx xx veya +90 5xx xxx xx xx
        {'subcategory': 'Telefon Numarası (Mobil)', 'pattern': r'\b(?:\+90[\s-]?|0)?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b'},
        # Telefon Numarası (Sabit Hat): 0xxx xxx xx xx veya (xxx) xxx xx xx
        {'subcategory': 'Telefon Numarası (Sabit Hat)', 'pattern': r'\b(?:0[2-9][0-9]{2}[\s-]?|\([2-9][0-9]{2}\)[\s-]?)\d{3}[\s-]?\d{2}[\s-]?\d{2}\b'},
        # E-posta Adresi
        {'subcategory': 'E-posta Adresi', 'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'},
        # Doğum Tarihi: GG/AA/YYYY veya GG.AA.YYYY
        {'subcategory': 'Doğum Tarihi', 'pattern': r'\b(?:0[1-9]|[12][0-9]|3[01])[./-](?:0[1-9]|1[0-2])[./-](?:19|20)\d{2}\b'},
        # Ad Soyad: En az iki kelime, baş harfler büyük
        {'subcategory': 'Ad Soyad', 'pattern': r'\b[A-ZÇĞİÖŞÜ][a-zçğıöşü]+(?:\s+[A-ZÇĞİÖŞÜ][a-zçğıöşü]+)+\b'}
    ],
    'financialData': [
        {'subcategory': 'Kredi Kartı Numarası', 'pattern': r'\b(?:\d[ -]*?){13,16}\b'},
        {'subcategory': 'IBAN', 'pattern': r'TR\d{2}\s?(\d{4}\s?){5}\d{2}'},
        {'subcategory': 'Hesap Numarası', 'pattern': r'\b[0-9]{10,26}\b'},
        {'subcategory': 'SWIFT/BIC Kodu', 'pattern': r'[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?'}
    ],
    'healthData': [
        {'subcategory': 'SGK Numarası', 'pattern': r'\b[0-9]{10}\b'},
        {'subcategory': 'Hasta Kayıt Numarası', 'pattern': r'\bH[0-9]{8}\b'},
        {'subcategory': 'Tıbbi Rapor Numarası', 'pattern': r'\bR[0-9]{8}\b'}
    ],
    'corporateData': [
        {'subcategory': 'Vergi Numarası', 'pattern': r'\b[0-9]{10}\b'},
        {'subcategory': 'Şirket Sicil Numarası', 'pattern': r'\b[0-9]{10}\b'},
        {'subcategory': 'Şirket Telefonu', 'pattern': r'\b0[2-9][0-9]{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b'}
    ],
    'locationData': [
        {'subcategory': 'Adres', 'pattern': r'(?:Mahalle|Sokak|Cadde|Bulvar)\s+[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:No|No\.)?\s*[0-9]+'},
        {'subcategory': 'Posta Kodu', 'pattern': r'\b[0-9]{5}\b'},
        {'subcategory': 'GPS Koordinatları', 'pattern': r'\b\d{1,3}\.\d{6},\s*\d{1,3}\.\d{6}\b'}
    ],
    'authData': [
        {'subcategory': 'Şifre', 'pattern': r'(?:password|passwd|pwd)\s*=\s*["\']?[^"\']+["\']?'},
        {'subcategory': 'API Anahtarı', 'pattern': r'(?:api[_-]?key|apikey)\s*=\s*["\']?[^"\']+["\']?'},
        {'subcategory': 'Gizli Anahtar', 'pattern': r'(?:secret[_-]?key|private[_-]?key)\s*=\s*["\']?[^"\']+["\']?'}
    ],
    'educationData': [
        {'subcategory': 'Öğrenci Numarası', 'pattern': r'\b[0-9]{7,10}\b'},
        {'subcategory': 'Diploma Numarası', 'pattern': r'\bD[0-9]{8}\b'},
        {'subcategory': 'Sertifika Numarası', 'pattern': r'\bS[0-9]{8}\b'}
    ],
    'systemSecurityData': [
        {'subcategory': 'IP Adresi', 'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'},
        {'subcategory': 'MAC Adresi', 'pattern': r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})'},
        {'subcategory': 'SSH Anahtarı', 'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'}
    ]
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

def get_context_lines(file_path, line_number, context=3):
    """Get context lines around a specific line number from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        start_line = max(0, line_number - context - 1)
        end_line = min(len(lines), line_number + context)
        
        context_lines = []
        for i in range(start_line, end_line):
            context_lines.append({
                'line_number': i + 1,
                'text': lines[i].rstrip('\n')
            })
            
        return context_lines
    except Exception as e:
        return [{'line_number': line_number, 'text': f'Error reading context: {str(e)}'}]

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