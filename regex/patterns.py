import re
import os
from django.conf import settings
from typing import Dict, List, Pattern, Tuple, Optional, Union

# Ana kategoriler ve alt kategoriler
CATEGORIES = {
    'personalInfo': {
        'name': 'Kişisel Bilgiler',
        'description': 'TC Kimlik, telefon, e-posta, adres gibi kişisel bilgiler',
        'subcategories': {
            'tcKimlik': {
                'name': 'TC Kimlik Numarası',
                'description': '11 haneli, 1 ile başlayan TC Kimlik Numarası',
                'pattern': r'^[1-9][0-9]{10}$'
            },
            'phone': {
                'name': 'Telefon Numarası',
                'description': 'Türkiye telefon numaraları (mobil ve sabit hat)',
                'pattern': r'^(\+90|0)?[ ]?([0-9]{3})[ ]?([0-9]{3})[ ]?([0-9]{2})[ ]?([0-9]{2})$'
            },
            'email': {
                'name': 'E-posta Adresi',
                'description': 'Geçerli e-posta adresleri',
                'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            },
            'address': {
                'name': 'Adres',
                'description': 'Türkiye adres formatı',
                'pattern': r'^[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:Mahallesi|Sokak|Caddesi|Bulvarı|No\.?\s*\d+)[,\s]+(?:Daire\s*\d+)?[,\s]+(?:[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:İlçesi|İli))?$'
            },
            'birthDate': {
                'name': 'Doğum Tarihi',
                'description': 'GG/AA/YYYY formatında doğum tarihi',
                'pattern': r'^(0[1-9]|[12][0-9]|3[01])/(0[1-9]|1[0-2])/(19|20)\d{2}$'
            }
        }
    },
    'financialData': {
        'name': 'Finansal Bilgiler',
        'description': 'Kredi kartı, IBAN, hesap numarası gibi finansal bilgiler',
        'subcategories': {
            'creditCard': {
                'name': 'Kredi Kartı Numarası',
                'description': 'Visa, MasterCard, Amex ve Discover kartları',
                'pattern': r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})$'
            },
            'cvv': {
                'name': 'CVV Kodu',
                'description': '3 veya 4 haneli CVV kodu',
                'pattern': r'^[0-9]{3,4}$'
            },
            'expiryDate': {
                'name': 'Son Kullanma Tarihi',
                'description': 'AA/YY formatında son kullanma tarihi',
                'pattern': r'^(0[1-9]|1[0-2])/([0-9]{2})$'
            },
            'iban': {
                'name': 'IBAN',
                'description': 'Türkiye IBAN formatı',
                'pattern': r'^TR[0-9]{2}[ ]?([0-9]{4}[ ]?){5}[0-9]{2}$'
            },
            'swift': {
                'name': 'SWIFT/BIC Kodu',
                'description': '8 veya 11 karakterli SWIFT/BIC kodu',
                'pattern': r'^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$'
            },
            'accountNumber': {
                'name': 'Banka Hesap Numarası',
                'description': 'Türkiye banka hesap numarası',
                'pattern': r'^[0-9]{10,26}$'
            }
        }
    },
    'healthData': {
        'name': 'Sağlık Bilgileri',
        'description': 'SGK numarası, sağlık raporları gibi sağlık bilgileri',
        'subcategories': {
            'sgkNumber': {
                'name': 'SGK Numarası',
                'description': '10 haneli SGK numarası',
                'pattern': r'^[0-9]{10}$'
            }
        }
    },
    'corporateData': {
        'name': 'Kurumsal Bilgiler',
        'description': 'Vergi numarası, şirket kayıt numarası gibi kurumsal bilgiler',
        'subcategories': {
            'taxNumber': {
                'name': 'Vergi Numarası',
                'description': '10 haneli vergi numarası',
                'pattern': r'^[0-9]{10}$'
            },
            'companyRegistry': {
                'name': 'Şirket Kayıt Numarası',
                'description': '10 haneli şirket kayıt numarası',
                'pattern': r'^[0-9]{10}$'
            }
        }
    },
    'locationData': {
        'name': 'Konum Bilgileri',
        'description': 'Adres, GPS koordinatları gibi konum bilgileri',
        'subcategories': {
            'address': {
                'name': 'Adres',
                'description': 'Türkiye adres formatı',
                'pattern': r'^[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:Mahallesi|Sokak|Caddesi|Bulvarı|No\.?\s*\d+)[,\s]+(?:Daire\s*\d+)?[,\s]+(?:[A-Za-zğüşıöçĞÜŞİÖÇ\s]+(?:İlçesi|İli))?$'
            },
            'gpsCoordinates': {
                'name': 'GPS Koordinatları',
                'description': 'Enlem ve boylam koordinatları',
                'pattern': r'^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$'
            }
        }
    },
    'authData': {
        'name': 'Kimlik Doğrulama Bilgileri',
        'description': 'Şifre, API anahtarı, SSH anahtarı gibi kimlik doğrulama bilgileri',
        'subcategories': {
            'password': {
                'name': 'Şifre',
                'description': 'En az 8 karakterli şifre',
                'pattern': r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$'
            },
            'apiKey': {
                'name': 'API Anahtarı',
                'description': 'AWS, Google ve diğer API anahtarları',
                'pattern': r'^(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|[0-9a-f]{32}|[0-9a-f]{40})$'
            },
            'sshKey': {
                'name': 'SSH Anahtarı',
                'description': 'SSH özel ve genel anahtarları',
                'pattern': r'^-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{4}\n)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\n-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----$'
            },
            'sslCertificate': {
                'name': 'SSL Sertifikası',
                'description': 'SSL/TLS sertifikaları',
                'pattern': r'^-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{4}\n)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\n-----END CERTIFICATE-----$'
            }
        }
    },
    'systemSecurityData': {
        'name': 'Sistem Güvenlik Bilgileri',
        'description': 'IP adresi, MAC adresi, veritabanı bağlantı bilgileri',
        'subcategories': {
            'ipAddress': {
                'name': 'IP Adresi',
                'description': 'IPv4 ve IPv6 adresleri',
                'pattern': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
            },
            'macAddress': {
                'name': 'MAC Adresi',
                'description': 'MAC adresi formatı',
                'pattern': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            },
            'databaseConnection': {
                'name': 'Veritabanı Bağlantısı',
                'description': 'Veritabanı bağlantı bilgileri',
                'pattern': r'(?:jdbc|mysql|postgresql|mongodb|redis)://[a-zA-Z0-9._%+-]+:[0-9]+/[a-zA-Z0-9._%+-]+'
            }
        }
    },
    'identificationData': {
        'name': 'Kimlik Bilgileri',
        'description': 'Pasaport, ehliyet gibi kimlik bilgileri',
        'subcategories': {
            'passport': {
                'name': 'Pasaport Numarası',
                'description': '8 karakterli pasaport numarası',
                'pattern': r'^[A-Z][0-9]{7}$'
            },
            'driverLicense': {
                'name': 'Ehliyet Numarası',
                'description': '8 karakterli ehliyet numarası',
                'pattern': r'^[A-Z][0-9]{7}$'
            }
        }
    }
}

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

def get_category_names() -> Dict[str, Dict[str, Union[str, Dict[str, str]]]]:
    """Kategori ve alt kategori isimlerini döndürür."""
    category_names = {
        'personal': {
            'name': 'Kişisel Bilgiler',
            'subcategories': {
                'tc_kimlik': 'TC Kimlik Numarası',
                'email': 'E-posta Adresi',
                'phone': 'Cep Telefonu',
                'phone_landline': 'Sabit Telefon',
                'address': 'Adres',
                'birth_date': 'Doğum Tarihi'
            }
        },
        'financial': {
            'name': 'Finansal Bilgiler',
            'subcategories': {
                'credit_card': 'Kredi Kartı',
                'credit_card_cvv': 'CVV Kodu',
                'credit_card_expiry': 'Son Kullanma Tarihi',
                'iban': 'IBAN',
                'swift_bic': 'SWIFT/BIC',
                'account_number': 'Hesap Numarası'
            }
        },
        'corporate': {
            'name': 'Kurumsal Bilgiler',
            'subcategories': {
                'tax_number': 'Vergi Numarası',
                'sgk_number': 'SGK Numarası',
                'company_registry': 'Kurum Sicil No'
            }
        },
        'security': {
            'name': 'Güvenlik Bilgileri',
            'subcategories': {
                'password': 'Şifre',
                'api_key': 'API Anahtarı',
                'aws_key': 'AWS Anahtarı',
                'google_api_key': 'Google API Anahtarı',
                'ssh_key': 'SSH Anahtarı',
                'ssl_cert': 'SSL Sertifikası'
            }
        },
        'network': {
            'name': 'Ağ Bilgileri',
            'subcategories': {
                'ipv4': 'IPv4 Adresi',
                'ipv6': 'IPv6 Adresi',
                'mac_address': 'MAC Adresi',
                'database_connection': 'Veritabanı Bağlantısı'
            }
        },
        'authentication': {
            'name': 'Kimlik Doğrulama',
            'subcategories': {
                'jwt_token': 'JWT Token',
                'oauth_token': 'OAuth Token',
                'session_id': 'Oturum ID'
            }
        },
        'location': {
            'name': 'Konum Bilgileri',
            'subcategories': {
                'gps_coordinates': 'GPS Koordinatları',
                'gps_coordinates_alt': 'GPS Koordinatları (Alt)'
            }
        },
        'identification': {
            'name': 'Kimlik Bilgileri',
            'subcategories': {
                'passport': 'Pasaport Numarası',
                'drivers_license': 'Ehliyet Numarası',
                'student_id': 'Öğrenci Numarası'
            }
        }
    }
    return category_names

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
    'IBAN': r'TR\d{2}\s?(\d{4}\s?){5}\d{2}',
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

# Centralized regex patterns in Python dictionary format (Comprehensive)
ALL_REGEX_PATTERNS_BACKEND = {
    'personal': [
        {
            'subcategory': 'tc_kimlik',
            'pattern': r'\b[1-9][0-9]{10}\b',
            'description': 'TC Kimlik Numarası (11 haneli, 1 ile başlayan)'
        },
        {
            'subcategory': 'email',
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'E-posta Adresi (RFC standartlarına uygun)'
        },
        {
            'subcategory': 'phone',
            'pattern': r'\b(?:\+90|0)?\s*5[0-9]{2}\s*[0-9]{3}\s*[0-9]{2}\s*[0-9]{2}\b',
            'description': 'Türkiye Cep Telefonu Numarası'
        },
        {
            'subcategory': 'phone_landline',
            'pattern': r'\b(?:\+90|0)?\s*[2-4][0-9]{2}\s*[0-9]{3}\s*[0-9]{2}\s*[0-9]{2}\b',
            'description': 'Türkiye Sabit Telefon Numarası'
        },
        {
            'subcategory': 'address',
            'pattern': r'\b(?:Mahalle|Sokak|Cadde|Bulvar|Avenue|Street|Road)\s+[A-Za-zğüşıöçĞÜŞİÖÇ\s]+\s+(?:No|No:)\s*\d+\s*(?:Daire|Kat|Blok)?\s*[A-Za-z0-9]*\b',
            'description': 'Adres Bilgisi (Mahalle, Sokak, No vb.)'
        },
        {
            'subcategory': 'birth_date',
            'pattern': r'\b(?:0[1-9]|[12][0-9]|3[01])[/.-](?:0[1-9]|1[0-2])[/.-](?:19|20)[0-9]{2}\b',
            'description': 'Doğum Tarihi (GG/AA/YYYY formatında)'
        }
    ],
    'financial': [
        {
            'subcategory': 'credit_card',
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
            'description': 'Kredi Kartı Numarası (Visa, MasterCard, Amex, Discover)'
        },
        {
            'subcategory': 'credit_card_cvv',
            'pattern': r'\b[0-9]{3,4}\b',
            'description': 'Kredi Kartı CVV Kodu'
        },
        {
            'subcategory': 'credit_card_expiry',
            'pattern': r'\b(?:0[1-9]|1[0-2])/(?:[0-9]{2})\b',
            'description': 'Kredi Kartı Son Kullanma Tarihi'
        },
        {
            'subcategory': 'iban',
            'pattern': r'\bTR[0-9]{2}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{2}\b',
            'description': 'Türkiye IBAN Numarası'
        },
        {
            'subcategory': 'swift_bic',
            'pattern': r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
            'description': 'SWIFT/BIC Kodu'
        },
        {
            'subcategory': 'account_number',
            'pattern': r'\b[0-9]{10,26}\b',
            'description': 'Banka Hesap Numarası'
        }
    ],
    'corporate': [
        {
            'subcategory': 'tax_number',
            'pattern': r'\b[0-9]{10}\b',
            'description': 'Vergi Numarası (10 haneli)'
        },
        {
            'subcategory': 'sgk_number',
            'pattern': r'\b[1-9][0-9]{9}\b',
            'description': 'SGK Numarası (10 haneli)'
        },
        {
            'subcategory': 'company_registry',
            'pattern': r'\b[0-9]{10}\b',
            'description': 'Kurum Sicil Numarası'
        }
    ],
    'security': [
        {
            'subcategory': 'password',
            'pattern': r'\b(?:password|şifre|parola)[\s]*[:=][\s]*[\w@#$%^&*()_+\-=\[\]{};\'\\|,.<>\/?]{8,}\b',
            'description': 'Şifre (8+ karakter)'
        },
        {
            'subcategory': 'api_key',
            'pattern': r'\b(?:api[_-]?key|api[_-]?token)[\s]*[:=][\s]*[a-zA-Z0-9]{32,}\b',
            'description': 'API Anahtarı'
        },
        {
            'subcategory': 'aws_key',
            'pattern': r'\bAKIA[0-9A-Z]{16}\b',
            'description': 'AWS Erişim Anahtarı'
        },
        {
            'subcategory': 'google_api_key',
            'pattern': r'\bAIza[0-9A-Za-z-_]{35}\b',
            'description': 'Google API Anahtarı'
        },
        {
            'subcategory': 'ssh_key',
            'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'description': 'SSH Özel Anahtarı'
        },
        {
            'subcategory': 'ssl_cert',
            'pattern': r'-----BEGIN CERTIFICATE-----',
            'description': 'SSL Sertifikası'
        }
    ],
    'network': [
        {
            'subcategory': 'ipv4',
            'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'description': 'IPv4 Adresi'
        },
        {
            'subcategory': 'ipv6',
            'pattern': r'\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b',
            'description': 'IPv6 Adresi'
        },
        {
            'subcategory': 'mac_address',
            'pattern': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
            'description': 'MAC Adresi'
        },
        {
            'subcategory': 'database_connection',
            'pattern': r'\b(?:mysql|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@[^:\s]+:\d+\b',
            'description': 'Veritabanı Bağlantı Bilgisi'
        }
    ],
    'authentication': [
        {
            'subcategory': 'jwt_token',
            'pattern': r'\bey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b',
            'description': 'JWT Token'
        },
        {
            'subcategory': 'oauth_token',
            'pattern': r'\bya29\.[0-9A-Za-z\-_]+\b',
            'description': 'OAuth Token'
        },
        {
            'subcategory': 'session_id',
            'pattern': r'\b(?:session[_-]?id|sid)[\s]*[:=][\s]*[A-Za-z0-9]{32,}\b',
            'description': 'Oturum ID'
        }
    ],
    'location': [
        {
            'subcategory': 'gps_coordinates',
            'pattern': r'\b(?:[NS])\s*(\d{1,2}(?:\.\d+)?)\s*(?:[EW])\s*(\d{1,3}(?:\.\d+)?)\b',
            'description': 'GPS Koordinatları (Derece formatında)'
        },
        {
            'subcategory': 'gps_coordinates_alt',
            'pattern': r'\b(?:[+-]?\d{1,2}(?:\.\d+)?)\s*,\s*(?:[+-]?\d{1,3}(?:\.\d+)?)\b',
            'description': 'GPS Koordinatları (Alternatif format)'
        }
    ],
    'identification': [
        {
            'subcategory': 'passport',
            'pattern': r'\b[A-Z][0-9]{8}\b',
            'description': 'Pasaport Numarası'
        },
        {
            'subcategory': 'drivers_license',
            'pattern': r'\b[A-Z][0-9]{8}\b',
            'description': 'Ehliyet Numarası'
        },
        {
            'subcategory': 'student_id',
            'pattern': r'\b[0-9]{8,10}\b',
            'description': 'Öğrenci Numarası'
        }
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