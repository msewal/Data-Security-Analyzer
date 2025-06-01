import os
import re
from docx import Document

def normalize_path(path):
    """Dosya yolunu normalize eder."""
    return os.path.normpath(path)

def is_safe_path(path):
    """Dosya yolunun güvenli olup olmadığını kontrol eder."""
    # Tehlikeli karakterleri ve yolları kontrol et
    dangerous_patterns = [
        r'\.\.',  # Directory traversal
        r'^/',    # Absolute paths
        r'^[A-Za-z]:',  # Windows drive letters
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, path):
            return False
    return True

def scan_text_file(file_path):
    """Metin dosyalarını tarar ve hassas verileri bulur."""
    matches = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # TC Kimlik No
            tc_pattern = r'\b[1-9][0-9]{10}\b'
            tc_matches = re.findall(tc_pattern, content)
            if tc_matches:
                matches['TC Kimlik No'] = tc_matches
            
            # E-posta
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            email_matches = re.findall(email_pattern, content)
            if email_matches:
                matches['E-posta'] = email_matches
            
            # Telefon numarası
            phone_pattern = r'\b(?:0|90)?[0-9]{10}\b'
            phone_matches = re.findall(phone_pattern, content)
            if phone_matches:
                matches['Telefon'] = phone_matches
            
            # Kredi kartı
            cc_pattern = r'\b(?:\d[ -]*?){13,19}\b'
            cc_matches = re.findall(cc_pattern, content)
            if cc_matches:
                matches['Kredi Kartı'] = cc_matches
                
    except Exception as e:
        print(f"Error scanning {file_path}: {str(e)}")
    
    return matches if matches else None

def scan_docx_file(file_path):
    """Word dosyalarını tarar ve hassas verileri bulur."""
    matches = {}
    try:
        doc = Document(file_path)
        content = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
        
        # TC Kimlik No
        tc_pattern = r'\b[1-9][0-9]{10}\b'
        tc_matches = re.findall(tc_pattern, content)
        if tc_matches:
            matches['TC Kimlik No'] = tc_matches
        
        # E-posta
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_matches = re.findall(email_pattern, content)
        if email_matches:
            matches['E-posta'] = email_matches
        
        # Telefon numarası
        phone_pattern = r'\b(?:0|90)?[0-9]{10}\b'
        phone_matches = re.findall(phone_pattern, content)
        if phone_matches:
            matches['Telefon'] = phone_matches
        
        # Kredi kartı
        cc_pattern = r'\b(?:\d[ -]*?){13,19}\b'
        cc_matches = re.findall(cc_pattern, content)
        if cc_matches:
            matches['Kredi Kartı'] = cc_matches
            
    except Exception as e:
        print(f"Error scanning {file_path}: {str(e)}")
    
    return matches if matches else None 