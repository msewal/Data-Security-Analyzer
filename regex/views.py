import os
import re
import json
import urllib.parse
from django.shortcuts import render
from django.http import JsonResponse
from docx import Document

# Regex patterns for detecting sensitive information
REGEX_PATTERNS = {
    "TC Kimlik No": r"\b\d{11}\b",  # 11-digit National ID
    "Telefon Numarası": r"\b\d{10,11}\b",  # 10-11 digit phone number
    "E-posta Adresi": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email format
    "Kredi Kartı": r"\b(?:\d[ -]*?){13,16}\b",  # 13-16 digit credit card
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"  # IBAN pattern
}

def is_safe_path(path):
    # WSL için Windows dizinlerine erişime izin ver
    return True

def normalize_path(path):
    # Windows yolunu WSL yoluna çevir
    if path.startswith('/mnt/c/'):
        return path
    elif path.startswith('C:'):
        return '/mnt/c/' + path[2:].replace('\\', '/')
    return path

def scan_text_file(file_path):
    try:
        encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
        content = None
        
        for enc in encodings:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    content = f.read()
                break
            except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                print(f"Error reading {file_path} with {enc}: {str(e)}")
                continue
        
        if content is None:
            print(f"Could not read file {file_path} with any encoding")
            return None

        matches = {}
        for pattern_name, pattern in REGEX_PATTERNS.items():
            try:
                pattern_matches = re.findall(pattern, content)
                if pattern_matches:
                    matches[pattern_name] = pattern_matches
            except Exception as e:
                print(f"Error matching pattern {pattern_name} in {file_path}: {str(e)}")
                continue
        
        return matches if matches else None
    except Exception as e:
        print(f"Error scanning {file_path}: {str(e)}")
        return None

def scan_docx_file(file_path):
    try:
        doc = Document(file_path)
        content = "\n".join([para.text for para in doc.paragraphs])
        
        matches = {}
        for pattern_name, pattern in REGEX_PATTERNS.items():
            try:
                pattern_matches = re.findall(pattern, content)
                if pattern_matches:
                    matches[pattern_name] = pattern_matches
            except Exception as e:
                print(f"Error matching pattern {pattern_name} in {file_path}: {str(e)}")
                continue
        
        return matches if matches else None
    except Exception as e:
        print(f"Error reading DOCX file {file_path}: {str(e)}")
        return None

def regex_search_results_view(request):
    if request.method == 'POST':
        directory_path = request.POST.get('directory', '').strip()
        file_types = request.POST.getlist('file_types')
        
        if not directory_path:
            return render(request, 'regex/regex_search.html', {
                'error_message': 'Lütfen bir dizin yolu girin.'
            })

        # Normalize the path for WSL
        directory_path = normalize_path(directory_path)
        print(f"Scanning directory: {directory_path}")

        if not os.path.exists(directory_path):
            return render(request, 'regex/regex_search.html', {
                'error_message': f'Girilen dizin yolu mevcut değil: {directory_path}'
            })

        if not os.access(directory_path, os.R_OK):
            return render(request, 'regex/regex_search.html', {
                'error_message': f'Dizine erişim izni yok: {directory_path}'
            })

        if not file_types:
            return render(request, 'regex/regex_search.html', {
                'error_message': 'Lütfen en az bir dosya türü seçin.'
            })

        results = {}
        processed_files_count = 0
        matched_files_count = 0
        error_files = []

        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        file_ext = os.path.splitext(file)[1].lower()[1:]  # Remove the dot

                        if not is_safe_path(file_path):
                            continue

                        # Check if file type is selected
                        if file_ext not in file_types:
                            continue

                        if not os.access(file_path, os.R_OK):
                            print(f"No read permission for file: {file_path}")
                            continue

                        processed_files_count += 1
                        file_matches = None

                        if file_ext == 'docx':
                            file_matches = scan_docx_file(file_path)
                        else:  # For txt, csv, json
                            file_matches = scan_text_file(file_path)

                        if file_matches:
                            matched_files_count += 1
                            results[file_path] = file_matches
                    except Exception as e:
                        error_files.append(f"{file_path}: {str(e)}")
                        continue

        except Exception as e:
            return render(request, 'regex/regex_search.html', {
                'error_message': f'Tarama sırasında hata oluştu: {str(e)}'
            })

        return render(request, 'regex/regex_search.html', {
            'results': results,
            'search_path': directory_path,
            'processed_files_count': processed_files_count,
            'matched_files_count': matched_files_count,
            'error_files': error_files if error_files else None
        })

    return render(request, 'regex/regex_search.html')

def regex_search_detail_view(request, file_path):
    decoded_file_path = urllib.parse.unquote(file_path)
    matches = {}

    try:
        file_ext = os.path.splitext(decoded_file_path)[1].lower()
        
        if file_ext == '.docx':
            matches = scan_docx_file(decoded_file_path)
        else:
            matches = scan_text_file(decoded_file_path)

        if matches is None:
            return render(request, 'regex/regex_search_detail.html', {
                'error_message': 'Dosya okunamadı veya erişim izni yok.',
                'file_path': decoded_file_path
            })

    except Exception as e:
        return render(request, 'regex/regex_search_detail.html', {
            'error_message': f"Beklenmeyen bir hata oluştu: {str(e)}",
            'file_path': decoded_file_path
        })

    return render(request, 'regex/regex_search_detail.html', {
        'matches': matches,
        'file_path': decoded_file_path
    })

def api_get_regex_patterns(request):
    return JsonResponse(REGEX_PATTERNS)
