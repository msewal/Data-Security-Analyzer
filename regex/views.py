import io
import os
import re
import urllib.parse
import logging
import time
import json
import shutil
import hashlib
import mimetypes
import docx
import PyPDF2
import pandas as pd
import chardet
import magic
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from malware.models import QuarantinedFile
from django.contrib import messages
from datetime import datetime
from typing import Dict, List, Tuple
from .patterns import (
    get_patterns_by_category,
    get_all_patterns,
    validate_regex_pattern,
    compile_patterns,
    get_category_names,
    CATEGORIES,
    ALL_REGEX_PATTERNS_BACKEND
)

# Office ve PDF işleme için gerekli importlar
try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import PyPDF2
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from pptx import Presentation
    PPTX_AVAILABLE = True
except ImportError:
    PPTX_AVAILABLE = False

logger = logging.getLogger(__name__)

def get_file_content(file_path):
    """Dosya içeriğini okur ve metin olarak döndürür."""
    try:
        file_type = get_file_type(file_path)
        
        # Metin dosyaları
        if file_type in ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties', 'html', 'htm', 'css', 'js']:
            try:
                # Önce UTF-8 ile dene
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except UnicodeDecodeError:
                # UTF-8 başarısız olursa, chardet ile encoding'i tespit et
                import chardet
                with open(file_path, 'rb') as f:
                    raw_data = f.read()
                    result = chardet.detect(raw_data)
                    encoding = result['encoding']
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
        
        # PDF dosyaları
        elif file_type == 'pdf':
            try:
                import PyPDF2
                with open(file_path, 'rb') as f:
                    pdf = PyPDF2.PdfReader(f)
                    text = ''
                    for page in pdf.pages:
                        text += page.extract_text() + '\n'
                    return text
            except Exception as e:
                logger.error(f"Error reading PDF {file_path}: {str(e)}")
                return None
        
        # Word dosyaları
        elif file_type in ['docx', 'doc']:
            try:
                import docx
                doc = docx.Document(file_path)
                return '\n'.join([paragraph.text for paragraph in doc.paragraphs])
            except Exception as e:
                logger.error(f"Error reading Word file {file_path}: {str(e)}")
                return None
        
        # Excel dosyaları
        elif file_type in ['xlsx', 'xls']:
            try:
                import pandas as pd
                df = pd.read_excel(file_path)
                return df.to_string()
            except Exception as e:
                logger.error(f"Error reading Excel file {file_path}: {str(e)}")
                return None
        
        # CSV ve TSV dosyaları
        elif file_type in ['csv', 'tsv']:
            try:
                import pandas as pd
                sep = ',' if file_type == 'csv' else '\t'
                df = pd.read_csv(file_path, sep=sep)
                return df.to_string()
            except Exception as e:
                logger.error(f"Error reading CSV/TSV file {file_path}: {str(e)}")
                return None
        
        # JSON dosyaları
        elif file_type == 'json':
            try:
                import json
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return json.dumps(data, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error reading JSON file {file_path}: {str(e)}")
                return None
        
        # XML dosyaları
        elif file_type == 'xml':
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(file_path)
                root = tree.getroot()
                return ET.tostring(root, encoding='unicode')
            except Exception as e:
                logger.error(f"Error reading XML file {file_path}: {str(e)}")
                return None
        
        # YAML dosyaları
        elif file_type in ['yaml', 'yml']:
            try:
                import yaml
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    return yaml.dump(data, allow_unicode=True)
            except Exception as e:
                logger.error(f"Error reading YAML file {file_path}: {str(e)}")
                return None
        
        # Arşiv dosyaları
        elif file_type in ['zip', 'rar']:
            try:
                import tempfile
                import os
                import zipfile
                import rarfile
                
                # Geçici dizin oluştur
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Arşivi aç
                    if file_type == 'zip':
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir)
                    else:  # rar
                        with rarfile.RarFile(file_path, 'r') as rar_ref:
                            rar_ref.extractall(temp_dir)
                    
                    # Tüm dosyaları tara
                    all_content = []
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            content = get_file_content(file_path)
                            if content:
                                all_content.append(f"=== {file} ===\n{content}\n")
                    
                    return '\n'.join(all_content)
            except Exception as e:
                logger.error(f"Error processing archive {file_path}: {str(e)}")
                return None
        
        # Görsel dosyaları
        elif file_type in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']:
            try:
                import pytesseract
                from PIL import Image
                
                # Tesseract'ın kurulu olduğu dizini belirt (Windows için)
                pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
                
                # Görüntüyü aç ve OCR uygula
                image = Image.open(file_path)
                text = pytesseract.image_to_string(image, lang='tur+eng')
                return text
            except Exception as e:
                logger.error(f"Error processing image {file_path}: {str(e)}")
                return None
        
        else:
            logger.warning(f"Unsupported file type: {file_type}")
            return None
            
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None

def get_file_type(file_path):
    """Dosya türünü belirler."""
    try:
        # Önce uzantıya bak
        ext = os.path.splitext(file_path)[1].lower().lstrip('.')
        
        # MIME türünü kontrol et
        try:
            import magic
            mime = magic.from_file(file_path, mime=True)
        except Exception as e:
            logger.warning(f"Error getting MIME type for {file_path}: {str(e)}")
            mime = None
        
        # Uzantı ve MIME türüne göre dosya türünü belirle
        if ext in ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties']:
            return 'txt'
        elif ext in ['docx', 'doc']:
            return 'docx'
        elif ext in ['xlsx', 'xls']:
            return 'xlsx'
        elif ext in ['pptx', 'ppt']:
            return 'pptx'
        elif ext == 'pdf':
            return 'pdf'
        elif ext in ['csv', 'tsv']:
            return ext
        elif ext in ['json', 'xml', 'yaml', 'yml']:
            return ext
        elif ext in ['html', 'htm', 'css', 'js']:
            return ext
        elif ext in ['zip', 'rar']:
            return ext
        elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']:
            return ext
        else:
            # MIME türüne göre kontrol et
            if mime:
                if mime.startswith('text/'):
                    return 'txt'
                elif mime == 'application/pdf':
                    return 'pdf'
                elif mime in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                            'application/msword']:
                    return 'docx'
                elif mime in ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                            'application/vnd.ms-excel']:
                    return 'xlsx'
                elif mime in ['application/vnd.openxmlformats-officedocument.presentationml.presentation',
                            'application/vnd.ms-powerpoint']:
                    return 'pptx'
                elif mime == 'application/json':
                    return 'json'
                elif mime == 'application/xml':
                    return 'xml'
                elif mime == 'application/zip':
                    return 'zip'
                elif mime.startswith('image/'):
                    return ext
            return None
    except Exception as e:
        logger.error(f"Error determining file type for {file_path}: {str(e)}")
        return None

def regex_search(request):
    """Regex araması yapar."""
    if request.method == 'POST':
        directory = request.POST.get('directory', '')
        file_types = request.POST.getlist('file_types', [])
        case_sensitive = request.POST.get('case_sensitive', 'false') == 'true'
        multiline = request.POST.get('multiline', 'false') == 'true'
        selected_categories = request.POST.getlist('categories', [])
        selected_subcategories = request.POST.getlist('subcategories', [])
        
        if not directory or not os.path.exists(directory):
            messages.error(request, 'Geçersiz dizin yolu.')
            return redirect('regex:regex_search')
            
        if not file_types:
            messages.error(request, 'En az bir dosya türü seçmelisiniz.')
            return redirect('regex:regex_search')
            
        if not selected_categories and not selected_subcategories:
            messages.error(request, 'En az bir kategori veya alt kategori seçmelisiniz.')
            return redirect('regex:regex_search')
            
        # Seçilen kategorilere göre regex desenlerini al
        patterns = []
        if selected_categories:
            for category in selected_categories:
                patterns.extend(get_patterns_by_category(category))
                
        if selected_subcategories:
            for subcategory in selected_subcategories:
                for category in CATEGORIES.values():
                    if subcategory in category.get('subcategories', {}):
                        patterns.extend(category['subcategories'][subcategory])
                        
        if not patterns:
            messages.error(request, 'Geçerli regex deseni bulunamadı.')
            return redirect('regex:regex_search')
            
        # Regex desenlerini derle
        compiled_patterns = compile_patterns(patterns)
        
        results = {
            'matches': [],
            'errors': [],
            'skipped': []
        }
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_type = get_file_type(file_path)
                
                if file_type not in file_types:
                    results['skipped'].append({
                        'path': file_path,
                        'reason': 'Desteklenmeyen dosya türü'
                    })
                    continue
                    
                content = get_file_content(file_path)
                if content is None:
                    results['errors'].append({
                        'path': file_path,
                        'error': 'Dosya okunamadı'
                    })
                    continue
                    
                file_matches = []
                for pattern in compiled_patterns:
                    matches = pattern.finditer(content)
                    for match in matches:
                        file_matches.append({
                            'pattern': pattern.pattern,
                            'match': match.group(),
                            'line': content[:match.start()].count('\n') + 1,
                            'position': match.start()
                        })
                        
                if file_matches:
                    results['matches'].append({
                        'path': file_path,
                        'matches': file_matches
                    })
                    
        # Sonuçları oturuma kaydet
        request.session['regex_results'] = results
        
        return redirect('regex:regex_search_results')
        
    # GET isteği için
    return render(request, 'regex/regex_search.html', {
        'categories': get_category_names(),
        'file_types': {
            'text': ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties'],
            'office': ['docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'pdf'],
            'data': ['csv', 'tsv', 'dat', 'json', 'xml', 'yaml', 'yml'],
            'web': ['html', 'htm', 'css', 'js'],
            'archive': ['zip', 'rar'],
            'image': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']
        }
    })

def regex_search_results(request):
    """Regex arama sonuçlarını gösterir."""
    results = request.session.get('regex_results', {})
    if not results:
        messages.error(request, 'Arama sonucu bulunamadı.')
        return redirect('regex:regex_search')
        
    return render(request, 'regex/regex_search_results.html', {
        'results': results
    })

def regex_search_detail(request, file_path):
    """Belirli bir dosyanın regex arama sonuçlarını gösterir."""
    results = request.session.get('regex_results', {})
    if not results:
        messages.error(request, 'Arama sonucu bulunamadı.')
        return redirect('regex:regex_search')
        
    file_results = next(
        (result for result in results['matches'] if result['path'] == file_path),
        None
    )
    
    if not file_results:
        messages.error(request, 'Dosya sonuçları bulunamadı.')
        return redirect('regex:regex_search_results')
        
    return render(request, 'regex/regex_search_detail.html', {
        'file_path': file_path,
        'matches': file_results['matches']
    })

def quarantine_file(request, file_path):
    """Dosyayı karantinaya alır."""
    try:
        quarantine_dir = os.path.join(settings.MEDIA_ROOT, 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)
        
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, file_name)
        
        os.rename(file_path, quarantine_path)
        messages.success(request, f'Dosya karantinaya alındı: {file_name}')
        
    except Exception as e:
        messages.error(request, f'Karantina hatası: {str(e)}')
        
    return redirect('regex:regex_search_results')

def edit_file(request, file_path):
    """Dosya içeriğini düzenler."""
    if request.method == 'POST':
        try:
            content = request.POST.get('content', '')
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            messages.success(request, 'Dosya başarıyla güncellendi.')
            
        except Exception as e:
            messages.error(request, f'Dosya güncelleme hatası: {str(e)}')
            
        return redirect('regex:regex_search_results')
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
    except Exception as e:
        messages.error(request, f'Dosya okuma hatası: {str(e)}')
        return redirect('regex:regex_search_results')
        
    return render(request, 'regex/edit_file.html', {
        'file_path': file_path,
        'content': content
    })

def is_safe_path(path):
    """Dosya yolunun güvenli olup olmadığını kontrol eder."""
    try:
        # Mutlak yol kontrolü
        abs_path = os.path.abspath(path)
        # İzin verilen dizinlerin kontrolü
        allowed_dirs = [
            os.path.abspath(settings.MEDIA_ROOT),
            os.path.abspath(settings.BASE_DIR)
        ]
        return any(abs_path.startswith(d) for d in allowed_dirs)
    except Exception:
        return False

def sensitive_scan(request):
    """Hassas veri taraması yapar."""
    if request.method == 'POST':
        directory = request.POST.get('directory', '')
        file_types = request.POST.getlist('file_types', [])
        selected_categories = request.POST.getlist('categories', [])
        selected_subcategories = request.POST.getlist('subcategories', [])
        
        if not directory or not os.path.exists(directory):
            messages.error(request, 'Geçersiz dizin yolu.')
            return redirect('regex:sensitive_scan')
            
        if not file_types:
            messages.error(request, 'En az bir dosya türü seçmelisiniz.')
            return redirect('regex:sensitive_scan')
            
        if not selected_categories and not selected_subcategories:
            messages.error(request, 'En az bir kategori veya alt kategori seçmelisiniz.')
            return redirect('regex:sensitive_scan')

        start_time = time.time()
        logger.info(f"Starting sensitive data scan in directory: {directory}")
        logger.info(f"Selected file types: {file_types}")
        logger.info(f"Selected categories: {selected_categories}")
        logger.info(f"Selected subcategories: {selected_subcategories}")

        # Seçilen kategorilere göre regex desenlerini al
        combined_patterns = []
        for category in selected_categories:
            patterns = ALL_REGEX_PATTERNS_BACKEND.get(category, [])
            logger.info(f"Found {len(patterns)} patterns for category: {category}")
            
            # Eğer bu kategori için alt kategoriler seçilmişse, sadece onları derle
            if category in selected_subcategories:
                patterns = [p for p in patterns if p['subcategory'] in selected_subcategories[category]]
            
            for pattern_dict in patterns:
                try:
                    compiled_pattern = re.compile(pattern_dict['pattern'], re.IGNORECASE | re.MULTILINE)
                    combined_patterns.append({
                        'pattern': compiled_pattern,
                        'category': category,
                        'subcategory': pattern_dict['subcategory'],
                        'description': pattern_dict.get('description', '')
                    })
                except re.error as e:
                    logger.error(f"Error compiling pattern {pattern_dict['pattern']}: {str(e)}")
                    continue

        logger.info(f"Total combined patterns: {len(combined_patterns)}")

        results = []
        processed_files_count = 0
        matched_files_count = 0
        error_files = []
        skipped_files = []

        # Fetch all quarantined file paths to exclude them from scanning
        quarantined_paths = set(QuarantinedFile.objects.filter(status='quarantined').values_list('original_path', flat=True))
        logger.info(f"Found {len(quarantined_paths)} files in quarantine. These will be skipped.")

        try:
            logger.info("Starting file walk...")
            for root, dirs, files in os.walk(directory):
                # Skip certain directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__', 'quarantine']]
                
                # Check for timeout (5 minutes)
                if time.time() - start_time > 300:
                    logger.warning("Scan timeout reached after 5 minutes")
                    return render(request, 'regex/sensitive_scan.html', {
                        'error_message': 'Tarama zaman aşımına uğradı (5 dakika). Lütfen daha küçük bir dizin seçin.',
                        'partial_results': results,
                        'processed_files_count': processed_files_count,
                        'matched_files_count': matched_files_count,
                        'error_files': error_files,
                        'skipped_files': skipped_files
                    })

                logger.info(f"Processing directory: {root}")
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check if file is quarantined
                    if file_path in quarantined_paths:
                        skipped_files.append({'file': file_path, 'reason': 'Karantinaya alınmış dosya'})
                        continue

                    # Skip certain file types
                    if file.startswith('.') or file.endswith(('.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin')):
                        skipped_files.append({'file': file_path, 'reason': 'Gizli veya derlenmiş dosya'})
                        continue

                    # Check file extension
                    file_type = get_file_type(file_path)
                    if file_types and file_type not in file_types:
                        skipped_files.append({'file': file_path, 'reason': 'Desteklenmeyen dosya uzantısı'})
                        continue

                    if not is_safe_path(file_path):
                        logger.debug(f"Skipping unsafe file: {file_path}")
                        skipped_files.append({'file': file_path, 'reason': 'Güvensiz yol'})
                        continue

                    # Skip binary files and large files
                    try:
                        if os.path.getsize(file_path) > 5 * 1024 * 1024:  # Skip files larger than 5MB
                            logger.debug(f"Skipping large file: {file_path}")
                            skipped_files.append({'file': file_path, 'reason': 'Büyük dosya (>5MB)'})
                            continue
                    except OSError as e:
                        logger.error(f"Error getting file size for {file_path}: {str(e)}")
                        error_files.append({'path': file_path, 'error': str(e)})
                        continue

                    # Dosya içeriğini oku (uzantıya göre)
                    content = get_file_content(file_path)
                    if content is None:
                        error_files.append({
                            'path': file_path,
                            'error': 'Dosya okunamadı veya erişim izni yok'
                        })
                        continue

                    processed_files_count += 1
                    if processed_files_count % 100 == 0:
                        logger.info(f"Processed {processed_files_count} files so far...")

                    pattern_matches = {}
                    for pattern_info in combined_patterns:
                        pattern = pattern_info['pattern']
                        category = pattern_info['category']
                        subcategory = pattern_info['subcategory']
                        description = pattern_info['description']
                        try:
                            matches = pattern.findall(content) if content else []
                            if matches:
                                if category not in pattern_matches:
                                    pattern_matches[category] = {}
                                if subcategory not in pattern_matches[category]:
                                    pattern_matches[category][subcategory] = {
                                        'matches': [],
                                        'description': description
                                    }
                                pattern_matches[category][subcategory]['matches'].extend(matches)
                                logger.debug(f"Found match in {file_path}: {subcategory}")
                        except Exception as e:
                            logger.error(f"Error processing pattern in {file_path}: {str(e)}")
                            continue

                    if pattern_matches:
                        matched_files_count += 1
                        results.append({
                            'file_path': file_path,
                            'matches': pattern_matches
                        })
                        logger.info(f"Found matches in file: {file_path}")

        except Exception as e:
            logger.error(f"Error during file processing: {str(e)}")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': f'Dosya işleme sırasında bir hata oluştu: {str(e)}',
                'partial_results': results,
                'processed_files_count': processed_files_count,
                'matched_files_count': matched_files_count,
                'error_files': error_files,
                'skipped_files': skipped_files
            })

        scan_duration = time.time() - start_time
        logger.info(f"Search completed in {scan_duration:.2f} seconds. Processed files: {processed_files_count}, Matched files: {matched_files_count}")

        # Sonuçları session'a kaydet
        request.session['sensitive_scan_results'] = {
            'results': results,
            'error_files': error_files,
            'skipped_files': skipped_files,
            'stats': {
                'processed_files': processed_files_count,
                'matched_files': matched_files_count,
                'duration': scan_duration
            }
        }
        
        return redirect('regex:sensitive_scan_results')

    # GET isteği için
    return render(request, 'regex/sensitive_scan.html', {
        'categories': get_category_names(),
        'file_types': {
            'text': ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties'],
            'office': ['docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'pdf'],
            'data': ['csv', 'tsv', 'json', 'xml', 'yaml', 'yml'],
            'web': ['html', 'htm', 'css', 'js'],
            'archive': ['zip', 'rar'],
            'image': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']
        }
    })

def sensitive_scan_results(request):
    """Hassas veri taraması sonuçlarını gösterir."""
    results = request.session.get('sensitive_scan_results', {})
    if not results:
        messages.error(request, 'Tarama sonucu bulunamadı.')
        return redirect('regex:sensitive_scan')
        
    return render(request, 'regex/sensitive_scan_results.html', {
        'results': results['results'],
        'error_files': results['error_files'],
        'skipped_files': results['skipped_files'],
        'stats': results['stats']
    })

def sensitive_scan_detail(request, file_path):
    """View function for displaying detailed scan results for a specific file"""
    decoded_file_path = urllib.parse.unquote(file_path)
    matches = {}

    try:
        encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
        for enc in encodings:
            try:
                with open(decoded_file_path, 'r', encoding=enc) as f:
                    content = f.read()
                break
            except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                logger.error(f"Error reading file {decoded_file_path}: {str(e)}")
                continue
        else:
            return render(request, 'regex/sensitive_scan_detail.html', {
                'error_message': 'Dosya okunamadı veya erişim izni yok.',
                'file_path': decoded_file_path
            })

        for category, patterns in ALL_REGEX_PATTERNS_BACKEND.items():
            category_matches = {}
            for pattern_dict in patterns:
                try:
                    pattern = re.compile(pattern_dict['pattern'], re.IGNORECASE | re.MULTILINE)
                    found_matches = pattern.findall(content)
                    if found_matches:
                        category_matches[pattern_dict['subcategory']] = found_matches
                except re.error as e:
                    logger.error(f"Regex error with pattern {pattern_dict['pattern']}: {str(e)}")
                    continue
            
            if category_matches:
                matches[category] = category_matches

        return render(request, 'regex/sensitive_scan_detail.html', {
            'file_path': decoded_file_path,
            'matches': matches
        })

    except Exception as e:
        logger.error(f"Error processing file {decoded_file_path}: {str(e)}")
        return render(request, 'regex/sensitive_scan_detail.html', {
            'error_message': f'Dosya işlenirken bir hata oluştu: {str(e)}',
            'file_path': decoded_file_path
        })

def api_get_regex_patterns(request):
    return JsonResponse(ALL_REGEX_PATTERNS_BACKEND)

def quarantine_list(request):
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    return render(request, 'regex/quarantine_list.html', {'files': files})
