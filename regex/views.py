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
    ALL_REGEX_PATTERNS_BACKEND,
    get_all_patterns,
    validate_regex_pattern,
    get_context_lines,
    should_scan_file
)
from collections import defaultdict

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
                    try:
                        pdf = PyPDF2.PdfReader(f)
                        if len(pdf.pages) == 0:
                            logger.warning(f"PDF dosyası boş: {file_path}")
                            return "PDF dosyası boş veya okunamıyor."
                            
                        text = ''
                        for page_num, page in enumerate(pdf.pages, 1):
                            try:
                                page_text = page.extract_text()
                                if page_text:
                                    text += f"\n--- Sayfa {page_num} ---\n{page_text}\n"
                                else:
                                    text += f"\n--- Sayfa {page_num} (Metin içermiyor) ---\n"
                            except Exception as page_error:
                                logger.error(f"PDF sayfa {page_num} okuma hatası: {str(page_error)}")
                                text += f"\n--- Sayfa {page_num} (Okunamadı) ---\n"
                                
                        if not text.strip():
                            return "PDF dosyasından metin çıkarılamadı."
                        return text
                    except PyPDF2.errors.PdfReadError as pdf_error:
                        logger.error(f"PDF okuma hatası: {str(pdf_error)}")
                        return f"PDF dosyası okunamıyor: {str(pdf_error)}"
            except Exception as e:
                logger.error(f"PDF dosyası açma hatası {file_path}: {str(e)}")
                return f"PDF dosyası açılamıyor: {str(e)}"
        
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
    """Dosya türünü belirler - Ubuntu subsystem uyumlu."""
    try:
        # Önce uzantıya bak
        ext = os.path.splitext(file_path)[1].lower().lstrip('.')
        
        # MIME türünü kontrol et (Ubuntu subsystem için güvenli)
        mime = None
        try:
            # Ubuntu subsystem'de magic kütüphanesi farklı çalışabilir
            import magic
            if hasattr(magic, 'from_file'):
                mime = magic.from_file(file_path, mime=True)
            else:
                # Alternative magic usage
                m = magic.Magic(mime=True)
                mime = m.from_file(file_path)
        except Exception as e:
            logger.warning(f"Error getting MIME type for {file_path}: {str(e)}")
            # Fallback: mimetypes modülünü kullan
            import mimetypes
            mime, _ = mimetypes.guess_type(file_path)
        
        # Uzantı ve MIME türüne göre dosya türünü belirle
        if ext in ['txt', 'md', 'log', 'ini', 'conf', 'cfg', 'properties', 'py', 'sh', 'bash']:
            return 'txt'
        elif ext in ['docx']:
            return 'docx'
        elif ext in ['doc']:
            return 'docx'  # Doc dosyalarını da docx olarak işle
        elif ext in ['xlsx']:
            return 'xlsx'
        elif ext in ['xls']:
            return 'xlsx'  # Xls dosyalarını da xlsx olarak işle
        elif ext in ['pptx']:
            return 'pptx'
        elif ext in ['ppt']:
            return 'pptx'  # Ppt dosyalarını da pptx olarak işle
        elif ext == 'pdf':
            return 'pdf'
        elif ext in ['csv', 'tsv']:
            return ext
        elif ext in ['json', 'xml', 'yaml', 'yml']:
            return ext
        elif ext in ['html', 'htm', 'css', 'js']:
            return ext
        elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
            return ext
        elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp']:
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
                elif mime in ['application/xml', 'text/xml']:
                    return 'xml'
                elif mime == 'text/csv':
                    return 'csv'
                elif mime in ['application/zip', 'application/x-zip-compressed']:
                    return 'zip'
                elif mime.startswith('image/'):
                    return ext or 'image'
            
            # Varsayılan olarak txt döndür
            return 'txt'
            
    except Exception as e:
        logger.error(f"Error determining file type for {file_path}: {str(e)}")
        return 'txt'  # Hata durumunda varsayılan

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
                patterns.extend(ALL_REGEX_PATTERNS_BACKEND.get(category, []))
                
        if selected_subcategories:
            for subcategory in selected_subcategories:
                for category in ALL_REGEX_PATTERNS_BACKEND.items():
                    if subcategory in category[1]:
                        patterns.extend(category[1][subcategory])
                        
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
                    
        # Sonuçları ve kullanılan pattern'leri oturuma kaydet
        request.session['regex_results'] = results
        request.session['regex_patterns'] = [p.pattern for p in compiled_patterns]
        
        return redirect('regex:regex_search_results')
        
    # GET isteği için
    return render(request, 'regex/regex_search.html', {
        'categories': get_category_names(),
        'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
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
    """Dosyayı karantinaya alır - AJAX ve form desteği ile."""
    file_path = urllib.parse.unquote(file_path)
    
    if request.method == 'POST':
        try:
            # Dosya güvenlik kontrolü
            if not os.path.exists(file_path):
                error_msg = 'Dosya bulunamadı.'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'error': error_msg})
                messages.error(request, error_msg)
                return redirect('regex:regex_search_results')
                
            if not is_safe_path(file_path):
                error_msg = 'Dosya güvenli değil.'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'error': error_msg})
                messages.error(request, error_msg)
                return redirect('regex:regex_search_results')
            
            # Karantina dizinini oluştur
            if hasattr(settings, 'MEDIA_ROOT') and settings.MEDIA_ROOT:
                quarantine_dir = os.path.join(settings.MEDIA_ROOT, 'quarantine', 'quarantined_files')
            else:
                quarantine_dir = os.path.join(settings.BASE_DIR, 'quarantine', 'quarantined_files')
                
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Dosya adı ve hedef yol
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_filename = f"{timestamp}_{file_name}.quarantine"
            quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
            
            # Dosyayı karantinaya taşı
            import shutil
            shutil.move(file_path, quarantine_path)
            
            # Karantina kayıt dosyası oluştur
            quarantine_info = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'quarantine_time': timestamp,
                'file_name': file_name,
                'file_size': os.path.getsize(quarantine_path),
                'quarantine_reason': 'Regex tarama sonucu'
            }
            
            info_file = os.path.join(quarantine_dir, f"{quarantine_filename}.info")
            import json
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(quarantine_info, f, indent=2, ensure_ascii=False)
            
            success_msg = f'Dosya başarıyla karantinaya alındı: {file_name}'
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True, 'message': success_msg})
            else:
                messages.success(request, success_msg)
                return redirect('regex:regex_search_results')
                
        except Exception as e:
            error_msg = f'Karantina hatası: {str(e)}'
            logger.error(error_msg)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': error_msg})
            else:
                messages.error(request, error_msg)
                return redirect('regex:regex_search_results')
    
    # GET isteği için
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': False, 'error': 'Geçersiz istek.'})
    else:
        return redirect('regex:regex_search_results')

def is_safe_path(path):
    """Dosya yolunun güvenli olup olmadığını kontrol eder."""
    try:
        # Mutlak yol kontrolü
        abs_path = os.path.abspath(path)
        
        # Ubuntu subsystem için güvenli dizin kontrolü
        allowed_patterns = [
            '/mnt/c/Users/',  # Windows C: sürücüsü Ubuntu subsystem üzerinden
            '/home/',         # Linux home dizini
            '/tmp/',          # Geçici dosyalar
            '/var/tmp/',      # Geçici dosyalar
            os.path.abspath(settings.BASE_DIR),  # Django proje dizini
        ]
        
        # Django MEDIA_ROOT varsa onu da ekle
        if hasattr(settings, 'MEDIA_ROOT') and settings.MEDIA_ROOT:
            allowed_patterns.append(os.path.abspath(settings.MEDIA_ROOT))
            
        # Güvenli yol kontrolü
        is_safe = any(abs_path.startswith(pattern) for pattern in allowed_patterns)
        
        # Tehlikeli yolları reddet
        dangerous_patterns = [
            '/etc/',
            '/var/log/',
            '/var/www/',
            '/usr/bin/',
            '/bin/',
            '/sbin/',
            '/boot/',
            '/proc/',
            '/sys/',
            '/dev/',
            '/root/',
            '/..',
            '../'
        ]
        
        is_dangerous = any(pattern in abs_path for pattern in dangerous_patterns)
        
        return is_safe and not is_dangerous
        
    except Exception as e:
        logger.error(f"Error checking path safety: {str(e)}")
        return False

def edit_file(request, file_path):
    """Dosya içeriğini düzenler - AJAX ve form desteği ile."""
    file_path = urllib.parse.unquote(file_path)
    
    if request.method == 'POST':
        try:
            # JSON verisi kontrolü (AJAX)
            if request.content_type == 'application/json':
                import json
                data = json.loads(request.body)
                content = data.get('content', '')
            else:
                # Form verisi
                content = request.POST.get('content', '')
                
            # Dosya güvenlik kontrolü
            if not is_safe_path(file_path):
                if request.content_type == 'application/json':
                    return JsonResponse({'success': False, 'error': 'Dosya güvenli değil.'})
                messages.error(request, 'Dosya güvenli değil.')
                return redirect('regex:regex_search_results')
                
            # Dosyayı kaydet
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            if request.content_type == 'application/json':
                return JsonResponse({'success': True, 'message': 'Dosya başarıyla güncellendi.'})
            else:
                messages.success(request, 'Dosya başarıyla güncellendi.')
                return redirect('regex:regex_search_results')
                
        except Exception as e:
            error_msg = f'Dosya güncelleme hatası: {str(e)}'
            logger.error(error_msg)
            if request.content_type == 'application/json':
                return JsonResponse({'success': False, 'error': error_msg})
            else:
                messages.error(request, error_msg)
                return redirect('regex:regex_search_results')
    
    # GET isteği - dosya içeriğini döndür
    try:
        if not os.path.exists(file_path):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Dosya bulunamadı.'})
            messages.error(request, 'Dosya bulunamadı.')
            return redirect('regex:regex_search_results')
            
        if not is_safe_path(file_path):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Dosya güvenli değil.'})
            messages.error(request, 'Dosya güvenli değil.')
            return redirect('regex:regex_search_results')

        # Dosya içeriğini oku
        content = get_file_content(file_path)
        if content is None:
            content = ''
            
        # AJAX isteği ise JSON döndür
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'content': content,
                'file_name': os.path.basename(file_path),
                'file_path': file_path
            })
        
        # Normal sayfa isteği
        return render(request, 'regex/edit_file.html', {
            'file_path': file_path,
            'content': content,
            'file_name': os.path.basename(file_path)
        })
        
    except Exception as e:
        error_msg = f'Dosya okuma hatası: {str(e)}'
        logger.error(error_msg)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'error': error_msg})
        else:
            messages.error(request, error_msg)
            return redirect('regex:regex_search_results')

def get_category_names():
    """Kategori isimlerini döndürür."""
    return ALL_REGEX_PATTERNS_BACKEND.get_category_names()

def sensitive_scan(request):
    """Hassas veri taraması sayfasını gösterir ve tarama sonuçlarını işler."""
    if request.method == 'POST':
        directory = request.POST.get('directory', '').strip()
        selected_categories = request.POST.getlist('categories')
        selected_subcategories = request.POST.getlist('subcategories[]')
        selected_file_types = request.POST.getlist('file_types')

        if not directory:
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Lütfen bir dizin seçin.',
                'categories': get_category_names(),
                'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
            })

        if not os.path.exists(directory):
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': f'Dizin bulunamadı: {directory}',
                'categories': get_category_names(),
                'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
            })

        patterns = []
        if selected_categories:
            for category in selected_categories:
                patterns.extend(ALL_REGEX_PATTERNS_BACKEND.get_patterns_by_category(category))

        if selected_subcategories:
            for subcategory in selected_subcategories:
                for category in ALL_REGEX_PATTERNS_BACKEND.categories.values():
                    if subcategory in category.get('subcategories', {}):
                        patterns.extend(category['subcategories'][subcategory]['patterns'])

        if not patterns:
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Lütfen en az bir kategori veya alt kategori seçin.',
                'categories': get_category_names(),
                'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
            })

        results = []
        error_files = []
        skipped_files = []

        # Derlenmiş regex desenleri
        compiled_patterns = []
        for pattern in patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                logger.error(f"Regex derleme hatası: {pattern} - {str(e)}")

        for root, dirs, files in os.walk(directory):
            # Gizli dizinleri ve özel dizinleri atla
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower().lstrip('.')

                # Dosya türü kontrolü
                if file_ext not in selected_file_types:
                    continue

                # Dosya boyutu kontrolü (5MB'dan büyük dosyaları atla)
                try:
                    if os.path.getsize(file_path) > 5 * 1024 * 1024:
                        skipped_files.append(f"{file_path} (Dosya boyutu çok büyük: >5MB)")
                        continue
                except OSError as e:
                    error_files.append(f"{file_path} (Dosya boyutu alınamadı: {str(e)})")
                    continue

                # Dosya içeriğini oku
                try:
                    # Önce dosyanın metin dosyası olup olmadığını kontrol et
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        if b'\x00' in chunk:  # Binary dosya kontrolü
                            skipped_files.append(f"{file_path} (Binary dosya)")
                            continue

                    # Dosyayı oku
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_matches = defaultdict(lambda: defaultdict(list))

                        # Her desen için eşleşmeleri ara
                        for pattern in compiled_patterns:
                            for match in pattern.finditer(content):
                                line_number = content[:match.start()].count('\n') + 1
                                line = content.split('\n')[line_number - 1]
                                context = get_context_lines(content, line_number)

                                # Eşleşmenin hangi kategori ve alt kategoriye ait olduğunu bul
                                for category, data in ALL_REGEX_PATTERNS_BACKEND.categories.items():
                                    for subcategory, subdata in data['subcategories'].items():
                                        if pattern.pattern in subdata['patterns']:
                                            file_matches[data['name']][subdata['name']].append({
                                                'line': line_number,
                                                'match': match.group(),
                                                'context': context,
                                                'pattern': pattern.pattern
                                            })

                        if file_matches:
                            results.append({
                                'file_path': file_path,
                                'matches': file_matches
                            })

                except UnicodeDecodeError:
                    error_files.append(f"{file_path} (Karakter kodlaması hatası)")
                except PermissionError:
                    error_files.append(f"{file_path} (Erişim izni yok)")
                except Exception as e:
                    error_files.append(f"{file_path} ({str(e)})")

        return render(request, 'regex/sensitive_scan_results.html', {
            'results': results,
            'error_files': error_files,
            'skipped_files': skipped_files,
            'directory': directory,
            'stats': {
                'total_files': len(results) + len(error_files) + len(skipped_files),
                'matched_files': len(results),
                'error_files': len(error_files),
                'skipped_files': len(skipped_files)
            }
        })

    return render(request, 'regex/sensitive_scan.html', {
        'categories': get_category_names(),
        'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
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
    """Hassas veri taraması sonuçlarının detaylarını gösterir."""
    try:
        # Dosya içeriğini oku
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Eşleşmeleri bul
        matches = []
        for category, data in ALL_REGEX_PATTERNS_BACKEND.categories.items():
            for subcategory, subdata in data['subcategories'].items():
                for pattern in subdata['patterns']:
                    try:
                        compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        for match in compiled_pattern.finditer(content):
                            line_number = content[:match.start()].count('\n') + 1
                            line = content.split('\n')[line_number - 1]
                            context = get_context_lines(content, line_number)
                            matches.append({
                                'category': data['name'],
                                'subcategory': subdata['name'],
                                'line': line_number,
                                'match': match.group(),
                                'context': context,
                                'pattern': pattern
                            })
                    except re.error as e:
                        logger.error(f"Regex derleme hatası: {pattern} - {str(e)}")
                        continue

        # Eşleşmeleri satır numarasına göre sırala
        matches.sort(key=lambda x: x['line'])

        return render(request, 'regex/sensitive_scan_detail.html', {
            'file_path': file_path,
            'matches': matches,
            'quarantine_url': reverse('regex:quarantine_file', kwargs={'file_path': file_path})
        })

    except Exception as e:
        return render(request, 'regex/sensitive_scan_detail.html', {
            'error_message': f'Dosya işlenirken bir hata oluştu: {str(e)}',
            'file_path': file_path
        })

def api_get_regex_patterns(request):
    """Regex desenlerini JSON formatında döndürür."""
    patterns = {
        'categories': ALL_REGEX_PATTERNS_BACKEND.categories,
        'file_types': ALL_REGEX_PATTERNS_BACKEND.file_types
    }
    return JsonResponse(patterns)

def quarantine_list(request):
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    return render(request, 'regex/quarantine_list.html', {'files': files})

def view_file(request, file_path):
    """Dosyayı görüntüler ve eşleşen regex pattern'lerini işaretler."""
    try:
        file_path = urllib.parse.unquote(file_path)
        
        if not os.path.exists(file_path):
            return render(request, 'regex/file_viewer.html', {
                'error_message': 'Dosya bulunamadı.',
                'file_path': file_path
            })
            
        if not is_safe_path(file_path):
            return render(request, 'regex/file_viewer.html', {
                'error_message': 'Dosya güvenli değil veya erişim izniniz yok.',
                'file_path': file_path
            })
        
        # Session'dan regex pattern'lerini al
        patterns = request.session.get('regex_patterns', [])
        
        content = get_file_content(file_path)
        if content is None:
            return render(request, 'regex/file_viewer.html', {
                'error_message': 'Dosya içeriği okunamadı.',
                'file_path': file_path
            })
            
        # Eğer content bir hata mesajı ise
        if isinstance(content, str) and content.startswith(('PDF dosyası', 'Dosya açılamıyor')):
            return render(request, 'regex/file_viewer.html', {
                'error_message': content,
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_type': get_file_type(file_path),
                'file_size': os.path.getsize(file_path)
            })
        
        file_type = get_file_type(file_path)
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Regex eşleşmelerini bul
        all_matches = []
        highlighted_content = content
        
        if patterns and content:
            # Tüm pattern'ler için eşleşmeleri bul
            for pattern in patterns:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                    pattern_matches = list(compiled_pattern.finditer(content))
                    all_matches.extend(pattern_matches)
                except re.error as e:
                    logger.error(f"Regex error for pattern '{pattern}': {str(e)}")
            
            # Eşleşmeleri pozisyona göre sırala
            all_matches.sort(key=lambda m: m.start())
            
            # İçeriği HTML için escape et
            import html
            highlighted_content = html.escape(content)
            
            # Eşleşmeleri işaretle (üstü çizili yap)
            if all_matches:
                offset = 0
                for match in all_matches:
                    start = match.start() + offset
                    end = match.end() + offset
                    matched_text = highlighted_content[start:end]
                    
                    # HTML işaretlemesi ekle
                    marked_text = f'<mark style="text-decoration: line-through; background-color: #ffeb3b;">{matched_text}</mark>'
                    
                    highlighted_content = highlighted_content[:start] + marked_text + highlighted_content[end:]
                    offset += len(marked_text) - len(matched_text)
        
        # Desteklenen dosya türleri
        viewable_types = ['txt', 'html', 'htm', 'css', 'js', 'json', 'xml', 'yaml', 'yml', 'md', 'log', 'ini', 'conf', 'cfg', 'properties']
        
        context = {
            'file_path': file_path,
            'file_name': file_name,
            'file_type': file_type,
            'file_size': file_size,
            'content': highlighted_content,
            'original_content': content,
            'patterns': patterns,
            'pattern': ', '.join(patterns) if patterns else '',
            'matches_count': len(all_matches),
            'is_viewable': file_type in viewable_types or file_type in ['pdf', 'docx', 'doc', 'pptx', 'ppt'],
            'is_text_file': file_type in viewable_types,
            'is_office_file': file_type in ['pdf', 'docx', 'doc', 'pptx', 'ppt'],
        }
        
        return render(request, 'regex/file_viewer.html', context)
        
    except Exception as e:
        logger.error(f"Error viewing file {file_path}: {str(e)}")
        return render(request, 'regex/file_viewer.html', {
            'error_message': f'Dosya görüntülenirken hata oluştu: {str(e)}',
            'file_path': file_path
        })
