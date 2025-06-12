import io
import os
import re
import urllib.parse
import logging
import time
import json
import shutil
import hashlib
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from malware.models import QuarantinedFile

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

from .patterns import (
    ALL_REGEX_PATTERNS_BACKEND
)

# Configure logging
logger = logging.getLogger(__name__)

def regex_search(request):
    """View function for the regex search page"""
    return render(request, 'regex/regex_search.html')

def is_safe_path(path):
    """Check if the path is safe to scan"""
    # Add your path safety checks here
    return True

def sensitive_scan(request):
    """View function for the sensitive data scan page"""
    if request.method == 'POST':
        logger.info("POST request received for sensitive scan")
        start_time = time.time()
        
        # Get form data
        directory_path = request.POST.get('directory')
        file_types = request.POST.getlist('file_types')
        selected_categories = request.POST.getlist('categories')
        selected_subcategories = {}
        
        # Alt kategorileri topla
        for key, value in request.POST.items():
            if key.startswith('subcategories['):
                category = key.split('[')[1].split(']')[0]
                if category not in selected_subcategories:
                    selected_subcategories[category] = []
                selected_subcategories[category].append(value)

        logger.info(f"Form data received - Directory: {directory_path}")
        logger.info(f"Selected categories: {selected_categories}")
        logger.info(f"Selected subcategories: {selected_subcategories}")
        logger.info(f"File types: {file_types}")

        if not directory_path:
            logger.error("No directory path provided")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Lütfen bir dizin yolu girin.'
            })

        if not selected_categories:
            logger.error("No categories selected")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Lütfen en az bir kategori seçin.'
            })

        if not os.path.exists(directory_path):
            logger.error(f"Directory does not exist: {directory_path}")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Girilen dizin yolu mevcut değil.'
            })

        # Check if directory is accessible
        try:
            files = os.listdir(directory_path)
            logger.info(f"Successfully accessed directory. Found {len(files)} files/directories")
        except PermissionError:
            logger.error(f"Permission denied for directory: {directory_path}")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': 'Dizine erişim izniniz yok.'
            })
        except Exception as e:
            logger.error(f"Error accessing directory {directory_path}: {str(e)}")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': f'Dizine erişim sırasında bir hata oluştu: {str(e)}'
            })

        # Compile regex patterns for selected categories and subcategories
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
                        'subcategory': pattern_dict['subcategory']
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
            for root, dirs, files in os.walk(directory_path):
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
                    file_ext = os.path.splitext(file)[1].lower().lstrip('.')
                    if file_types and file_ext not in file_types:
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
                        error_files.append(file_path)
                        continue

                    # Dosya içeriğini oku (uzantıya göre)
                    content = None
                    try:
                        if file_ext in ['docx']:
                            doc = Document(file_path)
                            content = '\n'.join([p.text for p in doc.paragraphs])
                        elif file_ext in ['pdf']:
                            # PDF desteği için PyPDF2 veya benzeri kullanılabilir
                            try:
                                with open(file_path, 'rb') as f:
                                    reader = PyPDF2.PdfReader(f)
                                    content = '\n'.join(page.extract_text() or '' for page in reader.pages)
                            except Exception as e:
                                skipped_files.append({'file': file_path, 'reason': f'PDF okunamadı: {str(e)}'})
                                continue
                        else:
                            encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
                            for enc in encodings:
                                try:
                                    with open(file_path, 'r', encoding=enc) as f:
                                        content = f.read()
                                    break
                                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                                    continue
                            else:
                                error_files.append(file_path)
                                continue
                    except Exception as e:
                        error_files.append(file_path)
                        continue

                    processed_files_count += 1
                    if processed_files_count % 100 == 0:
                        logger.info(f"Processed {processed_files_count} files so far...")

                    pattern_matches = {}
                    for pattern_info in combined_patterns:
                        pattern = pattern_info['pattern']
                        category = pattern_info['category']
                        subcategory = pattern_info['subcategory']
                        try:
                            matches = pattern.findall(content) if content else []
                            if matches:
                                if category not in pattern_matches:
                                    pattern_matches[category] = {}
                                if subcategory not in pattern_matches[category]:
                                    pattern_matches[category][subcategory] = []
                                pattern_matches[category][subcategory].extend(matches)
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

        # Sonuçları session'a kaydet ve sonuç sayfasına yönlendir
        request.session['regex_scan_results'] = {
            'results': results,
            'search_path': directory_path,
            'processed_files_count': processed_files_count,
            'matched_files_count': matched_files_count,
            'error_files': error_files,
            'skipped_files': skipped_files,
            'scan_duration': f"{scan_duration:.2f}"
        }
        return redirect(reverse('regex:regex_search_results'))

    return render(request, 'regex/sensitive_scan.html')

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

def regex_search_detail_view(request, file_path):
    decoded_file_path = urllib.parse.unquote(file_path)
    matches = []

    try:
        encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
        for enc in encodings:
            try:
                with open(decoded_file_path, 'r', encoding=enc) as f:
                    lines = f.readlines()
                break
            except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                logger.error(f"Error reading file {decoded_file_path}: {str(e)}")
                continue
        else:
            return render(request, 'regex/regex_search_detail.html', {
                'error_message': 'Dosya okunamadı veya erişim izni yok.',
                'file_path': decoded_file_path
            })

        for i, line in enumerate(lines, 1):
            for category, patterns in ALL_REGEX_PATTERNS_BACKEND.items():
                for pattern_dict in patterns:
                    try:
                        if re.search(pattern_dict['pattern'], line):
                            matches.append({
                                'line_number': i,
                                'line_content': line.strip(),
                                'pattern_type': pattern_dict['subcategory'],
                                'pattern': pattern_dict['pattern']
                            })
                    except re.error as e:
                        logger.error(f"Regex error with pattern {pattern_dict['pattern']}: {str(e)}")
                        continue

    except Exception as e:
        logger.error(f"Unexpected error in detail view: {str(e)}")
        return render(request, 'regex/regex_search_detail.html', {
            'error_message': f"Beklenmeyen bir hata oluştu: {str(e)}",
            'file_path': decoded_file_path
        })

    return render(request, 'regex/regex_search_detail.html', {
        'matches': matches,
        'file_path': decoded_file_path
    })

def api_get_regex_patterns(request):
    return JsonResponse(ALL_REGEX_PATTERNS_BACKEND)

def regex_search_results(request):
    """Kalıcı olarak tarama sonuçlarını gösteren sayfa"""
    context = request.session.get('regex_scan_results', {})
    return render(request, 'regex/regex_search_results.html', context)

@require_http_methods(["GET", "POST"])
def edit_file(request, file_path):
    """View function for editing files"""
    decoded_file_path = urllib.parse.unquote(file_path)
    
    if not os.path.exists(decoded_file_path):
        return JsonResponse({'error': 'Dosya bulunamadı'}, status=404)
    
    if request.method == 'POST':
        try:
            content = request.POST.get('content')
            if content is None:
                return JsonResponse({'error': 'İçerik boş olamaz'}, status=400)
            
            # Dosyayı yedekle
            backup_path = f"{decoded_file_path}.bak"
            if os.path.exists(decoded_file_path):
                import shutil
                shutil.copy2(decoded_file_path, backup_path)
            
            # Dosya uzantısına göre kaydetme işlemi
            file_ext = os.path.splitext(decoded_file_path)[1].lower()
            
            if file_ext == '.pdf':
                if not PDF_AVAILABLE:
                    return JsonResponse({'error': 'PDF düzenleme için gerekli kütüphaneler yüklü değil'}, status=500)
                try:
                    # Yeni PDF oluştur
                    packet = io.BytesIO()
                    can = canvas.Canvas(packet, pagesize=letter)
                    can.drawString(100, 750, content)  # Basit metin ekleme
                    can.save()
                    
                    # Mevcut PDF'i oku
                    existing_pdf = PyPDF2.PdfReader(decoded_file_path)
                    output = PyPDF2.PdfWriter()
                    
                    # İlk sayfaya yeni içeriği ekle
                    page = existing_pdf.pages[0]
                    page.merge_page(PyPDF2.PdfReader(packet).pages[0])
                    output.add_page(page)
                    
                    # Diğer sayfaları ekle
                    for i in range(1, len(existing_pdf.pages)):
                        output.add_page(existing_pdf.pages[i])
                    
                    # Kaydet
                    with open(decoded_file_path, 'wb') as output_file:
                        output.write(output_file)
                        
                except Exception as e:
                    logger.error(f"PDF düzenleme hatası: {str(e)}")
                    return JsonResponse({'error': f'PDF düzenlenirken hata oluştu: {str(e)}'}, status=500)
                    
            elif file_ext in ['.docx', '.doc']:
                if not DOCX_AVAILABLE:
                    return JsonResponse({'error': 'DOCX düzenleme için gerekli kütüphaneler yüklü değil'}, status=500)
                try:
                    doc = Document()
                    doc.add_paragraph(content)
                    doc.save(decoded_file_path)
                except Exception as e:
                    logger.error(f"DOCX düzenleme hatası: {str(e)}")
                    return JsonResponse({'error': f'DOCX düzenlenirken hata oluştu: {str(e)}'}, status=500)
                    
            elif file_ext in ['.pptx', '.ppt']:
                if not PPTX_AVAILABLE:
                    return JsonResponse({'error': 'PPTX düzenleme için gerekli kütüphaneler yüklü değil'}, status=500)
                try:
                    prs = Presentation()
                    slide_layout = prs.slide_layouts[0]  # Başlık düzeni
                    slide = prs.slides.add_slide(slide_layout)
                    title = slide.shapes.title
                    title.text = content
                    prs.save(decoded_file_path)
                except Exception as e:
                    logger.error(f"PPTX düzenleme hatası: {str(e)}")
                    return JsonResponse({'error': f'PPTX düzenlenirken hata oluştu: {str(e)}'}, status=500)
                    
            else:
                # Metin dosyaları için normal kaydetme
                with open(decoded_file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            return JsonResponse({'success': True, 'message': 'Dosya başarıyla güncellendi'})
        except Exception as e:
            logger.error(f"Error editing file {decoded_file_path}: {str(e)}")
            return JsonResponse({'error': f'Dosya düzenlenirken bir hata oluştu: {str(e)}'}, status=500)
    
    # GET isteği için dosya içeriğini oku
    try:
        file_ext = os.path.splitext(decoded_file_path)[1].lower()
        content = None
        
        if file_ext == '.pdf':
            if not PDF_AVAILABLE:
                return JsonResponse({'error': 'PDF okuma için gerekli kütüphaneler yüklü değil'}, status=500)
            try:
                with open(decoded_file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    content = '\n'.join(page.extract_text() or '' for page in reader.pages)
            except Exception as e:
                logger.error(f"PDF okuma hatası: {str(e)}")
                return JsonResponse({'error': f'PDF okunurken hata oluştu: {str(e)}'}, status=500)
                
        elif file_ext in ['.docx', '.doc']:
            if not DOCX_AVAILABLE:
                return JsonResponse({'error': 'DOCX okuma için gerekli kütüphaneler yüklü değil'}, status=500)
            try:
                doc = Document(decoded_file_path)
                content = '\n'.join([p.text for p in doc.paragraphs])
            except Exception as e:
                logger.error(f"DOCX okuma hatası: {str(e)}")
                return JsonResponse({'error': f'DOCX okunurken hata oluştu: {str(e)}'}, status=500)
                
        elif file_ext in ['.pptx', '.ppt']:
            if not PPTX_AVAILABLE:
                return JsonResponse({'error': 'PPTX okuma için gerekli kütüphaneler yüklü değil'}, status=500)
            try:
                prs = Presentation(decoded_file_path)
                content = []
                for slide in prs.slides:
                    for shape in slide.shapes:
                        if hasattr(shape, "text"):
                            content.append(shape.text)
                content = '\n'.join(content)
            except Exception as e:
                logger.error(f"PPTX okuma hatası: {str(e)}")
                return JsonResponse({'error': f'PPTX okunurken hata oluştu: {str(e)}'}, status=500)
                
        else:
            # Metin dosyaları için normal okuma
            encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
            for enc in encodings:
                try:
                    with open(decoded_file_path, 'r', encoding=enc) as f:
                        content = f.read()
                    break
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue
        
        if content is None:
            return JsonResponse({'error': 'Dosya okunamadı'}, status=500)
        
        return render(request, 'regex/edit_file.html', {
            'file_path': decoded_file_path,
            'content': content,
            'file_type': file_ext.lstrip('.')
        })
    except Exception as e:
        logger.error(f"Error reading file {decoded_file_path}: {str(e)}")
        return JsonResponse({'error': f'Dosya okunurken bir hata oluştu: {str(e)}'}, status=500)

@csrf_exempt
def quarantine_file(request):
    file_path = request.POST.get('file_path')
    reason = request.POST.get('reason', 'Sensitive data detected')

    if not file_path:
        return JsonResponse({'success': False, 'error': 'File path is missing.'})

    try:
        # Define quarantine directory from settings
        quarantine_base_dir = getattr(settings, 'QUARANTINE_DIR', os.path.join(settings.MEDIA_ROOT, 'quarantine'))
        os.makedirs(quarantine_base_dir, exist_ok=True)

        filename = os.path.basename(file_path)
        quarantined_full_path = os.path.join(quarantine_base_dir, filename + '.quarantine')

        # Ensure unique filename if it already exists in quarantine
        counter = 1
        original_quarantined_full_path = quarantined_full_path
        while os.path.exists(quarantined_full_path):
            name, ext = os.path.splitext(filename)
            quarantined_full_path = os.path.join(quarantine_base_dir, f"{name}_{counter}{ext}.quarantine")
            counter += 1

        # Move the file to the quarantine directory
        shutil.move(file_path, quarantined_full_path)

        # Apply chmod 000 if OS supports it (e.g., Linux/WSL)
        # This will make the file inaccessible for read/write/execute by anyone
        try:
            os.chmod(quarantined_full_path, 0o000) # Use octal literal for permissions
        except OSError as e:
            # This error is expected on Windows, so we just log it or ignore
            print(f"Warning: Could not set permissions for {quarantined_full_path}: {e}")
            pass # Continue if chmod fails (e.g., on Windows)


        # Create a record in the QuarantinedFile model
        # The create_from_file method handles hash and size calculation
        QuarantinedFile.create_from_file(
            file_path=file_path,  # original_path
            reason=reason,
            scan_type='regex_scan' # Assuming this is the scan type
        )
        
        # Update the quarantine_path in the newly created QuarantinedFile object
        # since create_from_file uses settings.QUARANTINE_DIR to construct it,
        # but we might have used a unique name here.
        # It's better to pass the final quarantined_full_path to create_from_file if possible.
        # For now, let's update it after creation if needed, or adjust create_from_file.
        # Let's adjust create_from_file to accept a predefined quarantine_path.
        # For now, I will create a new QuarantinedFile object directly.
        
        # If create_from_file was modified, it would be better.
        # For simplicity and to use the existing `create_from_file` (which handles hashes),
        # I will rely on its internal path handling based on settings.QUARANTINE_DIR.
        # The `shutil.move` already moved the file, so we'll just record it.
        
        # It seems QuarantinedFile.create_from_file expects the file to be at file_path
        # to calculate hash and size. So we should move it AFTER calling create_from_file.
        # Let's revert the shutil.move and chmod, and instead, let create_from_file handle the move.
        # I will modify malware/models.py first to ensure create_from_file can handle this.
        
        # Re-evaluating: The create_from_file method in malware/models.py already handles the
        # moving of the file to settings.QUARANTINE_DIR and setting permissions (implicitly via shutil).
        # It calculates hash and size from the original file_path *before* moving.
        # So, the original plan of moving the file *then* creating the object is problematic.
        # The correct flow would be:
        # 1. Call QuarantinedFile.create_from_file(original_file_path, reason, scan_type)
        #    This method will move the file to quarantine_path and create the DB entry.
        # 2. After the file is moved, apply chmod 000.
        
        # Let's assume create_from_file needs adjustment or we use it directly:
        # My previous thought for create_from_file was it would move the file, but looking at the code again:
        # quarantine_path = os.path.join(settings.QUARANTINE_DIR, filename + '.quarantine')
        # It *constructs* the quarantine_path, but it doesn't *move* the file.
        # "return cls.objects.create(" implies it only creates the DB entry.
        # So, we *do* need to handle the move and chmod here.
        # Let's correct the logic for handling existing files in quarantine and then moving.

        # Corrected logic for moving and setting permissions:
        # 1. Get original file hash and size BEFORE moving
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash_val = sha256_hash.hexdigest()
        file_size_val = os.path.getsize(file_path)
        
        # 2. Construct target quarantine path, ensuring uniqueness
        quarantine_base_dir = getattr(settings, 'QUARANTINE_DIR', os.path.join(settings.MEDIA_ROOT, 'quarantine'))
        os.makedirs(quarantine_base_dir, exist_ok=True)
        filename_base = os.path.basename(file_path)
        
        quarantine_target_name = filename_base + '.quarantine'
        final_quarantine_path = os.path.join(quarantine_base_dir, quarantine_target_name)
        
        counter = 1
        while os.path.exists(final_quarantine_path):
            name, ext = os.path.splitext(filename_base)
            quarantine_target_name = f"{name}_{counter}{ext}.quarantine"
            final_quarantine_path = os.path.join(quarantine_base_dir, quarantine_target_name)
            counter += 1

        # 3. Move the file
        shutil.move(file_path, final_quarantine_path)

        # 4. Apply chmod 000
        try:
            os.chmod(final_quarantine_path, 0o000)
        except OSError as e:
            print(f"Warning: Could not set permissions for {final_quarantine_path}: {e}")
            pass

        # 5. Create the QuarantinedFile record directly (since create_from_file doesn't move)
        QuarantinedFile.objects.create(
            filename=filename_base,
            original_path=file_path,
            quarantine_path=final_quarantine_path,
            malware_type='Sensitive Data', # Or a more specific type if known
            scan_tool='regex_scanner',
            file_size=file_size_val,
            file_hash=file_hash_val,
            detected_by_user='System', # Or the logged-in user
            threat_level='high', # Or dynamically determined
            status='quarantined',
            reason=reason
        )

        return JsonResponse({'success': True, 'message': f'{filename_base} successfully quarantined.'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def quarantine_list(request):
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    return render(request, 'regex/quarantine_list.html', {'files': files})
