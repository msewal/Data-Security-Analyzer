import io
import os
import re
import urllib.parse
import logging
import time
import json
import shutil
import hashlib
import concurrent.futures
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.urls import reverse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from malware.models import QuarantinedFile
from django.contrib import messages
from datetime import datetime

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

# Configure logging
logger = logging.getLogger(__name__)

# Add caching for patterns
_cached_patterns = None

def load_patterns():
    global _cached_patterns
    if _cached_patterns is not None:
        return _cached_patterns

    patterns_file_path = os.path.join(settings.BASE_DIR, 'regex', 'patterns.json')
    loaded_patterns = []
    try:
        with open(patterns_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for pattern_dict in data.get('patterns', []):
                try:
                    flags = re.IGNORECASE | re.MULTILINE
                    # 'greedy' field is for semantic meaning, regex behavior is determined by the pattern itself
                    
                    compiled_pattern = re.compile(pattern_dict['regex'], flags)
                    loaded_patterns.append({
                        'name': pattern_dict['name'],
                        'regex': pattern_dict['regex'], # Keep original regex string for display
                        'compiled_pattern': compiled_pattern,
                        'description': pattern_dict.get('description'),
                        'category': pattern_dict.get('category'),
                        'risk_level': pattern_dict.get('risk_level'),
                        'validation_function': pattern_dict.get('validation_function'),
                        'subcategory': pattern_dict.get('subcategory', 'Genel') # Default subcategory if not provided
                    })
                except re.error as e:
                    logger.error(f"Error compiling pattern {pattern_dict.get('regex', 'N/A')}: {str(e)}")
                    continue
    except FileNotFoundError:
        logger.error(f"Patterns file not found at: {patterns_file_path}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from patterns file: {str(e)}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading patterns: {str(e)}")

    _cached_patterns = loaded_patterns
    return _cached_patterns

# Placeholder validation functions
def validate_tc_kimlik(tc_kimlik_no):
    # Check if the number is 11 digits and all are digits
    if not isinstance(tc_kimlik_no, str) or len(tc_kimlik_no) != 11 or not tc_kimlik_no.isdigit():
        return False
    
    # First digit cannot be 0
    if tc_kimlik_no[0] == '0':
        return False
    
    digits = [int(d) for d in tc_kimlik_no]

    # Calculate 10th digit based on the algorithm
    sum_odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    sum_even = digits[1] + digits[3] + digits[5] + digits[7]
    
    tenth_digit_calc = (sum_odd * 7 - sum_even) % 10
    
    if tenth_digit_calc != digits[9]:
        return False
        
    # Calculate 11th digit based on the algorithm
    eleventh_digit_calc = (sum(digits[i] for i in range(10))) % 10
    
    if eleventh_digit_calc != digits[10]:
        return False

    return True

def validate_luhn(card_no):
    # Remove any non-digit characters
    cleaned_card_no = re.sub(r'\D', '', card_no)
    
    if not cleaned_card_no.isdigit() or len(cleaned_card_no) < 13 or len(cleaned_card_no) > 19:
        return False

    # Luhn algorithm implementation
    digits = [int(d) for d in cleaned_card_no]
    
    # Double every second digit from the right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
            
    # Sum all digits
    total_sum = sum(digits)
    
    # If the total sum is divisible by 10, the number is valid
    return total_sum % 10 == 0

def regex_search(request):
    """View function for the regex search page"""
    return render(request, 'regex/regex_search.html')

def is_safe_path(path):
    """Check if the path is safe to scan"""
    # Add your path safety checks here
    return True

def _scan_single_file(file_path, combined_patterns, quarantined_paths, file_types, logger):
    results_for_file = {
        'processed_files_count': 0,
        'matched_files_count': 0,
        'error_files': [],
        'skipped_files': [],
        'file_results': None
    }

    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1].lower().lstrip('.')

    # Check if file is quarantined
    if file_path in quarantined_paths:
        results_for_file['skipped_files'].append({'file': file_path, 'reason': 'Karantinaya alınmış dosya'})
        return results_for_file

    # Skip certain file types
    if file_name.startswith('.') or file_name.endswith(('.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin')):
        results_for_file['skipped_files'].append({'file': file_path, 'reason': 'Gizli veya derlenmiş dosya'})
        return results_for_file

    # Check file extension
    if file_types and file_ext not in file_types:
        results_for_file['skipped_files'].append({'file': file_path, 'reason': 'Desteklenmeyen dosya uzantısı'})
        return results_for_file

    if not is_safe_path(file_path):
        logger.debug(f"Skipping unsafe file: {file_path}")
        results_for_file['skipped_files'].append({'file': file_path, 'reason': 'Güvensiz yol'})
        return results_for_file

    # Skip binary files and large files
    try:
        if os.path.getsize(file_path) > 5 * 1024 * 1024:  # Skip files larger than 5MB
            logger.debug(f"Skipping large file: {file_path}")
            results_for_file['skipped_files'].append({'file': file_path, 'reason': 'Büyük dosya (>5MB)'})
            return results_for_file
    except OSError as e:
        logger.error(f"Error getting file size for {file_path}: {str(e)}")
        results_for_file['error_files'].append({'path': file_path, 'error': str(e)})
        return results_for_file

    content_lines = []
    try:
        if file_ext in ['docx']:
            doc = Document(file_path)
            content_lines = [p.text for p in doc.paragraphs]
        elif file_ext in ['pdf']:
            try:
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    content_lines = [page.extract_text() or '' for page in reader.pages]
            except Exception as e:
                results_for_file['skipped_files'].append({'file': file_path, 'reason': f'PDF okunamadı: {str(e)}'})
                return results_for_file
        else:
            encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
            for enc in encodings:
                try:
                    with open(file_path, 'r', encoding=enc) as f:
                        for line in f:
                            content_lines.append(line)
                    break
                except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                    continue
            else:
                results_for_file['error_files'].append({'path': file_path, 'error': 'Dosya okunamadı veya erişim izni yok'})
                return results_for_file
    except Exception as e:
        results_for_file['error_files'].append({'path': file_path, 'error': str(e)})
        return results_for_file

    results_for_file['processed_files_count'] = 1
    found_matches_in_file = False
    pattern_matches = {}
    
    for line_num, line_content in enumerate(content_lines, 1):
        for pattern_info in combined_patterns:
            pattern = pattern_info['compiled_pattern']
            category = pattern_info['category']
            subcategory = pattern_info['subcategory']
            validation_func_name = pattern_info.get('validation_function')

            try:
                matches = pattern.findall(line_content) if line_content else []
                if matches:
                    validated_matches = []
                    for match in matches:
                        is_valid = True
                        if validation_func_name:
                            validation_func = globals().get(validation_func_name)
                            if validation_func and callable(validation_func):
                                if not validation_func(match):
                                    is_valid = False
                                    logger.debug(f"Match '{match}' failed validation for {validation_func_name} in file {file_path} at line {line_num}")
                            else:
                                logger.warning(f"Validation function '{validation_func_name}' not found or not callable.")

                        if is_valid:
                            validated_matches.append({
                                'match': match,
                                'line_number': line_num,
                                'line_content': line_content.strip()
                            })

                    if validated_matches:
                        found_matches_in_file = True
                        if category not in pattern_matches:
                            pattern_matches[category] = {}
                        if subcategory not in pattern_matches[category]:
                            pattern_matches[category][subcategory] = []
                        pattern_matches[category][subcategory].extend(validated_matches)

            except Exception as e:
                logger.error(f"Error during pattern matching for {pattern_info.get('name', 'N/A')} in file {file_path} at line {line_num}: {str(e)}")
                continue

    if found_matches_in_file:
        results_for_file['matched_files_count'] = 1
        results_for_file['file_results'] = {
            'file_path': file_path,
            'matches': pattern_matches,
            'encoded_file_path': urllib.parse.quote_plus(file_path)
        }
    
    return results_for_file

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
            patterns = load_patterns()
            logger.info(f"Found {len(patterns)} patterns for category: {category}")
            
            # Eğer bu kategori için alt kategoriler seçilmişse, sadece onları derle
            if category in selected_subcategories:
                patterns = [p for p in patterns if p['subcategory'] in selected_subcategories[category]]
            
            for pattern_dict in patterns:
                try:
                    compiled_pattern = re.compile(pattern_dict['regex'], re.IGNORECASE | re.MULTILINE)
                    combined_patterns.append({
                        'name': pattern_dict['name'],
                        'regex': pattern_dict['regex'],
                        'compiled_pattern': compiled_pattern,
                        'description': pattern_dict.get('description'),
                        'category': category,
                        'subcategory': pattern_dict['subcategory'],
                        'risk_level': pattern_dict.get('risk_level'),
                        'validation_function': pattern_dict.get('validation_function')
                    })
                except re.error as e:
                    logger.error(f"Error compiling pattern {pattern_dict['regex']}: {str(e)}")
                    continue

        logger.info(f"Total combined patterns: {len(combined_patterns)}")

        # Fetch all quarantined file paths to exclude them from scanning
        quarantined_paths = set(QuarantinedFile.objects.filter(status='quarantined').values_list('original_path', flat=True))
        logger.info(f"Found {len(quarantined_paths)} files in quarantine. These will be skipped.")

        files_to_scan = []
        try:
            logger.info("Starting file walk to collect paths...")
            for root, dirs, files in os.walk(directory_path):
                # Skip certain directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__', 'quarantine']]

                if time.time() - start_time > 300: # Timeout for collecting files
                    logger.warning("File collection timeout reached after 5 minutes")
                    return render(request, 'regex/sensitive_scan.html', {
                        'error_message': 'Dosya toplama zaman aşımına uğradı (5 dakika). Lütfen daha küçük bir dizin seçin.'
                    })

                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    files_to_scan.append(file_path)
            logger.info(f"Collected {len(files_to_scan)} files for scanning.")

        except Exception as e:
            logger.error(f"Error during file path collection: {str(e)}")
            return render(request, 'regex/sensitive_scan.html', {
                'error_message': f'Dosya yolları toplanırken bir hata oluştu: {str(e)}'
            })

        # Use ThreadPoolExecutor for parallel processing
        results = []
        processed_files_count = 0
        matched_files_count = 0
        error_files = []
        skipped_files = []

        MAX_WORKERS = os.cpu_count() or 1 # Use all available CPU cores, or at least 1
        logger.info(f"Starting ThreadPoolExecutor with {MAX_WORKERS} workers.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit tasks to the executor
            future_to_file = {
                executor.submit(_scan_single_file, file_path, combined_patterns, quarantined_paths, file_types, logger):
                file_path for file_path in files_to_scan
            }

            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                if time.time() - start_time > 300: # Timeout for scanning
                    logger.warning(f"Scan timeout reached during processing of {file_path}. Stopping further processing.")
                    executor.shutdown(wait=False, cancel_futures=True) # Attempt to cancel remaining tasks
                    break # Exit the loop

                try:
                    scan_result = future.result()
                    processed_files_count += scan_result['processed_files_count']
                    matched_files_count += scan_result['matched_files_count']
                    error_files.extend(scan_result['error_files'])
                    skipped_files.extend(scan_result['skipped_files'])
                    if scan_result['file_results']:
                        results.append(scan_result['file_results'])
                except Exception as exc:
                    logger.error(f'{file_path} dosyasında hata oluştu: {exc}')
                    error_files.append({'path': file_path, 'error': str(exc)})

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Scan finished in {duration:.2f} seconds.")
        logger.info(f"Processed {processed_files_count} files, found matches in {matched_files_count} files.")
        logger.info(f"Total errors: {len(error_files)}, total skipped: {len(skipped_files)}")

        return render(request, 'regex/sensitive_scan.html', {
            'results': results,
            'scan_duration': f"{duration:.2f}",
            'processed_files_count': processed_files_count,
            'matched_files_count': matched_files_count,
            'error_files': error_files,
            'skipped_files': skipped_files,
            'selected_categories': selected_categories,
            'selected_file_types': file_types,
            'directory_path': directory_path
        })
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

        for category, patterns in load_patterns():
            category_matches = {}
            for pattern_dict in patterns:
                try:
                    pattern = re.compile(pattern_dict['regex'], re.IGNORECASE | re.MULTILINE)
                    found_matches = pattern.findall(content)
                    if found_matches:
                        category_matches[pattern_dict['subcategory']] = found_matches
                except re.error as e:
                    logger.error(f"Regex error with pattern {pattern_dict['regex']}: {str(e)}")
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
            for category, patterns in load_patterns():
                for pattern_dict in patterns:
                    try:
                        if re.search(pattern_dict['regex'], line):
                            matches.append({
                                'line_number': i,
                                'line_content': line.strip(),
                                'pattern_type': pattern_dict['subcategory'],
                                'pattern': pattern_dict['regex']
                            })
                    except re.error as e:
                        logger.error(f"Regex error with pattern {pattern_dict['regex']}: {str(e)}")
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
    patterns = load_patterns()
    # Send only necessary info, not compiled regex objects
    serializable_patterns = []
    for p in patterns:
        serializable_patterns.append({
            'name': p['name'],
            'regex': p['regex'],
            'description': p.get('description', ''),
            'category': p.get('category', ''),
            'subcategory': p.get('subcategory', ''),
            'risk_level': p.get('risk_level', '')
        })
    return JsonResponse({'patterns': serializable_patterns})

def regex_search_results(request):
    """View function for displaying regex search results"""
    # Session'dan tarama sonuçlarını al
    scan_results = request.session.get('scan_results', {})
    
    if not scan_results:
        messages.warning(request, 'Tarama sonuçları bulunamadı. Lütfen yeni bir tarama başlatın.')
        return redirect('regex:sensitive_scan')
    
    # Eşleşen dosyaları işle
    matched_files = []
    for result in scan_results.get('results', []):
        file_info = {
            'filename': os.path.basename(result['file_path']),
            'path': result['file_path'],
            'matches': result['matches'],
            'matched_regex': ', '.join([
                f"{category}: {', '.join(subcategories.keys())}"
                for category, subcategories in result['matches'].items()
            ])
        }
        matched_files.append(file_info)
    
    context = {
        'scan_path': scan_results.get('scan_path', ''),
        'scan_time': scan_results.get('scan_time', ''),
        'scan_duration': scan_results.get('scan_duration', 0),
        'processed_files_count': scan_results.get('processed_files_count', 0),
        'matched_files_count': scan_results.get('matched_files_count', 0),
        'matched_files': matched_files,
        'error_files': scan_results.get('error_files', []),
        'skipped_files': scan_results.get('skipped_files', [])
    }
    
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
    """View function for quarantining files from regex scanner"""
    try:
        if request.method != 'POST':
            return JsonResponse({'success': False, 'error': 'Sadece POST istekleri kabul edilir'})

        # Önce form verilerini kontrol et
        file_path = request.POST.get('file_path')
        threat_type = request.POST.get('threat_type', 'Sensitive Data')
        threat_level = request.POST.get('threat_level', 'High')
        detected_pattern = request.POST.get('detected_pattern', '')

        # Eğer form verisi yoksa, JSON verisini dene
        if not file_path and request.body:
            try:
                print("GELEN VERİ:", repr(request.body))  # ham veri
                print("TİP:", type(request.body))         # veri tipi
                data = json.loads(request.body)
                file_path = data.get('file_path')
                threat_type = data.get('threat_type', 'Sensitive Data')
                threat_level = data.get('threat_level', 'High')
                detected_pattern = data.get('detected_pattern', '')
            except json.JSONDecodeError:
                pass

        if not file_path:
            return JsonResponse({'success': False, 'error': 'Dosya yolu belirtilmedi'})

        # Dosyanın varlığını kontrol et
        if not os.path.exists(file_path):
            return JsonResponse({'success': False, 'error': f'Dosya bulunamadı: {file_path}'})

        # Karantina dizinini oluştur
        quarantine_dir = os.path.join(settings.BASE_DIR, 'quarantine', 'quarantined_files')
        os.makedirs(quarantine_dir, exist_ok=True)

        # Dosya adını al ve benzersiz bir isim oluştur
        file_name = os.path.basename(file_path)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_name = f"{timestamp}_{file_name}"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)

        # Dosyayı karantina dizinine taşı
        try:
            shutil.move(file_path, quarantine_path)
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Dosya taşıma hatası: {str(e)}'})

        # Dosya hash'ini hesapla
        file_hash = None
        try:
            with open(quarantine_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Hash hesaplama hatası: {str(e)}")

        # Veritabanına kaydet
        try:
            quarantined_file = QuarantinedFile.objects.create(
                filename=file_name,
                original_path=file_path,
                quarantine_path=quarantine_path,
                quarantine_time=datetime.now(),
                threat_type=threat_type,
                threat_level=threat_level,
                status='quarantined',
                scan_tool='regex_scanner',
                detected_by_user=request.user.username if request.user.is_authenticated else 'Anonymous',
                file_size=os.path.getsize(quarantine_path),
                file_hash=file_hash
            )
        except Exception as e:
            # Veritabanı hatası durumunda dosyayı geri taşı
            try:
                shutil.move(quarantine_path, file_path)
            except:
                pass
            return JsonResponse({'success': False, 'error': f'Veritabanı hatası: {str(e)}'})

        return JsonResponse({
            'success': True,
            'message': 'Dosya başarıyla karantinaya alındı',
            'file_id': quarantined_file.id,
            'quarantine_path': quarantine_path
        })

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Karantina işlemi başarısız: {str(e)}'})

def quarantine_list(request):
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    return render(request, 'regex/quarantine_list.html', {'files': files})
