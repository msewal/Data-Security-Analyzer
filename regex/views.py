import os
import re
import urllib.parse
import logging
import time
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings

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

def regex_search_results_view(request):
    if request.method == 'POST':
        logger.info("POST request received for regex search")
        start_time = time.time()
        
        # Get form data
        directory_path = request.POST.get('directory_path')
        selected_categories = request.POST.get('selected_categories', '')
        category_keys = selected_categories.split(',') if selected_categories else []
        scan_type = request.POST.get('scan_type', 'full')

        logger.info(f"Form data received - Directory: {directory_path}")
        logger.info(f"Selected categories: {category_keys}")
        logger.info(f"Scan type: {scan_type}")

        if not directory_path:
            logger.error("No directory path provided")
            return render(request, 'regex/regex_search_results.html', {
                'error_message': 'Lütfen bir dizin yolu girin.'
            })

        if not category_keys:
            logger.error("No categories selected")
            return render(request, 'regex/regex_search_results.html', {
                'error_message': 'Lütfen en az bir veri türü seçin.'
            })

        if not os.path.exists(directory_path):
            logger.error(f"Directory does not exist: {directory_path}")
            return render(request, 'regex/regex_search_results.html', {
                'error_message': 'Girilen dizin yolu mevcut değil.'
            })

        # Check if directory is accessible
        try:
            files = os.listdir(directory_path)
            logger.info(f"Successfully accessed directory. Found {len(files)} files/directories")
        except PermissionError:
            logger.error(f"Permission denied for directory: {directory_path}")
            return render(request, 'regex/regex_search_results.html', {
                'error_message': 'Dizine erişim izniniz yok.'
            })
        except Exception as e:
            logger.error(f"Error accessing directory {directory_path}: {str(e)}")
            return render(request, 'regex/regex_search_results.html', {
                'error_message': f'Dizine erişim sırasında bir hata oluştu: {str(e)}'
            })

        # Compile regex patterns once
        combined_patterns = []
        for category in category_keys:
            patterns = ALL_REGEX_PATTERNS_BACKEND.get(category, [])
            logger.info(f"Found {len(patterns)} patterns for category: {category}")
            for pattern_dict in patterns:
                try:
                    compiled_pattern = re.compile(pattern_dict['pattern'])
                    combined_patterns.append({
                        'pattern': compiled_pattern,
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

        try:
            logger.info("Starting file walk...")
            for root, dirs, files in os.walk(directory_path):
                # Skip certain directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__']]
                
                # Check for timeout (5 minutes)
                if time.time() - start_time > 300:
                    logger.warning("Scan timeout reached after 5 minutes")
                    return render(request, 'regex/regex_search_results.html', {
                        'error_message': 'Tarama zaman aşımına uğradı (5 dakika). Lütfen daha küçük bir dizin seçin veya kısmi tarama yapın.',
                        'partial_results': results,
                        'processed_files_count': processed_files_count,
                        'matched_files_count': matched_files_count,
                        'error_files': error_files,
                        'skipped_files': skipped_files
                    })

                logger.info(f"Processing directory: {root}")
                for file in files:
                    # Skip certain file types
                    if file.startswith('.') or file.endswith(('.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin')):
                        skipped_files.append(os.path.join(root, file))
                        continue

                    file_path = os.path.join(root, file)
                    logger.debug(f"Processing file: {file_path}")

                    if not is_safe_path(file_path):
                        logger.debug(f"Skipping unsafe file: {file_path}")
                        skipped_files.append(file_path)
                        continue

                    # Skip binary files and large files
                    try:
                        if os.path.getsize(file_path) > 5 * 1024 * 1024:  # Skip files larger than 5MB
                            logger.debug(f"Skipping large file: {file_path}")
                            skipped_files.append(file_path)
                            continue
                    except OSError as e:
                        logger.error(f"Error getting file size for {file_path}: {str(e)}")
                        error_files.append(file_path)
                        continue

                    encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
                    content = None
                    for enc in encodings:
                        try:
                            with open(file_path, 'r', encoding=enc) as f:
                                lines = f.readlines()
                                logger.debug(f"Successfully read file with encoding: {enc}")
                                break
                        except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                            logger.debug(f"Failed to read with encoding {enc}: {str(e)}")
                            continue
                    else:
                        logger.debug(f"Could not read file with any encoding: {file_path}")
                        error_files.append(file_path)
                        continue

                    processed_files_count += 1
                    if processed_files_count % 100 == 0:
                        logger.info(f"Processed {processed_files_count} files so far...")

                    if scan_type == 'partial':
                        lines = lines[:100]
                        logger.debug(f"Using partial scan, limiting to first 100 lines")

                    pattern_matches = {}
                    for pattern_info in combined_patterns:
                        pattern = pattern_info['pattern']
                        subcategory = pattern_info['subcategory']
                        for line in lines:
                            try:
                                if pattern.search(line):
                                    if subcategory not in pattern_matches:
                                        pattern_matches[subcategory] = []
                                    pattern_matches[subcategory].append(line.strip())
                                    logger.debug(f"Found match in {file_path}: {pattern_info['subcategory']}")
                            except Exception as e:
                                logger.error(f"Error processing line in {file_path}: {str(e)}")
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
            return render(request, 'regex/regex_search_results.html', {
                'error_message': f'Dosya işleme sırasında bir hata oluştu: {str(e)}',
                'partial_results': results,
                'processed_files_count': processed_files_count,
                'matched_files_count': matched_files_count,
                'error_files': error_files,
                'skipped_files': skipped_files
            })

        scan_duration = time.time() - start_time
        logger.info(f"Search completed in {scan_duration:.2f} seconds. Processed files: {processed_files_count}, Matched files: {matched_files_count}")
        
        return render(request, 'regex/regex_search_results.html', {
            'results': results,
            'search_path': directory_path,
            'processed_files_count': processed_files_count,
            'matched_files_count': matched_files_count,
            'error_files': error_files,
            'skipped_files': skipped_files,
            'scan_duration': f"{scan_duration:.2f}"
        })

    return render(request, 'regex/regex_search_results.html', {
        'error_message': 'Geçersiz istek.'
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
