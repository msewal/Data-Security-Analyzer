import os
import re
import urllib.parse
from django.shortcuts import render
from django.http import JsonResponse

from .patterns import (
    ALL_REGEX_PATTERNS_BACKEND
)

# Tüm path'leri güvenli kabul et (sistem geneli taranabilir)
def is_safe_path(path):
    return True

# Ana tarama fonksiyonu
def regex_search_results_view(request):
    if request.method == 'POST':
        directory_path = request.POST.get('directory_path')
        selected_categories = request.POST.get('selected_categories', '')
        category_keys = selected_categories.split(',') if selected_categories else []
        scan_type = request.POST.get('scan_type', 'full')

        if not os.path.exists(directory_path):
            return render(request, 'regex/regex_search_results.html', {
                'error_message': 'Girilen dizin yolu mevcut değil.'
            })

        combined_patterns = []
        for category in category_keys:
            patterns = ALL_REGEX_PATTERNS_BACKEND.get(category, [])
            combined_patterns.extend(patterns)

        results = []
        processed_files_count = 0
        matched_files_count = 0

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)

                if not is_safe_path(file_path):
                    continue

                encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
                content = None
                for enc in encodings:
                    try:
                        with open(file_path, 'r', encoding=enc) as f:
                            lines = f.readlines()
                        break
                    except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                        continue
                else:
                    continue  # Geçerli encoding bulunamadıysa atla

                processed_files_count += 1

                if scan_type == 'partial':
                    lines = lines[:100]

                pattern_counts = {}
                for pattern in combined_patterns:
                    for line in lines:
                        try:
                            if re.search(pattern, line):
                                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
                        except re.error:
                            continue

                if pattern_counts:
                    matched_files_count += 1
                    results.append({
                        'file_path': file_path,
                        'pattern_counts': pattern_counts
                    })

        return render(request, 'regex/regex_search_results.html', {
            'results': results,
            'search_path': directory_path,
            'processed_files_count': processed_files_count,
            'matched_files_count': matched_files_count
        })

    return render(request, 'regex/regex_search_results.html', {
        'error_message': 'Geçersiz istek.'
    })

# Detaylı eşleşmeleri gösteren view
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
                print(f"Hata ({decoded_file_path}): {e}")
                continue
        else:
            return render(request, 'regex/regex_search_detail.html', {
                'error_message': 'Dosya okunamadı veya erişim izni yok.',
                'file_path': decoded_file_path
            })

        for i, line in enumerate(lines, 1):
            for category, patterns in ALL_REGEX_PATTERNS_BACKEND.items():
                for pattern in patterns:
                    try:
                        if re.search(pattern, line):
                            matches.append({
                                'line_number': i,
                                'line_content': line.strip(),
                                'pattern_type': category,
                                'pattern': pattern
                            })
                    except re.error:
                        continue

    except Exception as e:
        return render(request, 'regex/regex_search_detail.html', {
            'error_message': f"Beklenmeyen bir hata oluştu: {str(e)}",
            'file_path': decoded_file_path
        })

    return render(request, 'regex/regex_search_detail.html', {
        'matches': matches,
        'file_path': decoded_file_path
    })

# Kategori listesini JSON olarak döner (API endpoint)
def api_get_regex_patterns(request):
    return JsonResponse(ALL_REGEX_PATTERNS_BACKEND)
