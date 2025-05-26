import os
import stat
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, FileResponse
from .bash.cmd import ls, mkdir, cp, mv, touch, chmod, isTextFile
from django.contrib import messages
from .models import QuarantinedFile
import shutil
from django.conf import settings
from .bash.cmd import regex_search_in_file

from .bash.cmd import classify_file
from django.shortcuts import render
from .bash.cmd import quarantine_file
from .bash.cmd import malware_scan_file

import json
from django.views.decorators.csrf import csrf_exempt
import time
import re
import subprocess

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

def index(request):
    path = request.GET.get('path', '/')
    if not os.path.exists(path):
        path = '/'
    
    items = []
    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        try:
            stat_info = os.stat(item_path)
            is_dir = os.path.isdir(item_path)
            
            # Determine file type based on extension
            file_type_display = '-'
            if is_dir:
                file_type_display = 'Klasör'
            else:
                file_extension = os.path.splitext(item)[1].lower()
                if file_extension == '.txt':
                    file_type_display = 'Metin Belgesi'
                elif file_extension == '.pdf':
                    file_type_display = 'PDF Belgesi'
                elif file_extension in ['.doc', '.docx']:
                    file_type_display = 'Word Belgesi'
                elif file_extension in ['.xls', '.xlsx']:
                    file_type_display = 'Excel Çalışma Kitabı'
                elif file_extension in ['.ppt', '.pptx']:
                    file_type_display = 'PowerPoint Sunusu'
                elif file_extension == '.jpg' or file_extension == '.jpeg':
                    file_type_display = 'JPEG Resim'
                elif file_extension == '.png':
                    file_type_display = 'PNG Resim'
                elif file_extension == '.gif':
                    file_type_display = 'GIF Resim'
                elif file_extension == '.mp3':
                    file_type_display = 'MP3 Ses Dosyası'
                elif file_extension == '.mp4':
                    file_type_display = 'MP4 Video Dosyası'
                elif file_extension == '.zip':
                    file_type_display = 'ZIP Arşivi'
                elif file_extension == '.rar':
                    file_type_display = 'RAR Arşivi'
                elif file_extension == '.py':
                    file_type_display = 'Python Dosyası'
                elif file_extension == '.html' or file_extension == '.htm':
                    file_type_display = 'HTML Belgesi'
                elif file_extension == '.css':
                    file_type_display = 'CSS Dosyası'
                elif file_extension == '.js':
                    file_type_display = 'JavaScript Dosyası'
                elif file_extension == '.json':
                    file_type_display = 'JSON Dosyası'
                elif file_extension == '.xml':
                    file_type_display = 'XML Belgesi'
                elif file_extension == '.db' or file_extension == '.sqlite3':
                     file_type_display = 'SQLite Veritabanı'
                # Add more file types as needed
                else:
                    file_type_display = f'{file_extension.upper()[1:]} Dosyası' if file_extension else 'Dosya'

            items.append({
                'name': item,
                'path': item_path,
                'is_dir': is_dir,
                'size': format_size(stat_info.st_size) if not is_dir else '-',
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': get_owner(stat_info.st_uid),
                'group': get_group(stat_info.st_gid),
                'created': format_time(stat_info.st_ctime),
                'modified': format_time(stat_info.st_mtime),
                'accessed': format_time(stat_info.st_atime),
                'file_type_display': file_type_display # Add the determined file type
            })
        except Exception as e:
            print(f"Error getting stats or type for {item_path}: {e}")
    
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    
    context = {
        'current_path': path,
        'parent_path': os.path.dirname(path),
        'items': items
    }
    return render(request, 'list/index.html', context)

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def format_time(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def get_owner(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except ImportError:
        try:
            import win32security
            import win32api
            import win32con
            sid = win32security.GetFileSecurity(str(uid), win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
            name, domain, type = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
        except ImportError:
            return str(uid)
        except Exception:
            return str(uid)

def get_group(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except ImportError:
        try:
            import win32security
            import win32api
            import win32con
            sid = win32security.GetFileSecurity(str(gid), win32security.GROUP_SECURITY_INFORMATION).GetSecurityDescriptorGroup()
            name, domain, type = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
        except ImportError:
            return str(gid)
        except Exception:
            return str(gid)

def api_mkdir(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = mkdir(path)
    return JsonResponse(mkdir_response)

def api_touch(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = touch(path)
    return JsonResponse(mkdir_response)

def api_mv(request):
    try:
        src = request.GET["src"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "src is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        dest = request.GET["dest"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "dest is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = mv(src, dest)
    return JsonResponse(mkdir_response)

def api_cp(request):
    try:
        src = request.GET["src"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "src is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        dest = request.GET["dest"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "dest is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = cp(src, dest)
    return JsonResponse(mkdir_response)

def api_chmod(request):
    try:
        path = request.GET["path"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "path is not specified."
        return JsonResponse(mkdir_response)
    
    try:
        mod = request.GET["mod"]
    except KeyError:
        mkdir_response = {}
        mkdir_response['error'] = True
        mkdir_response['msg'] = "mod is not specified."
        return JsonResponse(mkdir_response)
        
    mkdir_response = chmod(path, mod)
    return JsonResponse(mkdir_response)

def edit(request):
    context = {}
    context["texterror"] = False
    context["patherror"] = False
    context["notfounderror"] = False
    try:
        path = request.GET["path"]
        if os.path.exists(path):
            if(os.path.isfile(path) and isTextFile(path)):
                context["path"] = path
                f = open(path, "r")
                lines = f.read()
                context["data"] = lines
            else:
                context["texterror"] = True
        else:
            context["notfounderror"] = True
    except KeyError:
        context["patherror"] = True

    return render(request,"list/edit.html", context)
    
def api_savefile(request):
    if request.method != "POST":
        return redirect("/list")
    else:
        path = request.POST.get('path')
        text = request.POST.get('text')
        f = open(path, 'w')
        f.write(text)
        f.close()
        return redirect(f"/list/edit?path={path}")

def api_regex_search(request):
    path = request.GET.get("path")
    pattern = request.GET.get("pattern")

    if not path or not pattern:
        return JsonResponse({"error": True, "msg": "Path and pattern are required."})

    try:
        # Perform regex search using the regex_search_in_file function
        results = regex_search_in_file(path, pattern)
        formatted_results = []

        for result in results:
            formatted_results.append({
                "file": result["file"],
                "line_number": result["line_number"],
                "match": result["match"]
            })

        return JsonResponse({"error": False, "results": formatted_results})
    except Exception as e:
        return JsonResponse({"error": True, "msg": str(e)})

def api_malware_scan(request):
    path = request.GET.get("path")

    if not path:
        return JsonResponse({"error": True, "msg": "Path parameter required."})

    result = malware_scan_file(path)
    return JsonResponse(result)

def api_quarantine(request):
    path = request.GET.get("path")

    if not path:
        return JsonResponse({"error": True, "msg": "Path parameter required."})

    result = quarantine_file(path)
    return JsonResponse(result)

def api_classify_file(request):
    path = request.GET.get("path")

    if not path:
        return JsonResponse({"error": True, "msg": "Path parameter required."})

    result = classify_file(path)
    return JsonResponse(result)

def dashboard(request):
    return render(request, 'list/dashboard.html')

def get_items(path):
    """
    Returns a list of items (files and directories) in the given path.
    """
    try:
        items = []
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            items.append({
                "name": entry,
                "is_dir": os.path.isdir(full_path),
                "path": full_path
            })
        return items
    except Exception as e:
        return []

def procedure(request):
    path = request.GET.get("path", "/")  # veya varsayılan dizin
    items = get_items(path)  # böyle bir fonksiyon olmalı
    return render(request, "list/procedure.html", {
        "items": items,
        "current_path": path,
        "parent_path": os.path.dirname(path)
    })

def scan_file_for_sensitive_data(file_path):
    file_results = []
    try:
        # Handle different file types
        if file_path.endswith('.docx'):
            try:
                from docx import Document
                doc = Document(file_path)
                content = "\n".join([para.text for para in doc.paragraphs])
            except ImportError:
                return file_results
        else:
            # For text files, try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
            content = None
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                return file_results

        # Scan content for each pattern
        for sensitive_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get some context around the match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ').strip()
                
                file_results.append({
                    'file_path': file_path,
                    'sensitive_type': sensitive_type,
                    'matched_data': match.group(),
                    'line_number': content[:match.start()].count('\n') + 1,
                    'context': context
                })
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return file_results

def regex_search_results(request):
    path = request.GET.get('path')
    scan_type = request.GET.get('type', 'file')
    
    if not path:
        return JsonResponse({'error': True, 'msg': 'Path parameter required.'})
    
    results = []
    
    try:
        if scan_type == 'file':
            # Single file scan
            if os.path.isfile(path):
                results.extend(scan_file_for_sensitive_data(path))
        else:
            # Directory scan
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Only scan text-based files and docx files
                    if should_scan_file(file_path):
                        results.extend(scan_file_for_sensitive_data(file_path))
        
        # Group results by file and create summary
        summary = {}
        for result in results:
            file_path = result['file_path']
            if file_path not in summary:
                summary[file_path] = {
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'types': {},
                    'total_matches': 0
                }
            sensitive_type = result['sensitive_type']
            if sensitive_type not in summary[file_path]['types']:
                summary[file_path]['types'][sensitive_type] = 0
            summary[file_path]['types'][sensitive_type] += 1
            summary[file_path]['total_matches'] += 1
        
        return render(request, 'list/regex_search_results.html', {
            'results': results,
            'summary': summary,
            'scan_path': path,
            'scan_type': scan_type
        })
    except Exception as e:
        return JsonResponse({'error': True, 'msg': str(e)})

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

def edit_file(request):
    path = request.GET.get('path')
    content = ''
    error = None

    if path:
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                error = f"Dosya okunurken bir hata oluştu: {e}"
        else:
            error = 'Dosya bulunamadı veya bir dosya değil.'
    else:
        error = 'Dosya yolu belirtilmedi.'

    context = {
        'path': path,
        'data': content,
        'error': error
    }
    return render(request, 'list/edit.html', context)

@csrf_exempt
def save_file(request):
    if request.method == 'POST':
        try:
            path = request.POST.get('path')
            text = request.POST.get('text')
            
            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': 'Path does not exist'})
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            return JsonResponse({'success': True, 'message': 'Dosya başarıyla kaydedildi.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def download_file(request):
    path = request.GET.get('path')
    
    if not path:
        return HttpResponse('Dosya yolu belirtilmedi.', status=400)
    
    if not os.path.exists(path) or not os.path.isfile(path):
        return HttpResponse('Dosya bulunamadı.', status=404)
    
    try:
        from django.utils.encoding import escape_uri_path
        
        # Use FileResponse for efficient serving of large files
        response = FileResponse(open(path, 'rb'), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{escape_uri_path(os.path.basename(path))}"'
        return response
    except Exception as e:
        return HttpResponse(f'Dosya indirilirken bir hata oluştu: {e}', status=500)

def file_preview(request):
    path = request.GET.get('path')
    content = None
    error = None
    file_type = 'other' # Default file type
    
    if not path:
        error = 'Dosya yolu belirtilmedi.'
    elif not os.path.exists(path):
        error = 'Dosya bulunamadı.'
    elif os.path.isdir(path):
        error = 'Klasörler önizlenemez.'
    else:
        try:
            # Determine file type for preview
            file_extension = os.path.splitext(path)[1].lower()
            image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']
            text_extensions = ['.txt', '.log', '.py', '.html', '.css', '.js', '.json', '.xml', '.md'] # Add more text extensions as needed
            
            if file_extension in image_extensions:
                file_type = 'image'
            elif file_extension in text_extensions:
                file_type = 'text'
                # Read text file content
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    error = f'Metin dosyası okunurken bir hata oluştu: {e}'
            # Add more file type checks if needed (e.g., for PDF, although previewing might require libraries)
            
            # For other file types, content will remain None, and we just show file info and download link
            
        except Exception as e:
            error = f'Dosya türü belirlenirken bir hata oluştu: {e}'
            
    context = {
        'path': path,
        'file_name': os.path.basename(path) if path and not os.path.isdir(path) else None,
        'content': content,
        'error': error,
        'file_type': file_type,
    }
    return render(request, 'list/file_preview.html', context)

def sensitive_data_scan(request):
    return render(request, 'list/sensitive_data_scan.html')

def sensitive_data_results(request):
    path = request.GET.get('path')
    scan_type = request.GET.get('type', 'file')
    
    if not path:
        return JsonResponse({'error': True, 'msg': 'Path parameter required.'})
    
    results = []
    
    try:
        if scan_type == 'file':
            # Single file scan
            if os.path.isfile(path):
                results.extend(scan_file_for_sensitive_data(path))
        else:
            # Directory scan
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Only scan text-based files and docx files
                    if should_scan_file(file_path):
                        results.extend(scan_file_for_sensitive_data(file_path))
        
        # Group results by file and create summary
        summary = {}
        for result in results:
            file_path = result['file_path']
            if file_path not in summary:
                summary[file_path] = {
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'types': {},
                    'total_matches': 0
                }
            sensitive_type = result['sensitive_type']
            if sensitive_type not in summary[file_path]['types']:
                summary[file_path]['types'][sensitive_type] = 0
            summary[file_path]['types'][sensitive_type] += 1
            summary[file_path]['total_matches'] += 1
        
        return render(request, 'list/sensitive_data_results.html', {
            'results': results,
            'summary': summary,
            'scan_path': path,
            'scan_type': scan_type
        })
    except Exception as e:
        return JsonResponse({'error': True, 'msg': str(e)})

def is_tool_available(name):
    """Check if a command-line tool is available in the system's PATH."""
    return shutil.which(name) is not None

def malware_scan(request):
    current_path = request.GET.get('path', '/') # Path for browsing
    scan_target_path = request.GET.get('scan_path') # Path for scanning
    scan_type = request.GET.get('type', 'file')

    error = None
    infected_files = []
    scan_results = []
    clam_output = None
    rkhunter_output = None
    chkrootkit_output = None

    if scan_target_path:
        # Perform scan if scan_path is provided
        if not os.path.exists(scan_target_path):
            error = f"Tarama hedefi bulunamadı: {scan_target_path}"
        else:
            # Check if clamscan is available
            if not is_tool_available("clamscan"):
                error = "ClamAV (clamscan) bulunamadı. Lütfen kurulu olduğundan ve PATH'inizde bulunduğundan emin olun."
            else:
                try:
                    # ClamAV taraması
                    # Pass command and arguments as a list without shell=True
                    clam_result = subprocess.run(
                        ["clamscan", "-r", scan_target_path], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        text=True, # Keep text=True for string output
                        check=True # Add check=True to catch non-zero exit codes
                    )
                    clam_output = clam_result.stdout
                    
                    for line in clam_result.stdout.splitlines():
                        if "FOUND" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                filepath = parts[0].strip()
                                malware_type = parts[-1].strip()
                                
                                # Dosyayı karantinaya taşı
                                if os.path.exists(filepath):
                                    filename = os.path.basename(filepath)
                                    quarantine_dir = os.path.join(settings.BASE_DIR, 'quarantine')
                                    quarantine_path = os.path.join(quarantine_dir, filename)
                                    
                                    # Karantina dizinini oluştur
                                    os.makedirs(quarantine_dir, exist_ok=True)
                                    
                                    # Handle potential filename collisions in quarantine
                                    base, ext = os.path.splitext(filename)
                                    counter = 1
                                    while os.path.exists(quarantine_path):
                                         quarantine_path = os.path.join(quarantine_dir, f"{base}_{counter}{ext}")
                                         counter += 1

                                    try:
                                        shutil.move(filepath, quarantine_path)
                                         # Veritabanına kaydet - Placeholder values for new fields
                                        QuarantinedFile.objects.create(
                                            filename=filename,
                                            original_path=filepath,
                                            quarantine_path=quarantine_path,
                                            malware_type=malware_type,
                                            scan_tool='clamscan',
                                            file_size=os.path.getsize(quarantine_path), # Get size after moving
                                            file_hash="N/A", # TODO: Calculate hash
                                            detected_by_user=request.user.username if request.user.is_authenticated else "Anonymous",
                                            threat_level='medium' # TODO: Determine threat level
                                        )
                                        
                                        infected_files.append({
                                            'path': filepath,
                                            'malware_type': malware_type,
                                            'tool': 'clamscan'
                                        })
                                    except Exception as move_quarantine_error:
                                         scan_results.append({
                                             'tool': 'system',
                                             'message': f'Dosya karantinaya taşınırken hata oluştu {filepath}: {move_quarantine_error}'
                                         })
                                else:
                                    scan_results.append({
                                         'tool': 'clamscan',
                                         'message': f'Tespit edilen dosya karantina için bulunamadı: {filepath}'
                                     })
                            else:
                                scan_results.append({
                                    'tool': 'clamscan',
                                    'message': f'Clamscan çıktısı ayrıştırılırken hata: {line}'
                                })

                    # RKHunter taraması (rootkit tespiti) - Only for directories
                    if os.path.isdir(scan_target_path):
                         if not is_tool_available("rkhunter"):
                             scan_results.append({
                                'tool': 'system',
                                'message': "RKHunter bulunamadı. Lütfen kurulu olduğundan ve PATH'inizde bulunduğundan emin olun."
                             })
                         else:
                             try:
                                 # Pass command and arguments as a list without shell=True
                                 rkhunter_result = subprocess.run(
                                     ["rkhunter", "--check", scan_target_path],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True,
                                     check=True
                                 )
                                 rkhunter_output = rkhunter_result.stdout
                                 for line in rkhunter_result.stdout.splitlines():
                                     if "Warning:" in line:
                                         scan_results.append({
                                             'tool': 'rkhunter',
                                             'message': line.strip()
                                         })
                             except (subprocess.CalledProcessError, FileNotFoundError) as e:
                                 scan_results.append({
                                     'tool': 'rkhunter',
                                     'message': f'RKHunter çalıştırılırken hata oluştu: {e}'
                                 })

                    # Chkrootkit taraması - Only for directories
                    if os.path.isdir(scan_target_path):
                        if not is_tool_available("chkrootkit"):
                            scan_results.append({
                                'tool': 'system',
                                'message': "Chkrootkit bulunamadı. Lütfen kurulu olduğundan ve PATH'inizde bulunduğundan emin olun."
                             })
                        else:
                             try:
                                 # Pass command and arguments as a list without shell=True
                                 chkrootkit_result = subprocess.run(
                                     ["chkrootkit", scan_target_path],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True,
                                     check=True
                                 )
                                 chkrootkit_output = chkrootkit_result.stdout
                                 for line in chkrootkit_result.stdout.splitlines():
                                     if "INFECTED" in line:
                                         scan_results.append({
                                             'tool': 'chkrootkit',
                                             'message': line.strip()
                                         })
                             except (subprocess.CalledProcessError, FileNotFoundError) as e:
                                 scan_results.append({
                                     'tool': 'chkrootkit',
                                     'message': f'Chkrootkit çalıştırılırken hata oluştu: {e}'
                                 })

                except FileNotFoundError as e:
                     # This specifically catches if the command *itself* was not found
                     error = f"Tarama aracı bulunamadı: {e.strerror} ({e.filename}). Lütfen kurulu olduklarından ve PATH'inizde bulunduklarından emin olun."
                except subprocess.CalledProcessError as e:
                    # This catches errors from the scan command itself (non-zero exit code)
                    error = f"Tarama komutu çalıştırılırken hata oluştu ({e.cmd}): {e.stderr}"
                except Exception as e:
                    error = f"Tarama sırasında beklenmeyen bir hata oluştu: {str(e)}"

    # Always display file browser for the current_path
    items = []
    if os.path.exists(current_path) and os.path.isdir(current_path):
        try:
            for item in os.listdir(current_path):
                item_path = os.path.join(current_path, item)
                try:
                    stat_info = os.stat(item_path)
                    is_dir = os.path.isdir(item_path)
                    
                    # Determine file type based on extension
                    file_type_display = '-'
                    if is_dir:
                        file_type_display = 'Klasör'
                    else:
                        file_extension = os.path.splitext(item)[1].lower()
                        if file_extension == '.txt':
                            file_type_display = 'Metin Belgesi'
                        elif file_extension == '.pdf':
                            file_type_display = 'PDF Belgesi'
                         # Add more file types as needed
                        else:
                             file_type_display = f'{file_extension.upper()[1:]} Dosyası' if file_extension else 'Dosya'

                    items.append({
                        'name': item,
                        'path': item_path,
                        'is_dir': is_dir,
                        'size': format_size(stat_info.st_size) if not is_dir else '-',
                        'permissions': oct(stat_info.st_mode)[-3:],
                        'owner': get_owner(stat_info.st_uid) if hasattr(stat_info, 'st_uid') else 'N/A',
                        'group': get_group(stat_info.st_gid) if hasattr(stat_info, 'st_gid') else 'N/A',
                        'modified': format_time(stat_info.st_mtime),
                        'file_type_display': file_type_display
                    })
                except Exception as e: # Catch exceptions for individual items
                     print(f"Error getting stats or type for {item_path}: {e}")

            items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        except Exception as e: # Catch exceptions for listing directory
            error = f"Klasör içeriği listelenirken bir hata oluştu: {str(e)}"
            items = [] # Clear items on error
    elif os.path.exists(current_path) and os.path.isfile(current_path):
         # If the path is a file, just list the file itself
         try:
            stat_info = os.stat(current_path)
            file_type_display = os.path.splitext(current_path)[1].upper()[1:] + ' Dosyası' if os.path.splitext(current_path)[1] else 'Dosya'
            items.append({
                'name': os.path.basename(current_path),
                'path': current_path,
                'is_dir': False,
                'size': format_size(stat_info.st_size),
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': get_owner(stat_info.st_uid) if hasattr(stat_info, 'st_uid') else 'N/A',
                'group': get_group(stat_info.st_gid) if hasattr(stat_info, 'st_gid') else 'N/A',
                'modified': format_time(stat_info.st_mtime),
                'file_type_display': file_type_display
            })
         except Exception as e:
             error = f"Dosya bilgileri alınırken bir hata oluştu: {str(e)}"
             items = []
    else:
        error = f"Geçerli yol bulunamadı veya bir klasör değil: {current_path}"
        items = []

    context = {
        'current_path': current_path,
        'parent_path': os.path.dirname(current_path) if os.path.dirname(current_path) != current_path else None,
        'items': items,
        'scan_target_path': scan_target_path, # Pass the scanned path to the template
        'infected_files': infected_files,
        'scan_results': scan_results,
        'clam_output': clam_output,
        'rkhunter_output': rkhunter_output,
        'chkrootkit_output': chkrootkit_output,
        'error': error,
        'is_scanning': scan_target_path is not None # Indicate if a scan was attempted
    }

    return render(request, 'list/malware_scan.html', context)
