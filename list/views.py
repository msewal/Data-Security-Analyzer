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
        return str(uid)
    except Exception:
        return str(uid)

def get_group(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
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

def regex_search_page(request):
    query_path = request.GET.get("path")
    pattern = request.GET.get("pattern")
    results = []

    if query_path and pattern:
        # Assuming regex_search_in_file returns a list of matches or similar
        try:
            # Need to import regex_search_in_file from .bash.cmd
            from .bash.cmd import regex_search_in_file
            results = regex_search_in_file(query_path, pattern)
        except ImportError:
            results = [{"error": True, "msg": "Regex search backend not available."}]
        except Exception as e:
             results = [{"error": True, "msg": f"Search failed: {e}"}]

    context = {
        "query_path": query_path,
        "pattern": pattern,
        "results": results
    }
    return render(request, "list/regex_search_results.html", context)

def quarantine_list(request):
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    return render(request, 'list/quarantine.html', {
        'files': files,
        'quarantine_dir': settings.QUARANTINE_DIR
    })

def quarantine_restore(request, filename):
    quarantined_file = get_object_or_404(QuarantinedFile, filename=filename)
    
    # Restore the file to its original location
    try:
        shutil.move(quarantined_file.quarantine_path, quarantined_file.original_path)
        quarantined_file.delete()
        messages.success(request, f'File {filename} has been restored successfully.')
    except Exception as e:
        messages.error(request, f'Error restoring file: {str(e)}')
    
    return redirect('list:quarantine_list')

def quarantine_delete(request, filename):
    quarantined_file = get_object_or_404(QuarantinedFile, filename=filename)
    
    # Delete the quarantined file
    try:
        os.remove(quarantined_file.quarantine_path)
        quarantined_file.delete()
        messages.success(request, f'File {filename} has been deleted successfully.')
    except Exception as e:
        messages.error(request, f'Error deleting file: {str(e)}')
    
    return redirect('list:quarantine_list')

def navigate_directory(request):
    current_path = request.GET.get('path', '/')
    parent_path = os.path.dirname(current_path)

    items = get_items(current_path)

    return render(request, 'list/index.html', {
        'list': items,
        'path': current_path,
        'parent_path': parent_path
    })

@csrf_exempt
def upload_file(request):
    if request.method == 'POST':
        try:
            file = request.FILES['file']
            path = request.POST.get('path', '/')
            
            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': 'Path does not exist'})
            
            file_path = os.path.join(path, file.name)
            
            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@csrf_exempt
def create_folder(request):
    if request.method == 'POST':
        try:
            folder_name = request.POST.get('folder_name')
            path = request.POST.get('path', '/')
            
            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': 'Path does not exist'})
            
            folder_path = os.path.join(path, folder_name)
            
            if os.path.exists(folder_path):
                return JsonResponse({'success': False, 'error': 'Folder already exists'})
            
            os.makedirs(folder_path)
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@csrf_exempt
def delete_item(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            path = data.get('path')
            
            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': 'Path does not exist'})
            
            if os.path.isdir(path):
                os.rmdir(path)
            else:
                os.remove(path)
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@csrf_exempt
def quarantine_file(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            path = data.get('path')

            if not path:
                 return JsonResponse({'success': False, 'error': 'Quarantine operation failed: File path not provided.'})

            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': f'Quarantine operation failed: Path does not exist: {path}'})

            if os.path.isdir(path):
                return JsonResponse({'success': False, 'error': f'Quarantine operation failed: Cannot quarantine directories: {path}'})

            quarantine_dir = os.path.join(settings.BASE_DIR, 'quarantine')
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)

            filename = os.path.basename(path)
            quarantine_path = os.path.join(quarantine_dir, filename)

            # Handle potential filename collisions
            counter = 1
            while os.path.exists(quarantine_path):
                base, ext = os.path.splitext(filename)
                quarantine_path = os.path.join(quarantine_dir, f"{base}_{counter}{ext}")
                counter += 1

            os.rename(path, quarantine_path)
            return JsonResponse({'success': True, 'message': f'{filename} successfully quarantined.'})
        except Exception as e:
            # Log the exception for debugging
            import traceback
            traceback.print_exc()
            return JsonResponse({'success': False, 'error': f'An unexpected error occurred during quarantine: {str(e)}'})
    return JsonResponse({'success': False, 'error': 'Invalid request method for quarantine.'})

@csrf_exempt
def run_procedure(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            procedure_type = data.get('type')
            
            result = {'success': False, 'message': 'Bilinmeyen prosedür türü.'}

            if procedure_type == 'scan':
                # Dosya Taraması prosedürü
                # TODO: Implement file scanning logic using bash/cmd functions
                print("Running File Scan procedure...")
                result = {'success': True, 'message': 'Dosya taraması başlatıldı (Simüle).'}

            elif procedure_type == 'security':
                # Güvenlik Denetimi prosedürü
                # TODO: Implement security check logic using bash/cmd functions
                print("Running Security Check procedure...")
                result = {'success': True, 'message': 'Güvenlik denetimi başlatıldı (Simüle).'}

            elif procedure_type == 'backup':
                # Yedekleme prosedürü
                # TODO: Implement backup logic using bash/cmd functions
                print("Running Backup procedure...")
                result = {'success': True, 'message': 'Yedekleme başlatıldı (Simüle).'}

            return JsonResponse(result)
        except Exception as e:
            # Log the exception for debugging
            import traceback
            traceback.print_exc()
            return JsonResponse({'success': False, 'error': f'Prosedür çalıştırılırken bir hata oluştu: {str(e)}'})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

def regex_search(request):
    return render(request, 'list/regex_search.html')

def regex_search_results(request):
    return render(request, 'list/regex_search_results.html')

def quarantine_list(request):
    return render(request, 'list/quarantine.html')

def dashboard(request):
    return render(request, 'list/dashboard.html')

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
