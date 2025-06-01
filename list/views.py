import os
import stat
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.contrib import messages
import shutil
from django.conf import settings

from django.shortcuts import render

import json
from django.views.decorators.csrf import csrf_exempt
import time
import re
import subprocess
from urllib.parse import unquote
import urllib.parse
from django.utils import timezone
from .models import File

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

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

def index(request):
    current_path = '/'
    items = get_items(current_path)
    context = {
        'current_path': current_path,
        'parent_path': os.path.dirname(current_path) if os.path.dirname(current_path) != current_path else None,
        'items': items,
        'error': None
    }
    return render(request, 'list/index.html', context)

def dashboard(request):
    return render(request, 'list/dashboard.html')

def procedure(request):
    path = request.GET.get("path", "/")  # veya varsayılan dizin
    items = get_items(path)  # böyle bir fonksiyon olmalı
    return render(request, "list/procedure.html", {
        "items": items,
        "current_path": path,
        "parent_path": os.path.dirname(path)
    })

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

    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        if error:
            return JsonResponse({
                'success': False,
                'error': error
            })
        return JsonResponse({
            'success': True,
            'data': {
                'path': path,
                'content': content
            }
        })

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
            text_extensions = ['.txt', '.log', '.py', '.html', '.css', '.js', '.json', '.xml', '.md']
            
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
            
        except Exception as e:
            error = f'Dosya türü belirlenirken bir hata oluştu: {e}'
            
    context = {
        'path': path,
        'file_name': os.path.basename(path) if path and not os.path.isdir(path) else None,
        'content': content,
        'error': error,
        'file_type': file_type,
    }

    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        if error:
            return JsonResponse({
                'success': False,
                'error': error
            })
        return JsonResponse({
            'success': True,
            'data': {
                'path': path,
                'file_name': os.path.basename(path) if path and not os.path.isdir(path) else None,
                'content': content,
                'file_type': file_type
            }
        })

    return render(request, 'list/file_preview.html', context)

@csrf_exempt
def delete_item(request):
    if request.method == 'POST':
        try:
            path = request.POST.get('path')
            
            if not path:
                return JsonResponse({'success': False, 'error': 'Path is required'})
            
            if not os.path.exists(path):
                return JsonResponse({'success': False, 'error': 'Path does not exist'})
            
            # Check if it's a file or directory
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path)
            
            return JsonResponse({'success': True, 'message': 'Item deleted successfully'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@csrf_exempt
def upload_file(request):
    if request.method == 'POST':
        try:
            # Get the target directory from POST data
            target_dir = request.POST.get('target_dir', '/')
            
            # Validate target directory
            if not os.path.exists(target_dir):
                return JsonResponse({
                    'success': False,
                    'error': 'Target directory does not exist'
                })
            
            if not os.path.isdir(target_dir):
                return JsonResponse({
                    'success': False,
                    'error': 'Target path is not a directory'
                })
            
            # Check if file was uploaded
            if 'file' not in request.FILES:
                return JsonResponse({
                    'success': False,
                    'error': 'No file uploaded'
                })
            
            uploaded_file = request.FILES['file']
            
            # Create the full path for the uploaded file
            file_path = os.path.join(target_dir, uploaded_file.name)
            
            # Handle filename collisions
            base, ext = os.path.splitext(uploaded_file.name)
            counter = 1
            while os.path.exists(file_path):
                file_path = os.path.join(target_dir, f"{base}_{counter}{ext}")
                counter += 1
            
            # Save the uploaded file
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'size': os.path.getsize(file_path)
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({
        'success': False,
        'error': 'Invalid request method'
    })

@csrf_exempt
def create_folder(request):
    if request.method == 'POST':
        try:
            path = request.POST.get('path')
            folder_name = request.POST.get('folder_name')
            
            if not path or not folder_name:
                return JsonResponse({
                    'success': False,
                    'error': 'Path and folder name are required'
                })
            
            # Create full path for new folder
            new_folder_path = os.path.join(path, folder_name)
            
            # Check if folder already exists
            if os.path.exists(new_folder_path):
                return JsonResponse({
                    'success': False,
                    'error': 'Folder already exists'
                })
            
            # Create the folder
            os.makedirs(new_folder_path)
            
            return JsonResponse({
                'success': True,
                'data': {
                    'path': new_folder_path,
                    'name': folder_name
                }
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({
        'success': False,
        'error': 'Invalid request method'
    })
