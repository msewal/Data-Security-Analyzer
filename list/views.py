import os
import stat
import pwd
import grp
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse, FileResponse, HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import mimetypes
import magic
import urllib.parse

def format_size(size):
    """Convert file size to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_owner(uid):
    """Get owner name from uid"""
    try:
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)

def get_group(gid):
    """Get group name from gid"""
    try:
        return grp.getgrgid(gid).gr_name
    except:
        return str(gid)

def get_items(path):
    """Get list of items in directory"""
    items = []
    try:
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            try:
                stat_info = os.stat(full_path)
                is_dir = stat.S_ISDIR(stat_info.st_mode)
                
                # Get file type
                if is_dir:
                    file_type = 'Klasör'
                else:
                    mime = magic.Magic(mime=True)
                    mime_type = mime.from_file(full_path)
                    file_type = mime_type.split('/')[-1].upper()
                
                # Get file size
                if is_dir:
                    size = '-'
                else:
                    size = format_size(stat_info.st_size)
                
                items.append({
                    'name': item,
                    'path': full_path,
                    'is_dir': is_dir,
                    'type': file_type,
                    'size': size,
                    'permissions': oct(stat_info.st_mode)[-3:],
                    'owner': get_owner(stat_info.st_uid),
                    'group': get_group(stat_info.st_gid),
                    'created_at': datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    'modified_at': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'accessed_at': datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')
                })
            except Exception as e:
                print(f"Error getting info for {full_path}: {str(e)}")
    except Exception as e:
        print(f"Error listing directory {path}: {str(e)}")
    return sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))

def index(request):
    """Main file listing page"""
    path = request.GET.get('path', '/')
    if not os.path.exists(path):
        path = '/'
    
    # Get parent directory
    parent_path = os.path.dirname(path) if path != '/' else None
    
    files = get_items(path)
    return render(request, 'list/index.html', {
        'files': files,
        'current_path': path,
        'parent_path': parent_path
    })

def dashboard(request):
    """Dashboard page"""
    return render(request, 'list/dashboard.html')

def procedure(request):
    """Show items in path"""
    path = request.GET.get('path', '/')
    if not os.path.exists(path):
        path = '/'
    
    # Get parent directory
    parent_path = os.path.dirname(path) if path != '/' else None
    
    items = get_items(path)
    return render(request, 'list/procedure.html', {
        'items': items,
        'current_path': path,
        'parent_path': parent_path
    })

def edit_file(request):
    """Edit file content"""
    path = request.GET.get('path')
    if not path:
        return JsonResponse({'error': 'Path parameter is required'}, status=400)
    
    try:
        # Decode URL-encoded path
        path = urllib.parse.unquote(path)
        
        if not os.path.exists(path):
            return JsonResponse({'error': 'File not found'}, status=404)
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1254', 'iso-8859-9']
        content = None
        
        for enc in encodings:
            try:
                with open(path, 'r', encoding=enc) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            return JsonResponse({'error': 'File encoding not supported'}, status=400)
            
        return render(request, 'list/edit.html', {
            'content': content,
            'path': path
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def save_file(request):
    """Save file content"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    path = request.POST.get('path')
    content = request.POST.get('content')
    
    if not path or not content:
        return JsonResponse({'error': 'Missing path or content'}, status=400)
    
    try:
        # Decode URL-encoded path
        path = urllib.parse.unquote(path)
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save the file
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def download_file(request):
    """Download file"""
    path = request.GET.get('path')
    if not path or not os.path.exists(path):
        return JsonResponse({'error': 'File not found'}, status=404)
    
    try:
        response = FileResponse(open(path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(path)}"'
        return response
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def file_preview(request):
    """Preview file content"""
    path = request.GET.get('path')
    if not path or not os.path.exists(path):
        return JsonResponse({'error': 'File not found'}, status=404)
    
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(path)
        
        if file_type.startswith('text/'):
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            return render(request, 'list/preview.html', {
                'content': content,
                'path': path,
                'type': file_type
            })
        else:
            return JsonResponse({'error': 'File type not supported for preview'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def delete_item(request):
    """Delete file or directory"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    path = request.POST.get('path')
    if not path or not os.path.exists(path):
        return JsonResponse({'error': 'Item not found'}, status=404)
    
    try:
        if os.path.isdir(path):
            os.rmdir(path)
        else:
            os.remove(path)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def upload_file(request):
    """Upload file to directory"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    path = request.POST.get('path', '/')
    if not os.path.exists(path):
        return JsonResponse({'error': 'Directory not found'}, status=404)
    
    try:
        file = request.FILES.get('file')
        if not file:
            return JsonResponse({'error': 'No file provided'}, status=400)
        
        file_path = os.path.join(path, file.name)
        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def create_folder(request):
    """Create new folder"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    path = request.POST.get('path', '/')
    folder_name = request.POST.get('name')
    
    if not path or not folder_name:
        return JsonResponse({'error': 'Missing path or folder name'}, status=400)
    
    try:
        new_folder_path = os.path.join(path, folder_name)
        os.makedirs(new_folder_path, exist_ok=True)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500) 