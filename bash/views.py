import os
import stat
import subprocess
import sys

if sys.platform != 'win32':
    import pwd

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .cmd import ls, mkdir, cp, mv, touch, chmod, isTextFile
import logging

logger = logging.getLogger(__name__)

def index(request):
    return render(request, 'bash/index.html')

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_owner(uid):
    try:
        import grp
        return grp.getgrgid(uid).gr_name
    except:
        return str(uid)

def get_group(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except:
        return str(gid)

def get_items(path):
    items = []
    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        stat = os.stat(item_path)
        items.append({
            'name': item,
            'type': 'directory' if os.path.isdir(item_path) else 'file',
            'size': format_size(stat.st_size),
            'owner': get_owner(stat.st_uid),
            'group': get_group(stat.st_gid),
            'permissions': oct(stat.st_mode)[-3:],
            'path': item_path
        })
    return items

def get_username_from_uid(uid):
    """Get username from uid"""
    if sys.platform != 'win32':
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)
    else:
        return str(uid) # On Windows, just return the UID

@csrf_exempt
def api_mkdir(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            path = data.get('path')
            if not path:
                return JsonResponse({'success': False, 'error': 'Dizin yolu belirtilmedi.'})
            
            result = mkdir(path)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

@csrf_exempt
def api_touch(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            path = data.get('path')
            if not path:
                return JsonResponse({'success': False, 'error': 'Dosya yolu belirtilmedi.'})
            
            result = touch(path)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

@csrf_exempt
def api_mv(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            src = data.get('src')
            dest = data.get('dest')
            if not src or not dest:
                return JsonResponse({'success': False, 'error': 'Kaynak veya hedef belirtilmedi.'})
            
            result = mv(src, dest)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

@csrf_exempt
def api_cp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            src = data.get('src')
            dest = data.get('dest')
            if not src or not dest:
                return JsonResponse({'success': False, 'error': 'Kaynak veya hedef belirtilmedi.'})
            
            result = cp(src, dest)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

@csrf_exempt
def api_chmod(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            path = data.get('path')
            mode = data.get('mode')
            if not path or not mode:
                return JsonResponse({'success': False, 'error': 'Dosya yolu veya izin modu belirtilmedi.'})
            
            result = chmod(path, mode)
            return JsonResponse(result)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

def edit(request):
    path = request.GET.get('path')
    if not path:
        return render(request, 'bash/edit.html', {'patherror': True})
    
    if not os.path.exists(path):
        return render(request, 'bash/edit.html', {'notfounderror': True})
    
    if not isTextFile(path):
        return render(request, 'bash/edit.html', {'texterror': True})
    
    with open(path, 'r', encoding='utf-8') as f:
        data = f.read()
    
    return render(request, 'bash/edit.html', {'path': path, 'data': data})

@csrf_exempt
def api_savefile(request):
    if request.method == 'POST':
        try:
            path = request.POST.get('path')
            text = request.POST.get('text')
            if not path or text is None:
                return JsonResponse({'success': False, 'error': 'Dosya yolu veya içerik belirtilmedi.'})
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'})

@csrf_exempt
def run_bash_command(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            command = data.get('command')
            if not command:
                return JsonResponse({'success': False, 'error': 'Komut belirtilmedi.'})
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return JsonResponse({
                'success': True,
                'output': result.stdout,
                'error': result.stderr
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu.'}) 