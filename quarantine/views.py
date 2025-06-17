import os
import shutil
import json
import hashlib
import urllib.parse
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from malware.models import QuarantinedFile
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def convert_to_wsl_path(path):
    """Dosya yolunu WSL/Linux yoluna dönüştürür."""
    if not path:
        return None
    
    # Zaten Linux yolu ise olduğu gibi döndür
    if path.startswith('/'):
        return path
    
    # Windows yolunu Linux yoluna dönüştür
    path = path.replace('\\', '/')
    
    # Sürücü harfini kontrol et ve dönüştür (C: -> /mnt/c)
    if ':' in path:
        drive, rest = path.split(':', 1)
        return f"/mnt/{drive.lower()}{rest}"
    
    return path

def convert_to_linux_path(wsl_path):
    """WSL dosya yolunu standart Linux yoluna dönüştürür."""
    if not wsl_path:
        return None
    
    # /mnt/ ile başlayan yolları home dizinine dönüştür
    if wsl_path.startswith('/mnt/'):
        parts = wsl_path.split('/', 3)
        if len(parts) >= 4:
            # /mnt/c/Users/... -> /home/user/...
            rest = parts[3]
            if 'Users' in rest:
                user_part = rest.split('Users/')[-1] if 'Users/' in rest else rest
                return f"/home/{user_part}"
    
    return wsl_path

def quarantine_list(request):
    """View function for listing quarantined files"""
    files = QuarantinedFile.objects.all().order_by('-quarantine_time')
    
    # İstatistikleri hesapla
    scan_tools = files.values_list('scan_tool', flat=True).distinct()
    threat_types = files.values_list('malware_type', flat=True).distinct()
    total_size = sum(file.file_size for file in files)
    
    # Toplam boyutu okunabilir formata çevir
    def format_size(size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    context = {
        'files': files,
        'scan_tools_count': len(scan_tools),
        'threat_types_count': len(threat_types),
        'total_size': format_size(total_size)
    }
    
    return render(request, 'quarantine/quarantine.html', context)

@csrf_exempt
def quarantine_file(request):
    """View function for quarantining files from regex scanner"""
    try:
        if request.method != 'POST':
            return JsonResponse({'success': False, 'error': 'Sadece POST istekleri kabul edilir'})

        # Debug bilgileri
        print("Content-Type:", request.headers.get("Content-Type"))
        print("GELEN VERİ:", repr(request.body))
        print("TİP:", type(request.body))

        # Önce form verilerini kontrol et
        file_path = request.POST.get('file_path')
        malware_type = request.POST.get('threat_type', 'Sensitive Data')
        threat_level = request.POST.get('threat_level', 'high')
        detected_pattern = request.POST.get('detected_pattern', '')

        # Eğer form verisi yoksa, JSON verisini dene
        if not file_path and request.body:
            try:
                # JSON verisini decode et
                data = request.body.decode('utf-8')
                print("DECODED:", repr(data))
                
                if data:  # Boş değilse JSON parse et
                    json_data = json.loads(data)
                    file_path = json_data.get('file_path')
                    malware_type = json_data.get('threat_type', 'Sensitive Data')
                    threat_level = json_data.get('threat_level', 'high')
                    detected_pattern = json_data.get('detected_pattern', '')
                else:
                    print("Uyarı: JSON verisi boş!")
            except json.JSONDecodeError as e:
                print("JSON hatası:", e)
                print("Gelen veri:", repr(request.body))
                return JsonResponse({'success': False, 'error': f'Geçersiz JSON verisi: {str(e)}'})
            except Exception as e:
                print("Beklenmeyen hata:", e)
                return JsonResponse({'success': False, 'error': f'Veri işleme hatası: {str(e)}'})

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
                malware_type=malware_type,
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
        logger.error(f"Karantina hatası: {str(e)}")
        return JsonResponse({'success': False, 'error': f'Karantina işlemi başarısız: {str(e)}'})

@require_http_methods(["POST"])
def restore_file(request, file_id):
    """View function for restoring a quarantined file"""
    try:
        quarantined_file = get_object_or_404(QuarantinedFile, id=file_id)
        
        # Dosya yolunu Linux yoluna dönüştür
        original_wsl_path = convert_to_wsl_path(quarantined_file.original_path)
        quarantine_wsl_path = convert_to_wsl_path(quarantined_file.quarantine_path)
        
        if not original_wsl_path or not quarantine_wsl_path:
            return JsonResponse({'success': False, 'error': 'Geçersiz dosya yolu'})
        
        # Orijinal dizini oluştur
        os.makedirs(os.path.dirname(original_wsl_path), exist_ok=True)
        
        # Dosyayı geri taşı
        shutil.move(quarantine_wsl_path, original_wsl_path)
        
        # Veritabanından sil
        quarantined_file.delete()
        
        return JsonResponse({'success': True, 'message': 'Dosya başarıyla geri yüklendi'})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Geri yükleme işlemi başarısız: {str(e)}'})

@require_http_methods(["POST"])
def delete_file(request, file_id):
    """View function for permanently deleting a quarantined file"""
    try:
        quarantined_file = get_object_or_404(QuarantinedFile, id=file_id)
        
        # WSL yolunu al
        quarantine_wsl_path = convert_to_wsl_path(quarantined_file.quarantine_path)
        
        if not quarantine_wsl_path:
            return JsonResponse({'success': False, 'error': 'Geçersiz dosya yolu'})
        
        # Dosyayı sil
        if os.path.exists(quarantine_wsl_path):
            os.remove(quarantine_wsl_path)
        
        # Veritabanından sil
        quarantined_file.delete()
        
        return JsonResponse({'success': True, 'message': 'Dosya başarıyla silindi'})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Silme işlemi başarısız: {str(e)}'}) 