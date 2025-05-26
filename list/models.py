from django.db import models
from django.conf import settings
import os
import hashlib
from datetime import datetime
from django.utils import timezone

class QuarantinedFile(models.Model):
    THREAT_LEVELS = [
        ('low', 'Düşük'),
        ('medium', 'Orta'),
        ('high', 'Yüksek')
    ]

    filename = models.CharField(max_length=255)
    original_path = models.CharField(max_length=1024)
    quarantine_path = models.CharField(max_length=1024)
    malware_type = models.CharField(max_length=100, null=True, blank=True)
    scan_tool = models.CharField(max_length=100)
    quarantine_time = models.DateTimeField(default=timezone.now)
    file_size = models.BigIntegerField(default=0)  # bytes cinsinden
    file_hash = models.CharField(max_length=64)  # SHA256 hash
    detected_by_user = models.CharField(max_length=100, null=True, blank=True)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS, default='medium')
    status = models.CharField(max_length=20, default='quarantined')  # quarantined, restored, deleted

    def __str__(self):
        return f"{self.filename} ({self.malware_type})"

    class Meta:
        ordering = ['-quarantine_time']

    @classmethod
    def create_from_file(cls, file_path, reason, scan_type):
        """Create a QuarantinedFile instance from a file."""
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(settings.QUARANTINE_DIR, filename + '.quarantine')
        
        # Calculate file hash
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        return cls.objects.create(
            filename=filename,
            original_path=file_path,
            quarantine_path=quarantine_path,
            reason=reason,
            scan_type=scan_type,
            hash=file_hash,
            size=file_size
        )

    def get_file_size_display(self):
        """Dosya boyutunu okunabilir formatta döndürür"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} PB"
