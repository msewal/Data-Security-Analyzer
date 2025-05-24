from django.db import models
from django.conf import settings
import os
import hashlib
from datetime import datetime

class QuarantinedFile(models.Model):
    filename = models.CharField(max_length=255)
    original_path = models.CharField(max_length=255)
    quarantine_path = models.CharField(max_length=255)
    reason = models.CharField(max_length=255)
    quarantine_time = models.DateTimeField(auto_now_add=True)
    scan_type = models.CharField(max_length=50)
    hash = models.CharField(max_length=64)  # SHA-256 hash
    size = models.BigIntegerField()

    def __str__(self):
        return self.filename

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
