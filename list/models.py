from django.db import models
from django.conf import settings
import os
import hashlib
from django.utils import timezone

class File(models.Model):
    """Model for storing file information."""
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=1000)
    size = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    is_directory = models.BooleanField(default=False)
    owner = models.CharField(max_length=100, blank=True)
    group = models.CharField(max_length=100, blank=True)
    permissions = models.CharField(max_length=10, blank=True)
    mime_type = models.CharField(max_length=100, blank=True)
    is_quarantined = models.BooleanField(default=False)
    quarantine_date = models.DateTimeField(null=True, blank=True)
    scan_status = models.CharField(max_length=20, default='pending')  # pending, scanning, scanned, error
    scan_result = models.TextField(blank=True)
    scan_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['path']),
            models.Index(fields=['is_directory']),
            models.Index(fields=['is_quarantined']),
            models.Index(fields=['scan_status']),
        ]

    def __str__(self):
        return self.name

    def get_absolute_path(self):
        """Return the absolute path of the file."""
        return self.path

    def is_safe(self):
        """Check if the file is safe based on scan results."""
        return self.scan_status == 'scanned' and not self.scan_result
