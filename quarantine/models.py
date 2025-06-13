from django.db import models

class QuarantinedFile(models.Model):
    filename = models.CharField(max_length=255)
    original_path = models.CharField(max_length=500)
    quarantine_path = models.CharField(max_length=500)
    quarantine_time = models.DateTimeField(auto_now_add=True)
    threat_type = models.CharField(max_length=100)
    threat_level = models.CharField(max_length=50)
    status = models.CharField(max_length=50, default='quarantined')
    scan_tool = models.CharField(max_length=100)
    detected_by_user = models.CharField(max_length=100)
    file_size = models.BigIntegerField(null=True, blank=True)
    file_hash = models.CharField(max_length=64, null=True, blank=True)
    
    class Meta:
        ordering = ['-quarantine_time']
        
    def __str__(self):
        return self.filename 