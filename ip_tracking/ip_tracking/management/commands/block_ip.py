from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Model to log incoming requests with IP, timestamp, and path."""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        db_table = 'ip_tracking_requestlog'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"


class BlockedIP(models.Model):
    """Model to store blacklisted IP addresses."""
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'ip_tracking_blockedip'

    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """Model to store IPs flagged as suspicious."""
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=255)
    flagged_at = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)

    class Meta:
        db_table = 'ip_tracking_suspiciousip'
        ordering = ['-flagged_at']

    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"