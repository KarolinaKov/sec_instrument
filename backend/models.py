from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.utils import timezone
from frontend.models import Test


class LogScan(models.Model):
    """
    Logs each vulnerability scan execution
    """
    STATUS_CHOICES = [
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.AutoField(primary_key=True)
    test = models.ForeignKey(Test, null=True, on_delete=models.SET_NULL, related_name='log_scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='running')
    timestamp_start = models.DateTimeField(default=timezone.now)
    timestamp_end = models.DateTimeField(null=True, blank=True)
    
    live_ips_now = ArrayField(
        models.GenericIPAddressField(),
        default=list,
        help_text="Live IPs found during this scan"
    )
    
    succeeded = models.IntegerField(default=0, help_text="Number of successful scans")
    unsucceeded = models.IntegerField(default=0, help_text="Number of failed scans")
    problematic_ips = ArrayField(
        models.GenericIPAddressField(),
        default=list,
        help_text="IPs where scan failed"
    )
    
    vulnerabilities = models.IntegerField(default=0, help_text="Total vulnerabilities found")
    vulners = ArrayField(
        models.CharField(max_length=500),
        default=list,
        help_text="List of vulnerabilities found"
    )
    
    path_to_file = models.CharField(max_length=500, blank=True, help_text="Path to comprehensive scan output")
    
    consecutive_failures = models.IntegerField(default=0, help_text="Track consecutive failures for this test")
    
    class Meta:
        ordering = ['-timestamp_start']
        indexes = [
            models.Index(fields=['test', '-timestamp_start']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        test_label = self.test.nickname if self.test else 'deleted test'
        return f"LogScan {self.id} - {test_label} - {self.status}"
    
    def duration(self):
        """Calculate scan duration"""
        if self.timestamp_end:
            return (self.timestamp_end - self.timestamp_start).total_seconds()
        return None


class LogScanRetry(models.Model):
    """
    Tracks retry attempts for failed scans
    """
    REASON_CHOICES = [
        (1, 'DifferentIP'),
        (2, 'SmallFail'),
        (3, 'BigFail'),
    ]
    
    id = models.AutoField(primary_key=True)
    log_scan = models.ForeignKey(LogScan, on_delete=models.CASCADE, related_name='retries')
    reason_to_retry = models.IntegerField(choices=REASON_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    scheduled_for = models.DateTimeField(help_text="When the retry is scheduled")
    celery_task_id = models.CharField(max_length=255, blank=True, help_text="Celery task ID for tracking")
    executed = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['log_scan', '-created_at']),
            models.Index(fields=['scheduled_for', 'executed']),
        ]
    
    def __str__(self):
        test_label = self.log_scan.test.nickname if self.log_scan.test else 'deleted test'
        return f"Retry {self.id} - {self.get_reason_to_retry_display()} - {test_label}"