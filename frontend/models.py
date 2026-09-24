from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField


class TestIP(models.Model):
    id = models.AutoField(primary_key=True)
    ip_address = ArrayField(
        models.GenericIPAddressField(),
        default=list
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return ', '.join(self.ip_address) if self.ip_address else 'No IPs'


class Test(models.Model):
    id = models.AutoField(primary_key=True)
    ip_address = models.GenericIPAddressField()
    prefix = models.IntegerField()
    hostname = models.CharField(max_length=255, blank=True, default='')
    nickname = models.CharField(max_length=255)
    cron = models.CharField(max_length=100)
    cron_is_active = models.BooleanField(default=True)
    new_vulnerability_alerts_enabled = models.BooleanField(default=False)
    new_vulnerability_alerts_since = models.DateTimeField(null=True, blank=True)
    new_vulnerability_alerts_log_scan_id = models.IntegerField(null=True, blank=True)
    last_test = models.DateTimeField(null=True, blank=True)
    next_scheduled = models.DateTimeField(null=True, blank=True)
    scheduled_task_id = models.CharField(
        max_length=255, blank=True, default='',
        help_text="Celery task ID of the currently pending one-shot vulnerability scan, if any"
    )
    when_added = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='tests')
    ip_current = models.ForeignKey(TestIP, null=True, blank=True, on_delete=models.SET_NULL, related_name='current_for')
    
    class Meta:
        ordering = ['-when_added']
    
    def __str__(self):
        return f"{self.nickname} ({self.ip_address}/{self.prefix})"