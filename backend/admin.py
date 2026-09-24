from django.contrib import admin
from .models import LogScan, LogScanRetry


@admin.register(LogScan)
class LogScanAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'test', 'status', 'timestamp_start', 'timestamp_end',
        'succeeded', 'unsucceeded', 'vulnerabilities', 'get_duration'
    ]
    list_filter = ['status', 'timestamp_start', 'test__created_by']
    search_fields = ['test__nickname', 'test__ip_address']
    readonly_fields = [
        'id', 'timestamp_start', 'timestamp_end', 'get_duration',
        'live_ips_now', 'succeeded', 'unsucceeded', 'problematic_ips',
        'vulnerabilities', 'vulners', 'path_to_file', 'consecutive_failures'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'test', 'status', 'timestamp_start', 'timestamp_end', 'get_duration')
        }),
        ('IP Discovery', {
            'fields': ('live_ips_now',)
        }),
        ('Scan Results', {
            'fields': ('succeeded', 'unsucceeded', 'problematic_ips', 'consecutive_failures')
        }),
        ('Vulnerabilities', {
            'fields': ('vulnerabilities', 'vulners', 'path_to_file')
        }),
    )
    
    def get_duration(self, obj):
        duration = obj.duration()
        if duration:
            return f"{duration:.2f}s"
        return "In progress"
    get_duration.short_description = 'Duration'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LogScanRetry)
class LogScanRetryAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'log_scan', 'get_reason', 'scheduled_for',
        'executed', 'created_at', 'celery_task_id'
    ]
    list_filter = ['reason_to_retry', 'executed', 'scheduled_for']
    search_fields = ['log_scan__test__nickname', 'celery_task_id']
    readonly_fields = [
        'id', 'log_scan', 'reason_to_retry', 'created_at',
        'scheduled_for', 'celery_task_id', 'executed'
    ]
    
    def get_reason(self, obj):
        return obj.get_reason_to_retry_display()
    get_reason.short_description = 'Reason'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False