from django.contrib import admin
from .models import Test, TestIP


@admin.register(TestIP)
class TestIPAdmin(admin.ModelAdmin):
    list_display = ['id', '__str__', 'created_at']
    readonly_fields = ['id', 'ip_address', 'created_at']

    def has_add_permission(self, request):
        return False


@admin.register(Test)
class TestAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'nickname', 'ip_address', 'prefix', 'hostname', 'cron', 'cron_is_active',
        'last_test', 'next_scheduled', 'when_added', 'created_by',
    ]
    list_filter = ['cron_is_active', 'created_by']
    search_fields = ['nickname', 'ip_address', 'hostname', 'created_by__username']
    readonly_fields = [
        'id', 'when_added', 'last_test', 'next_scheduled',
        'scheduled_task_id', 'ip_current',
    ]

    fieldsets = (
        ('Target', {
            'fields': ('id', 'nickname', 'ip_address', 'prefix', 'created_by')
        }),
        ('Schedule', {
            'fields': ('cron', 'cron_is_active', 'next_scheduled', 'scheduled_task_id')
        }),
        ('History', {
            'fields': ('last_test', 'when_added', 'ip_current')
        }),
    )
