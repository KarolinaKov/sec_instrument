from django.core.management.base import BaseCommand

from backend.scheduler import setup_daily_report, setup_scan_cleanup


class Command(BaseCommand):
    help = 'Create or update the daily report and quarterly scan cleanup schedules.'

    def handle(self, *args, **options):
        setup_daily_report()
        setup_scan_cleanup()
        self.stdout.write(self.style.SUCCESS('Daily report and quarterly scan cleanup schedules are configured.'))