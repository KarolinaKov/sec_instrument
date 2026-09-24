from django.core.management.base import BaseCommand

from backend.scheduler import setup_daily_report


class Command(BaseCommand):
    help = 'Create or update the daily scan report schedule.'

    def handle(self, *args, **options):
        setup_daily_report()
        self.stdout.write(self.style.SUCCESS('Daily report schedule is configured.'))