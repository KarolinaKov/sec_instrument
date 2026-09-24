from celery import shared_task
from croniter import croniter
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from django.utils import timezone
import logging

logger = logging.getLogger('celery')


def compute_next_run_time(cron_expr, base_time=None):

    base_time = base_time or timezone.now()
    local_base_time = timezone.localtime(base_time)

    cron_parts = cron_expr.strip().split()
    if len(cron_parts) != 5:
        raise ValueError(f"Invalid cron format: {cron_expr}. Expected 5 fields: min hour day month day_of_week")

    return croniter(cron_expr, local_base_time).get_next(type(local_base_time))


def schedule_next_vulnerability_scan(test, base_time=None):

    from backend.backend_tasks_kali import vulnerability_scan_task
    from frontend.models import Test

    next_run = compute_next_run_time(test.cron, base_time)

    revoke_scheduled_task(test)

    task = vulnerability_scan_task.apply_async(args=[test.id], eta=next_run)

    Test.objects.filter(id=test.id).update(
        next_scheduled=next_run,
        scheduled_task_id=task.id,
    )
    test.next_scheduled = next_run
    test.scheduled_task_id = task.id

    logger.info(f"Scheduled next vulnerability scan for test {test.id} at {next_run} (task {task.id})")

    return next_run


def revoke_scheduled_task(test):

    if not test.scheduled_task_id:
        return

    from sec_instrument.celery import app as celery_app

    try:
        celery_app.control.revoke(test.scheduled_task_id)
        logger.info(f"Revoked pending scan task {test.scheduled_task_id} for test {test.id}")
    except Exception as e:
        logger.warning(f"Could not revoke task {test.scheduled_task_id} for test {test.id}: {e}")


def enable_scan_schedule(test, base_time=None):

    from frontend.models import Test

    Test.objects.filter(id=test.id).update(cron_is_active=True)
    test.cron_is_active = True

    next_run = schedule_next_vulnerability_scan(test, base_time)
    logger.info(f"Enabled schedule for test {test.id}, next run at {next_run}")
    return next_run


def disable_scan_schedule(test):

    from frontend.models import Test

    revoke_scheduled_task(test)

    Test.objects.filter(id=test.id).update(
        cron_is_active=False,
        next_scheduled=None,
        scheduled_task_id='',
    )
    test.cron_is_active = False
    test.next_scheduled = None
    test.scheduled_task_id = ''

    logger.info(f"Disabled schedule for test {test.id}")


def setup_daily_report():

    schedule, created = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='8',
        day_of_month='*',
        month_of_year='*',
        day_of_week='*',
        timezone=timezone.get_current_timezone()
    )

    task, created = PeriodicTask.objects.update_or_create(
        name='daily_scan_report',
        defaults={
            'crontab': schedule,
            'task': 'backend.backend_tasks_kali.send_daily_report',
            'enabled': True,
        }
    )

    action = "Created" if created else "Updated"
    logger.info(f"{action} daily report task to run at 8:00 AM")

    return task


@shared_task
def cleanup_old_scans(days=30):

    from backend.models import LogScan
    from datetime import timedelta
    import shutil
    from pathlib import Path
    from django.conf import settings

    logger.info(f"Starting cleanup of scans older than {days} days...")

    cutoff_date = timezone.now() - timedelta(days=days)

    old_scans = LogScan.objects.filter(timestamp_start__lt=cutoff_date)
    count = old_scans.count()

    for scan in old_scans:
        if scan.path_to_file:
            file_path = Path(scan.path_to_file)
            if file_path.exists():
                log_dir = file_path.parent
                try:
                    shutil.rmtree(log_dir)
                    logger.debug(f"Deleted scan directory: {log_dir}")
                except Exception as e:
                    logger.error(f"Error deleting directory {log_dir}: {e}")

    old_scans.delete()

    logger.info(f"Cleaned up {count} old scan logs older than {days} days")
    return {'deleted': count}
