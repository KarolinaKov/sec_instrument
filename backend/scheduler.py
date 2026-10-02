from croniter import croniter
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from django.utils import timezone
from frontend.models import Test
import logging

logger = logging.getLogger('celery')


def _periodic_task_name(test):
    return f'vulnerability_scan_{test.id}'


def compute_next_run_time(cron_expr, base_time=None):

    base_time = base_time or timezone.now()
    local_base_time = timezone.localtime(base_time)

    cron_parts = cron_expr.strip().split()
    if len(cron_parts) != 5:
        raise ValueError(f"Invalid cron format: {cron_expr}. Expected 5 fields: min hour day month day_of_week")

    return croniter(cron_expr, local_base_time).get_next(type(local_base_time))


def schedule_next_vulnerability_scan(test, base_time=None):
    from backend.backend_tasks_kali import vulnerability_scan_task
    from django.conf import settings

    revoke_scheduled_task(test)

    next_run = compute_next_run_time(test.cron, base_time)

    cron_parts = test.cron.strip().split()
    crontab, _ = CrontabSchedule.objects.get_or_create(
        minute=cron_parts[0],
        hour=cron_parts[1],
        day_of_month=cron_parts[2],
        month_of_year=cron_parts[3],
        day_of_week=cron_parts[4],
        timezone=settings.TIME_ZONE,
    )
    PeriodicTask.objects.update_or_create(
        name=_periodic_task_name(test),
        defaults={
            'crontab': crontab,
            'task': vulnerability_scan_task.name,
            'args': f'[{test.id}]',
            'enabled': True,
        },
    )

    Test.objects.filter(id=test.id).update(
        next_scheduled=next_run,
        scheduled_task_id='',
        status=1,
    )
    test.next_scheduled = next_run
    test.scheduled_task_id = ''
    test.status = 1

    logger.info(f"Scheduled vulnerability scan for test {test.id} with Celery Beat at {next_run}")

    return next_run

def schedule_retry(test, log_scan, reason, hours_delay=0, high_priority=False):
    from backend.backend_tasks_kali import vulnerability_scan_task
    from backend.models import LogScanRetry
    from datetime import timedelta

    scheduled_time = timezone.now() + timedelta(hours=hours_delay)

    retry = LogScanRetry.objects.create(
        log_scan=log_scan,
        reason_to_retry=reason,
        scheduled_for=scheduled_time,
    )

    revoke_scheduled_task(test)
    PeriodicTask.objects.filter(name=_periodic_task_name(test)).update(enabled=False)

    task = vulnerability_scan_task.apply_async(
        args=[log_scan.test.id],
        eta=scheduled_time,
        priority=9 if high_priority else 5,
    )

    retry.celery_task_id = task.id
    retry.save(update_fields=['celery_task_id'])

    Test.objects.filter(id=test.id).update(
        next_scheduled= scheduled_time,
        scheduled_task_id=task.id,
        status=2,
    )
    test.next_scheduled = scheduled_time
    test.scheduled_task_id = task.id
    test.status = 2

    logger.info(
        f"Scheduled retry {retry.id} for {scheduled_time} "
        f"(reason: {reason})"
    )
    return retry


def revoke_scheduled_task(test):

    if not test.scheduled_task_id:
        return

    from sec_instrument.celery import app as celery_app

    try:
        celery_app.control.revoke(test.scheduled_task_id)
        logger.info(f"Revoked pending scan task {test.scheduled_task_id} for test {test.id}")
    except Exception as e:
        logger.warning(f"Could not revoke task {test.scheduled_task_id} for test {test.id}: {e}")


def remove_periodic_scan(test):
    PeriodicTask.objects.filter(name=_periodic_task_name(test)).delete()

def enable_scan_schedule(test, base_time=None):

    from frontend.models import Test

    Test.objects.filter(id=test.id).update(cron_is_active=True, status=1)
    test.cron_is_active = True
    test.status = 1

    next_run = schedule_next_vulnerability_scan(test, base_time)
    logger.info(f"Enabled schedule for test {test.id}, next run at {next_run}")
    return next_run


def disable_scan_schedule(test):

    from frontend.models import Test

    revoke_scheduled_task(test)
    PeriodicTask.objects.filter(name=_periodic_task_name(test)).update(enabled=False)

    Test.objects.filter(id=test.id).update(
        cron_is_active=False,
        next_scheduled=None,
        scheduled_task_id='',
        status=3,
    )
    test.cron_is_active = False
    test.next_scheduled = None
    test.scheduled_task_id = ''
    test.status = 3

    logger.info(f"Disabled schedule for test {test.id}")


def setup_daily_report():
    from django.conf import settings

    schedule, created = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='8',
        day_of_month='*',
        month_of_year='*',
        day_of_week='*',
        timezone=settings.TIME_ZONE
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


def setup_scan_cleanup():
    from backend.backend_tasks_kali import cleanup_old_scans
    from django.conf import settings

    schedule, created = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='3',
        day_of_month='1',
        month_of_year='1,4,7,10',
        day_of_week='*',
        timezone=settings.TIME_ZONE,
    )

    task, created = PeriodicTask.objects.update_or_create(
        name='quarterly_scan_cleanup',
        defaults={
            'crontab': schedule,
            'task': cleanup_old_scans.name,
            'enabled': True,
        }
    )

    logger.info("Configured quarterly scan output archival at 3:00 AM")
    return task
