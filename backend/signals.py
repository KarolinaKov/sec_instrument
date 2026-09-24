from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from frontend.models import Test
from backend.scheduler import (
    disable_scan_schedule,
    schedule_next_vulnerability_scan,
    revoke_scheduled_task,
)
import logging

logger = logging.getLogger('backend')

SCHEDULE_TRIGGER_FIELDS = {'cron', 'cron_is_active', 'ip_address', 'prefix', 'hostname'}


@receiver(post_save, sender=Test)
def schedule_scan_on_test_create(sender, instance, created, update_fields=None, **kwargs):
    
    if kwargs.get('raw', False):
        return

    if created:
        logger.info(f"Test {instance.id} created; scheduling will begin once live IPs are discovered.")
        return

    if update_fields is not None:
        if not SCHEDULE_TRIGGER_FIELDS.intersection(update_fields):
            logger.debug(f"Test {instance.id} updated but schedule fields unchanged, skipping reschedule")
            return

    if not instance.cron_is_active:
        logger.info(f"Test {instance.id} updated with cron_is_active=False, disabling schedule...")
        try:
            disable_scan_schedule(instance)
        except Exception as e:
            logger.error(f"Error disabling schedule for test {instance.id}: {e}", exc_info=True)
        return

    logger.info(f"Test {instance.id} updated, rescheduling next vulnerability scan from now...")
    try:
        schedule_next_vulnerability_scan(instance)
        logger.info(f"Successfully rescheduled scan for test {instance.id}")
    except Exception as e:
        logger.error(f"Error rescheduling scan for test {instance.id}: {e}", exc_info=True)


@receiver(post_delete, sender=Test)
def unschedule_scan_on_test_delete(sender, instance, **kwargs):

    logger.info(f"Test {instance.id} deleted, revoking any pending scheduled scan...")
    try:
        revoke_scheduled_task(instance)
        logger.info(f"Successfully revoked pending scan for test {instance.id}")
    except Exception as e:
        logger.error(f"Error revoking pending scan for test {instance.id}: {e}", exc_info=True)
