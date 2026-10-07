from django.db import transaction
from .tasks import scan_network_task
import logging
logger = logging.getLogger('backend')

def create_live_ips(ip, prefix, test_object):
    """
    Trigger an immediate asynchronous quick "live IPs" scan.
    Returns immediately without waiting.
    Fired via transaction.on_commit so it only runs once the Test row is
    actually committed and visible to the worker (and any UI polling it) -
    without an arbitrary fixed delay.
    """
    def enqueue_scan():
        logger.info(
            "Publishing scan_network_task for test %s: %s/%s",
            test_object.id,
            ip,
            prefix,
        )
        result = scan_network_task.apply_async(
            args=[test_object.id, ip, prefix]
        )
        logger.info(
            "Published scan_network_task for test %s as task %s",
            test_object.id,
            result.id,
        )
    transaction.on_commit(enqueue_scan)
    return True
