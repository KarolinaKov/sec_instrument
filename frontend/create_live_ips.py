from django.db import transaction
from .tasks import scan_network_task


def create_live_ips(ip, prefix, test_object):
    """
    Trigger an immediate asynchronous quick "live IPs" scan.
    Returns immediately without waiting.
    Fired via transaction.on_commit so it only runs once the Test row is
    actually committed and visible to the worker (and any UI polling it) -
    without an arbitrary fixed delay.
    """
    transaction.on_commit(
        lambda: scan_network_task.apply_async(args=[test_object.id, ip, prefix])
    )
    return True
