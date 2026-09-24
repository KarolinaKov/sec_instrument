from celery import shared_task
from django.db import transaction
import subprocess
import ipaddress
from .models import TestIP, Test
from .dns_utils import resolve_hostname_ips


@shared_task(bind=True)
def scan_network_task(self, test_id, ip, prefix):
    try:
        test = Test.objects.get(id=test_id)

        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        live_ips = []

        print(f"Scanning network {ip}/{prefix}...")

        for host_ip in network.hosts():
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(host_ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if result.returncode == 0:
                live_ips.append(str(host_ip))
                print(f"Found live IP: {host_ip}")

        if test.hostname:
            for resolved_ip in resolve_hostname_ips(test.hostname):
                if resolved_ip not in live_ips:
                    live_ips.append(resolved_ip)

        print(f"Scan complete. Found {len(live_ips)} live IPs")

        with transaction.atomic():
            locked_test = Test.objects.select_for_update().get(id=test_id)
            test_ip = TestIP.objects.create(ip_address=live_ips)
            locked_test.ip_current = test_ip
            locked_test.save(update_fields=['ip_current'])

        print(f"Successfully scanned {ip}/{prefix}: Found {len(live_ips)} live IPs")

        try:
            from backend.scheduler import schedule_next_vulnerability_scan
            schedule_next_vulnerability_scan(locked_test)
        except Exception as e:
            print(f"Error scheduling vulnerability scan for test {test_id}: {e}")

        return {'success': True, 'count': len(live_ips)}

    except Exception as e:
        print(f"Scan error: {e}")
        return {'success': False, 'error': str(e)}