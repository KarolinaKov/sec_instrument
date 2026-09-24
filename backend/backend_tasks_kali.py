from celery import shared_task
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta, datetime
import subprocess
import ipaddress
import os
import json
from pathlib import Path
import re
import logging


logger = logging.getLogger('celery')


SCAN_TOOLS = {
    'nmap': {
        'enabled': True,
        'timeout': 300,
        'command': ['nmap', '-sV', '-sC', '--script=vuln', '{ip}', '-oN', '{output}']
    },
    'nikto': {
        'enabled': True,
        'timeout': 600,
        'command': ['nikto', '-h', '{ip}', '-output', '{output}', '-Format', 'txt']
    },
    'openvas': {
        'enabled': False,
        'timeout': 1800,
        'use_gvm': True
    },
    'nuclei': {
        'enabled': True,
        'timeout': 300,
        'command': ['nuclei', '-u', 'http://{ip}', '-o', '{output}', '-silent']
    },
    'whatweb': {
        'enabled': True,
        'timeout': 60,
        'command': ['whatweb', '{ip}', '-v', '--log-verbose={output}']
    },
    'sslyze': {
        'enabled': True,
        'timeout': 120,
        'command': ['sslyze', '--regular', '{ip}', '--json_out={output}']
    },
}

NOTIFICATION_EMAIL = getattr(settings, 'SCAN_NOTIFICATION_EMAIL', 'admin@example.com')


def sanitize_path_component(value):
    """
    Make a string safe to use as a single filesystem path segment, on both
    POSIX and Windows.
    """
    value = str(value).strip()
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', value)
    value = value.strip(' .')
    return value or 'unnamed'


@shared_task(bind=True)
def vulnerability_scan_task(self, test_id):
    """
    Main vulnerability scanning task using multiple Kali Linux tools
    Performs comprehensive security scan on all live IPs
    """
    from frontend.models import Test, TestIP
    from frontend.dns_utils import resolve_hostname_ips
    from backend.models import LogScan, LogScanRetry
    from backend.scheduler import disable_scan_schedule, enable_scan_schedule
    
    logger.info(f"Starting vulnerability scan for test_id: {test_id}")
    
    try:
        test = Test.objects.get(id=test_id)
        
        log_scan = LogScan.objects.create(
            test=test,
            status='running',
            timestamp_start=timezone.now()
        )
        
        logger.info(f"[SCAN START] Test ID: {test_id}, LogScan ID: {log_scan.id}")
        
        
        network = ipaddress.ip_network(f"{test.ip_address}/{test.prefix}", strict=False)
        live_ips = []
        
        logger.info(f"Discovering live IPs in {test.ip_address}/{test.prefix}...")
        
        for host_ip in network.hosts():
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(host_ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            if result.returncode == 0:
                live_ips.append(str(host_ip))
                logger.debug(f"Found live IP: {host_ip}")
        if test.hostname:
            for resolved_ip in resolve_hostname_ips(test.hostname):
                if resolved_ip not in live_ips:
                    live_ips.append(resolved_ip)

        log_scan.live_ips_now = live_ips
        log_scan.save()
        
        logger.info(f"Discovery complete. Found {len(live_ips)} live IPs")
        
        
        ip_count_changed = False
        if test.ip_current and test.ip_current.ip_address:
            previous_ips = set(test.ip_current.ip_address)
            current_ips = set(live_ips)
            
            if previous_ips != current_ips:
                ip_count_changed = True
                logger.warning(f"IP change detected: {len(previous_ips)} -> {len(current_ips)}")
                
                
                send_ip_change_notification(test, log_scan, len(live_ips))
                
                schedule_retry(log_scan, reason=1, hours_delay=8)
        
          
        succeeded = 0
        unsucceeded = 0
        problematic_ips = []
        all_vulnerabilities = []
        
        scan_date = timezone.localtime(log_scan.timestamp_start).date().isoformat()
        safe_nickname = f"{sanitize_path_component(test.nickname)}_{test.id}"
        output_dir = Path(settings.BASE_DIR) / 'scan_outputs' / scan_date / safe_nickname
        output_dir.mkdir(parents=True, exist_ok=True)
        
        comprehensive_output = {
            'test_id': test_id,
            'log_scan_id': log_scan.id,
            'nickname': test.nickname,
            'scan_start': str(log_scan.timestamp_start),
            'network': f"{test.ip_address}/{test.prefix}",
            'live_ips_count': len(live_ips),
            'tools_used': [tool for tool, config in SCAN_TOOLS.items() if config['enabled']],
            'results': []
        }
        
        for ip in live_ips:
            logger.info(f"Scanning {ip} with multiple tools...")
            scan_result = perform_multi_tool_scan(ip, output_dir, log_scan.id)

            if scan_result.get('vulnerabilities'):
                all_vulnerabilities.extend(scan_result['vulnerabilities'])
            
            if scan_result['success']:
                succeeded += 1
                comprehensive_output['results'].append({
                    'ip': ip,
                    'status': 'success',
                    'tool_results': scan_result.get('tool_results', {}),
                    'vulnerabilities': scan_result.get('vulnerabilities', []),
                    'services': scan_result.get('services', [])
                })
                
            else:
                unsucceeded += 1
                problematic_ips.append(ip)
                comprehensive_output['results'].append({
                    'ip': ip,
                    'status': 'failed',
                    'error': scan_result.get('error', 'Unknown error'),
                    'tool_results': scan_result.get('tool_results', {}),
                    'vulnerabilities': scan_result.get('vulnerabilities', [])
                })
        
        output_file = output_dir / f'comprehensive_scan_log{log_scan.id}.json'
        with open(output_file, 'w') as f:
            json.dump(comprehensive_output, f, indent=2)
        
        log_scan.succeeded = succeeded
        log_scan.unsucceeded = unsucceeded
        log_scan.problematic_ips = problematic_ips
        log_scan.vulnerabilities = len(all_vulnerabilities)
        log_scan.vulners = all_vulnerabilities
        log_scan.path_to_file = str(output_file)
        log_scan.timestamp_end = timezone.now()
        
        if unsucceeded > 0:
            previous_logs = LogScan.objects.filter(
                test=test,
                timestamp_start__lt=log_scan.timestamp_start
            ).order_by('-timestamp_start')

            consecutive_count = 0
            for prev_log in previous_logs:
                if prev_log.unsucceeded > 0:
                    consecutive_count += 1
                else:
                    break
            
            log_scan.consecutive_failures = consecutive_count + 1
            
            if consecutive_count >= 2:
                
                logger.error(f"Test {test.id} failed 3 times consecutively. Disabling schedule.")
                log_scan.status = 'failed'

                
                disable_scan_schedule(test)

                schedule_retry(log_scan, reason=3, hours_delay=8)

                send_scan_failure_notification(test, log_scan, problematic_ips)
            else:
                logger.warning(f"Test {test.id} had partial failure. Scheduling immediate retry.")
                log_scan.status = 'completed'
                schedule_retry(log_scan, reason=2, hours_delay=0, high_priority=True)
        else:
            log_scan.status = 'completed'
            log_scan.consecutive_failures = 0

            if not test.cron_is_active:
                logger.info(f"Test {test.id} succeeded after failures. Re-enabling schedule.")
            enable_scan_schedule(test)
        
        log_scan.save()

        from django.db import transaction
        with transaction.atomic():
            locked_test = Test.objects.select_for_update().get(id=test.id)
            current_ips = set(live_ips)
            previous_ips = set(
                locked_test.ip_current.ip_address
                if locked_test.ip_current else []
            )

            if locked_test.ip_current is None or current_ips != previous_ips:
                locked_test.ip_current = TestIP.objects.create(ip_address=live_ips)

            locked_test.last_test = timezone.now()
            locked_test.save(update_fields=['ip_current', 'last_test'])
        
        alert_vulnerabilities = all_vulnerabilities
        if test.new_vulnerability_alerts_enabled:
            previous_vulnerabilities = []
            if test.new_vulnerability_alerts_log_scan_id:
                previous_scan = LogScan.objects.filter(
                    id=test.new_vulnerability_alerts_log_scan_id,
                    test=test
                ).first()
                if previous_scan:
                    previous_vulnerabilities = previous_scan.vulners

            alert_vulnerabilities = sorted(
                set(all_vulnerabilities) - set(previous_vulnerabilities)
            ) if previous_vulnerabilities or test.new_vulnerability_alerts_log_scan_id else []

            test.new_vulnerability_alerts_log_scan_id = log_scan.id
            test.save(update_fields=['new_vulnerability_alerts_log_scan_id'])

        if alert_vulnerabilities:
            send_vulnerability_notification(test, log_scan, alert_vulnerabilities, str(output_file))
        
        logger.info(f"[SCAN COMPLETE] LogScan ID: {log_scan.id}, Status: {log_scan.status}")
        logger.info(f"Results: {succeeded} succeeded, {unsucceeded} failed, {len(all_vulnerabilities)} vulnerabilities")
        
        return {
            'success': True,
            'log_scan_id': log_scan.id,
            'succeeded': succeeded,
            'unsucceeded': unsucceeded,
            'vulnerabilities': len(all_vulnerabilities)
        }
        
    except Exception as e:
        logger.exception(f"[SCAN ERROR] Test ID: {test_id}, Error: {str(e)}")
        if 'log_scan' in locals():
            log_scan.status = 'failed'
            log_scan.timestamp_end = timezone.now()
            log_scan.save()
        return {'success': False, 'error': str(e)}


def perform_multi_tool_scan(ip, output_dir, log_scan_id):
    """
    Perform vulnerability scan on a single IP using multiple tools
    """
    ip_dir = output_dir / f'ip_{ip.replace(".", "_")}'
    ip_dir.mkdir(exist_ok=True)

    results = {
        'success': True,
        'tool_results': {},
        'vulnerabilities': [],
        'services': [],
        'errors': []
    }

    for tool_name, config in SCAN_TOOLS.items():
        if not config['enabled']:
            continue

        logger.debug(f"Running {tool_name} on {ip}...")
        tool_result = run_scan_tool(tool_name, config, ip, ip_dir, log_scan_id)
        
        results['tool_results'][tool_name] = {
            'success': tool_result['success'],
            'output_file': tool_result.get('output_file', ''),
            'execution_time': tool_result.get('execution_time', 0)
        }
        
        if tool_result.get('vulnerabilities'):
            results['vulnerabilities'].extend(tool_result['vulnerabilities'])

        if tool_result['success']:
            if tool_result.get('services'):
                results['services'].extend(tool_result['services'])
        else:
            results['errors'].append(f"{tool_name}: {tool_result.get('error', 'Unknown error')}")
    
    if len(results['errors']) == len([t for t in SCAN_TOOLS.values() if t['enabled']]):
        results['success'] = False
    
    return results


def run_scan_tool(tool_name, config, ip, output_dir, log_scan_id):
    """
    Execute a specific scanning tool
    """
    import time
    start_time = time.time()

    try:
        if tool_name == 'openvas':
            return run_openvas_scan(ip, output_dir, config['timeout'], log_scan_id)

        output_suffix = '.json' if tool_name == 'sslyze' else '.txt'
        output_file = output_dir / f'{tool_name}_scan_log{log_scan_id}{output_suffix}'
        command = [
            part.format(ip=ip, output=str(output_file))
            for part in config['command']
        ]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=config['timeout']
        )
        
        execution_time = time.time() - start_time
        
        if tool_name == 'nikto':
            tool_succeeded = output_file.exists() and output_file.stat().st_size > 0
        else:
            tool_succeeded = result.returncode == 0

        vulnerabilities = parse_tool_output(tool_name, output_file)

        if tool_succeeded:

            return {
                'success': True,
                'output_file': str(output_file),
                'execution_time': execution_time,
                'vulnerabilities': vulnerabilities,
                'services': parse_services(tool_name, output_file) if tool_name == 'nmap' else []
            }
        else:
            return {
                'success': False,
                'error': f"Exit code {result.returncode}",
                'execution_time': execution_time,
                'output_file': str(output_file),
                'vulnerabilities': vulnerabilities
            }
        
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': f'Timeout after {config["timeout"]}s'}
    except FileNotFoundError:
        return {'success': False, 'error': f'{tool_name} not installed'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def run_openvas_scan(ip, output_dir, timeout, log_scan_id):
    """
    Run OpenVAS scan using GVM CLI
    """
    try:
        output_file = output_dir / f'openvas_scan_log{log_scan_id}.xml'
        
        command = [
            'gvm-cli', 'socket', '--xml',
            f'<create_task><name>Scan {ip}</name><target><hosts>{ip}</hosts></target></create_task>'
        ]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            vulns = parse_openvas_output(output_file)
            return {
                'success': True,
                'output_file': str(output_file),
                'vulnerabilities': vulns
            }
        
        return {'success': False, 'error': 'OpenVAS scan failed'}
        
    except FileNotFoundError:
        return {'success': False, 'error': 'OpenVAS/GVM not installed'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def parse_tool_output(tool_name, output_file):
    """
    Parse scan output to extract vulnerabilities
    """
    vulnerabilities = []
    
    if not output_file.exists():
        return vulnerabilities
    
    try:
        with open(output_file, 'r', errors='ignore') as f:
            content = f.read()
        
        if tool_name == 'nmap':
            vuln_pattern = r'(\|.*(?:VULNERABLE|CVE-\d{4}-\d+).*)'
            matches = re.findall(vuln_pattern, content, re.MULTILINE)
            for match in matches:
                vulnerabilities.append(f"[nmap] {match.strip()}")
        
        elif tool_name == 'nikto':
            ignored_prefixes = ('+ Target Host:', '+ Target Port:', '+ Start Time:')
            vuln_lines = [
                line for line in content.split('\n')
                if line.startswith('+ ')
                and not line.startswith(ignored_prefixes)
                and 'Unable to connect' not in line
            ]
            for line in vuln_lines:
                vulnerabilities.append(f"[nikto] {line.strip()}")
        
        elif tool_name == 'nuclei':
            vuln_lines = [line for line in content.split('\n') if line.strip()]
            for line in vuln_lines:
                vulnerabilities.append(f"[nuclei] {line.strip()}")
        
        elif tool_name == 'whatweb':
            if 'vulnerabilities' in content.lower() or 'cve' in content.lower():
                interesting = [line for line in content.split('\n') 
                              if 'CVE' in line or 'vulnerable' in line.lower()]
                for line in interesting:
                    vulnerabilities.append(f"[whatweb] {line.strip()}")
        
        elif tool_name == 'sslyze':
            if output_file.suffix == '.json':
                with open(output_file, 'r') as jf:
                    data = json.load(jf)
                    vulnerabilities.append(f"[sslyze] SSL/TLS scan completed - see {output_file}")
    
    except Exception as e:
        logger.error(f"Error parsing {tool_name} output: {e}")
    
    return vulnerabilities


def parse_services(tool_name, output_file):
    """
    Parse detected services from tool output
    """
    services = []
    
    if tool_name != 'nmap' or not output_file.exists():
        return services
    
    try:
        with open(output_file, 'r', errors='ignore') as f:
            content = f.read()
        
        service_pattern = r'(\d+/tcp)\s+open\s+(\S+)\s*(.*)?'
        matches = re.findall(service_pattern, content)
        
        for match in matches:
            port, service, version = match
            services.append({
                'port': port,
                'service': service,
                'version': version.strip() if version else ''
            })
    
    except Exception as e:
        logger.error(f"Error parsing services: {e}")
    
    return services


def parse_openvas_output(output_file):
    """
    Parse OpenVAS XML output for vulnerabilities
    """
    vulnerabilities = []
    
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        for result in root.findall('.//result'):
            nvt = result.find('.//nvt/name')
            severity = result.find('.//severity')
            
            if nvt is not None and severity is not None:
                vuln_text = f"[openvas] {nvt.text} (Severity: {severity.text})"
                vulnerabilities.append(vuln_text)
    
    except Exception as e:
        logger.error(f"Error parsing OpenVAS output: {e}")
    
    return vulnerabilities


def schedule_retry(log_scan, reason, hours_delay=0, high_priority=False):
    """
    Schedule a retry for a scan
    """
    from backend.models import LogScanRetry
    from datetime import timedelta
    
    scheduled_time = timezone.now() + timedelta(hours=hours_delay)
    
    retry = LogScanRetry.objects.create(
        log_scan=log_scan,
        reason_to_retry=reason,
        scheduled_for=scheduled_time
    )
    
    if hours_delay == 0:
        task = vulnerability_scan_task.apply_async(
            args=[log_scan.test.id],
            priority=9 if high_priority else 5
        )
    else:
        task = vulnerability_scan_task.apply_async(
            args=[log_scan.test.id],
            eta=scheduled_time
        )
    
    retry.celery_task_id = task.id
    retry.save()
    
    logger.info(f"Scheduled retry {retry.id} for {scheduled_time} (reason: {reason})")


def send_ip_change_notification(test, log_scan, live_ips_count):
    """
    Send email notification when IP count changes
    """
    subject = 'Změna IP rozsahu'
    message = f"""Pro sken {test.nickname} s id {test.id} byl nalezen jiný počet živých IP adres {live_ips_count}, id k logu tohoto skenu je {log_scan.id}"""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[NOTIFICATION_EMAIL],
            fail_silently=False,
        )
        logger.info(f"Sent IP change notification for test {test.id}")
    except Exception as e:
        logger.error(f"Failed to send IP change notification: {e}")


def send_scan_failure_notification(test, log_scan, problematic_ips):
    """
    Send email notification when scan fails multiple times
    """
    subject = 'Selhání skenu'
    message = f"""Sken {test.nickname} s id {test.id} nebyl proveden spravne. Problemove IP: {', '.join(problematic_ips)}. Log skenu: {log_scan.id}

Periodické skenování bylo deaktivováno. Sken bude opakován za 8 hodin."""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[NOTIFICATION_EMAIL],
            fail_silently=False,
        )
        logger.info(f"Sent failure notification for test {test.id}")
    except Exception as e:
        logger.error(f"Failed to send failure notification: {e}")


def send_vulnerability_notification(test, log_scan, vulnerabilities, path_to_file):
    """
    Send email notification when vulnerabilities are found
    """
    subject = 'Nalezena zranitelnost'
    vulners_summary = '\n'.join(vulnerabilities[:10])
    if len(vulnerabilities) > 10:
        vulners_summary += f"\n... a dalších {len(vulnerabilities) - 10} zranitelností"
    
    message = f"""Pro sken {test.nickname} s id {test.id} byla nalezena zranitelnost:

{vulners_summary}

Celkem nalezeno: {len(vulnerabilities)} zranitelností
Výpis skenu lze nalézt na {path_to_file} nebo na webove aplikaci."""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[NOTIFICATION_EMAIL],
            fail_silently=False,
        )
        logger.info(f"Sent vulnerability notification for test {test.id}")
    except Exception as e:
        logger.error(f"Failed to send vulnerability notification: {e}")


@shared_task
def send_daily_report():
    """
    Send daily report at 8:00 AM with previous day's scan statistics
    """
    from backend.models import LogScan
    
    logger.info("Generating daily report...")
    
    today = timezone.now().date()
    yesterday_start = timezone.make_aware(datetime.combine(today - timedelta(days=1), datetime.min.time()))
    yesterday_end = timezone.make_aware(datetime.combine(today, datetime.min.time()))
    
    scans = LogScan.objects.filter(
        timestamp_start__gte=yesterday_start,
        timestamp_start__lt=yesterday_end
    )
    
    total_scans = scans.count()
    failed_scans = scans.filter(status='failed').count()
    completed_scans = scans.filter(status='completed').count()
    total_vulns = sum(scan.vulnerabilities for scan in scans)
    
    subject = 'Report'
    message = f"""Počet provedených skenů: {total_scans} z toho neúspěšných {failed_scans}.

Statistiky za {(today - timedelta(days=1)).strftime('%d.%m.%Y')}:
- Celkem skenů: {total_scans}
- Úspěšných: {completed_scans}
- Neúspěšných: {failed_scans}
- Nalezených zranitelností: {total_vulns}
"""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[NOTIFICATION_EMAIL],
            fail_silently=False,
        )
        logger.info(f"Sent daily report: {total_scans} scans, {failed_scans} failed, {total_vulns} vulnerabilities")
    except Exception as e:
        logger.error(f"Failed to send daily report: {e}")
    
    return {'total': total_scans, 'failed': failed_scans, 'vulnerabilities': total_vulns}