from celery import shared_task
from django.utils import timezone
from django.db import transaction
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


logger = logging.getLogger('backend')


SCAN_TOOLS = {
    'nmap': {
        'enabled': True,
        'core': True,
        'timeout': 600,
        'command': ['nmap', '-sV', '-sC', '--script=vuln', '{ip}', '-oN', '{output}'],
    },
    'nikto': {
        'enabled': True,
        'core': False,
        'timeout': 600,
        'command': ['nikto', '-h', '{ip}', '-output', '{output}', '-Format', 'txt'],
    },
    'openvas': {
        'enabled': False,
        'core': False,
        'timeout': 1800,
        'use_gvm': True,
    },
    'nuclei': {
        'enabled': True,
        'core': False,
        'timeout': 300,
        'command': ['nuclei', '-u', 'http://{ip}', '-o', '{output}', '-silent'],
    },
    'whatweb': {
        'enabled': True,
        'core': False,
        'timeout': 60,
        'command': ['whatweb', '{ip}', '-v', '--log-verbose={output}'],
    },
    'sslyze': {
        'enabled': True,
        'core': False,
        'timeout': 120,
        'command': ['sslyze', '--json_out={output}', '{ip}:443'],
    },
}

NOTIFICATION_EMAIL = getattr(settings, 'SCAN_NOTIFICATION_EMAIL', 'admin@example.com')

SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}

ALERT_SEVERITY_THRESHOLD = getattr(settings, 'SCAN_ALERT_SEVERITY_THRESHOLD', 'low')


def cvss_to_severity(score):
    """Map a CVSS base score (0.0-10.0) to a severity band."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 'info'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    if score > 0.0:
        return 'low'
    return 'info'


def meets_threshold(severity, threshold=ALERT_SEVERITY_THRESHOLD):
    """True if `severity` is at or above `threshold`."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(threshold, 0)


def finding_key(finding):
    """
    Stable identity for a finding, used for de-duplication and for diffing
    against a previous scan. Does NOT depend on formatting/whitespace, so
    cosmetic changes no longer produce false "new vulnerability" alerts.
    """
    cve = (finding.get('cve') or '').upper()
    if cve:
        return (finding.get('source', ''), 'cve', cve)
    return (
        finding.get('source', ''),
        finding.get('type', ''),
        (finding.get('title') or finding.get('raw') or '').strip().lower(),
    )


def format_finding(finding):
    """Human-readable one-line rendering of a structured finding (for emails)."""
    sev = finding.get('severity', 'info').upper()
    source = finding.get('source', '?')
    if finding.get('cve'):
        score = finding.get('cvss')
        score_part = f" ({score})" if score is not None else ''
        return f"[{source}] {sev} {finding['cve']}{score_part}"
    title = finding.get('title') or finding.get('raw') or ''
    return f"[{source}] {sev} {title}".rstrip()


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
    Main vulnerability scanning task using multiple Kali Linux tools.
    Performs comprehensive security scan on all live IPs.
    """
    from frontend.models import Test, TestIP
    from frontend.dns_utils import resolve_hostname_ips
    from backend.models import LogScan
    from backend.scheduler import schedule_next_vulnerability_scan, schedule_retry

    logger.info(f"Starting vulnerability scan for test_id: {test_id}")

    try:
        test = Test.objects.get(id=test_id)

        log_scan = LogScan.objects.create(
            test=test,
            status='running',
            timestamp_start=timezone.now(),
        )

        logger.info(f"[SCAN START] Test ID: {test_id}, LogScan ID: {log_scan.id}")

        network = ipaddress.ip_network(f"{test.ip_address}/{test.prefix}", strict=False)
        live_ips = []

        logger.info(f"Discovering live IPs in {test.ip_address}/{test.prefix}...")

        for host_ip in network.hosts():
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(host_ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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

        if not test.ip_current:
            with transaction.atomic():
                locked_test = Test.objects.select_for_update().get(id=test.id)
                test_ip = TestIP.objects.create(ip_address=live_ips)
                locked_test.ip_current = test_ip
                locked_test.last_test = timezone.now()
                locked_test.save(update_fields=['ip_current', 'last_test'])
        else:
            previous_ips = set(test.ip_current.ip_address)
            current_ips = set(live_ips)
            if previous_ips != current_ips:
                tested_ip = TestIP.objects.create(ip_address=live_ips)
                logger.warning(f"IP change detected for test {test.id}")

                send_ip_change_notification(test, log_scan, tested_ip)
            Test.objects.filter(id=test.id).update(last_test=timezone.now())
            test.last_test = timezone.now()

        succeeded = 0
        unsucceeded = 0
        problematic_ips = []
        all_findings = []

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
            'tools_used': [tool for tool, cfg in SCAN_TOOLS.items() if cfg['enabled']],
            'results': [],
        }

        for ip in live_ips:
            logger.info(f"Scanning {ip} with multiple tools...")
            scan_result = perform_multi_tool_scan(ip, output_dir, log_scan.id)

            all_findings.extend(scan_result.get('findings', []))

            ip_entry = {
                'ip': ip,
                'status': 'success' if scan_result['success'] else 'failed',
                'tool_results': scan_result.get('tool_results', {}),
                'findings': scan_result.get('findings', []),
                'services': scan_result.get('services', []),
            }
            if not scan_result['success']:
                ip_entry['error'] = scan_result.get('error', 'core tool(s) did not complete')

            comprehensive_output['results'].append(ip_entry)

            if scan_result['success']:
                succeeded += 1
            else:
                unsucceeded += 1
                problematic_ips.append(ip)

        deduped = {}
        for f in all_findings:
            deduped.setdefault(finding_key(f), f)
        unique_findings = sorted(
            deduped.values(),
            key=lambda f: (-SEVERITY_RANK.get(f.get('severity', 'info'), 0),
                           f.get('source', '')),
        )

        alertable_findings = [f for f in unique_findings
                              if meets_threshold(f.get('severity', 'info'))]

        comprehensive_output['summary'] = {
            'total_findings': len(unique_findings),
            'alertable_findings': len(alertable_findings),
            'by_severity': {
                sev: sum(1 for f in unique_findings if f.get('severity') == sev)
                for sev in SEVERITY_ORDER
            },
        }

        output_file = output_dir / f'comprehensive_scan_log{log_scan.id}.json'
        with open(output_file, 'w') as f:
            json.dump(comprehensive_output, f, indent=2)

        log_scan.succeeded = succeeded
        log_scan.unsucceeded = unsucceeded
        log_scan.problematic_ips = problematic_ips
        log_scan.vulnerabilities = len(alertable_findings)
        log_scan.vulners = unique_findings
        log_scan.path_to_file = str(output_file)
        log_scan.timestamp_end = timezone.now()

        consecutive_count = 0
        if unsucceeded > 0:
            previous_logs = LogScan.objects.filter(
                test=test,
                timestamp_start__lt=log_scan.timestamp_start,
                status__in=['completed', 'failed'],
            ).order_by('-timestamp_start')

            for prev_log in previous_logs:
                if prev_log.unsucceeded > 0:
                    consecutive_count += 1
                else:
                    break

            log_scan.consecutive_failures = consecutive_count + 1
            log_scan.status = 'failed' if consecutive_count >= 2 else 'completed'
        else:
            log_scan.status = 'completed'
            log_scan.consecutive_failures = 0

        log_scan.save()

        test.refresh_from_db(fields=['cron_is_active'])
        if test.cron_is_active:
            if unsucceeded > 0:
                if consecutive_count >= 2:
                    logger.error(f"Test {test.id} failed 3 times consecutively. Applying 8-hour delay.")
                    schedule_retry(test, log_scan, reason=3, hours_delay=8)
                    send_scan_failure_notification(test, log_scan, problematic_ips)
                else:
                    logger.warning(f"Test {test.id} had partial failure. Scheduling immediate retry.")
                    schedule_retry(test, log_scan, reason=2, hours_delay=0, high_priority=True)
            else:
                schedule_next_vulnerability_scan(test)

        alert_findings = alertable_findings
        if test.new_vulnerability_alerts_enabled:
            previous_findings = []
            if test.new_vulnerability_alerts_log_scan_id:
                previous_scan = LogScan.objects.filter(
                    id=test.new_vulnerability_alerts_log_scan_id,
                    test=test,
                ).first()
                if previous_scan:
                    previous_findings = previous_scan.vulners or []
                else:
                    logger.warning(
                        f"Previous LogScan ID {test.new_vulnerability_alerts_log_scan_id} "
                        f"not found for test {test.id}. Setting to {log_scan.id}."
                    )
                    test.new_vulnerability_alerts_log_scan_id = log_scan.id
                    test.new_vulnerability_alerts_since = timezone.now()
                    test.save(update_fields=[
                        'new_vulnerability_alerts_log_scan_id',
                        'new_vulnerability_alerts_since',
                    ])

            if previous_findings:
                previous_keys = {finding_key(f) for f in previous_findings
                                 if isinstance(f, dict)}
                alert_findings = [f for f in alertable_findings
                                  if finding_key(f) not in previous_keys]

        if alert_findings:
            send_vulnerability_notification(test, log_scan, alert_findings, str(output_file))

        logger.info(f"[SCAN COMPLETE] LogScan ID: {log_scan.id}, Status: {log_scan.status}")
        logger.info(
            f"Results: {succeeded} succeeded, {unsucceeded} failed, "
            f"{len(alertable_findings)} vulnerabilities "
            f"({len(unique_findings)} findings incl. informational)"
        )

        return {
            'success': True,
            'log_scan_id': log_scan.id,
            'succeeded': succeeded,
            'unsucceeded': unsucceeded,
            'vulnerabilities': len(alertable_findings),
            'total_findings': len(unique_findings),
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
    Perform a vulnerability scan on a single IP using multiple tools.

    IP-level success is determined by the *core* tools completing, not by
    "at least one tool didn't crash". If no core tools are enabled, success
    falls back to "at least one enabled tool completed".
    """
    ip_dir = output_dir / f'ip_{ip.replace(".", "_")}'
    ip_dir.mkdir(exist_ok=True)

    results = {
        'success': False,
        'tool_results': {},
        'findings': [],
        'services': [],
        'errors': [],
    }

    enabled = {name: cfg for name, cfg in SCAN_TOOLS.items() if cfg['enabled']}
    core_tools = [name for name, cfg in enabled.items() if cfg.get('core')]

    core_completed = 0
    any_completed = 0

    for tool_name, config in enabled.items():
        logger.debug(f"Running {tool_name} on {ip}...")
        tool_result = run_scan_tool(tool_name, config, ip, ip_dir, log_scan_id)

        results['tool_results'][tool_name] = {
            'status': tool_result.get('status', 'error'),
            'success': tool_result['success'],
            'output_file': tool_result.get('output_file', ''),
            'execution_time': round(tool_result.get('execution_time', 0), 2),
            'finding_count': len(tool_result.get('findings', [])),
        }
        if not tool_result['success']:
            results['tool_results'][tool_name]['error'] = tool_result.get('error', '')

        if tool_result.get('findings'):
            results['findings'].extend(tool_result['findings'])
        if tool_result.get('services'):
            results['services'].extend(tool_result['services'])

        if tool_result['success']:
            any_completed += 1
            if config.get('core'):
                core_completed += 1
        else:
            results['errors'].append(f"{tool_name}: {tool_result.get('error', 'Unknown error')}")

    if core_tools:
        results['success'] = core_completed == len(core_tools)
    else:
        results['success'] = any_completed > 0

    if not results['success']:
        results['error'] = '; '.join(results['errors']) or 'core tool(s) did not complete'

    return results


def run_scan_tool(tool_name, config, ip, output_dir, log_scan_id):
    """
    Execute a specific scanning tool.

    Parsing of the output file happens on EVERY return path (including
    timeout), so partial results written before a kill are never discarded.
    `status` distinguishes completed / timeout / not_installed / error.
    """
    import time
    start_time = time.time()

    if tool_name == 'openvas':
        return run_openvas_scan(ip, output_dir, config['timeout'], log_scan_id)

    output_suffix = '.json' if tool_name == 'sslyze' else '.txt'
    output_file = output_dir / f'{tool_name}_scan_log{log_scan_id}{output_suffix}'
    command = [part.format(ip=ip, output=str(output_file)) for part in config['command']]

    def parsed():
        """Parse whatever is on disk right now (may be empty)."""
        return parse_tool_output(tool_name, output_file)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=config['timeout'],
        )
        execution_time = time.time() - start_time

        if tool_name == 'nikto':
            tool_succeeded = output_file.exists() and output_file.stat().st_size > 0
        else:
            tool_succeeded = result.returncode == 0

        findings = parsed()
        services = parse_services(tool_name, output_file) if tool_name == 'nmap' else []

        if tool_succeeded:
            return {
                'success': True,
                'status': 'completed',
                'output_file': str(output_file),
                'execution_time': execution_time,
                'findings': findings,
                'services': services,
            }
        return {
            'success': False,
            'status': 'error',
            'error': f"Exit code {result.returncode}",
            'execution_time': execution_time,
            'output_file': str(output_file),
            'findings': findings,
            'services': services,
        }

    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        findings = parsed()
        services = parse_services(tool_name, output_file) if tool_name == 'nmap' else []
        return {
            'success': False,
            'status': 'timeout',
            'error': f'Timeout after {config["timeout"]}s',
            'execution_time': execution_time,
            'output_file': str(output_file) if output_file.exists() else '',
            'findings': findings,
            'services': services,
        }
    except FileNotFoundError:
        return {
            'success': False,
            'status': 'not_installed',
            'error': f'{tool_name} not installed',
            'findings': [],
            'services': [],
        }
    except Exception as e:
        findings = parsed() if output_file.exists() else []
        return {
            'success': False,
            'status': 'error',
            'error': str(e),
            'output_file': str(output_file) if output_file.exists() else '',
            'findings': findings,
            'services': [],
        }


def run_openvas_scan(ip, output_dir, timeout, log_scan_id):
    """Run OpenVAS scan using GVM CLI."""
    try:
        output_file = output_dir / f'openvas_scan_log{log_scan_id}.xml'

        command = [
            'gvm-cli', 'socket', '--xml',
            f'<create_task><name>Scan {ip}</name><target><hosts>{ip}</hosts></target></create_task>',
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode == 0:
            with open(output_file, 'w') as f:
                f.write(result.stdout)

            findings = parse_openvas_output(output_file)
            return {
                'success': True,
                'status': 'completed',
                'output_file': str(output_file),
                'findings': findings,
            }

        return {'success': False, 'status': 'error', 'error': 'OpenVAS scan failed', 'findings': []}

    except FileNotFoundError:
        return {'success': False, 'status': 'not_installed',
                'error': 'OpenVAS/GVM not installed', 'findings': []}
    except Exception as e:
        return {'success': False, 'status': 'error', 'error': str(e), 'findings': []}



def _finding(source, title, severity='info', type='info', cve=None, cvss=None, raw=None):
    return {
        'source': source,
        'type': type,
        'severity': severity,
        'cve': cve,
        'cvss': cvss,
        'title': title.strip() if title else '',
        'raw': (raw if raw is not None else title or '').strip(),
    }


_NMAP_CVE_RE = re.compile(r'(CVE-\d{4}-\d+)\s+(\d+(?:\.\d+)?)')
_NUCLEI_RE = re.compile(r'\[([a-z]+)\]\s*$|\]\s*\[(critical|high|medium|low|info)\]\s')


def parse_tool_output(tool_name, output_file):
    """Parse a tool's output file into structured findings."""
    findings = []

    if not output_file.exists():
        return findings

    try:
        with open(output_file, 'r', errors='ignore') as f:
            content = f.read()

        if tool_name == 'nmap':
            for line in content.splitlines():
                if 'NOT VULNERABLE' in line:
                    continue
                m = _NMAP_CVE_RE.search(line)
                if m:
                    cve, score = m.group(1), m.group(2)
                    findings.append(_finding(
                        'nmap', title=cve, type='cve', cve=cve, cvss=float(score),
                        severity=cvss_to_severity(score), raw=line.strip(),
                    ))
                elif 'VULNERABLE' in line and 'NOT VULNERABLE' not in line:
                    findings.append(_finding(
                        'nmap', title=line.strip().lstrip('| _').strip(),
                        type='config', severity='medium', raw=line.strip(),
                    ))

        elif tool_name == 'nikto':
            ignored_prefixes = ('+ Target Host:', '+ Target Port:', '+ Start Time:')
            for line in content.splitlines():
                if not line.startswith('+ '):
                    continue
                if line.startswith(ignored_prefixes) or 'Unable to connect' in line:
                    continue
                text = line[2:].strip()
                low = text.lower()
                if 'outdated' in low or 'cve-' in low:
                    sev = 'medium'
                    type_ = 'config'
                elif 'directory indexing' in low or 'brute force' in low:
                    sev = 'low'
                    type_ = 'config'
                elif 'security header' in low or 'header is' in low or 'header is not set' in low:
                    sev = 'low'
                    type_ = 'header'
                else:
                    sev = 'info'
                    type_ = 'info'
                cve_m = re.search(r'(CVE-\d{4}-\d+)', text, re.IGNORECASE)
                findings.append(_finding(
                    'nikto', title=text, type=type_, severity=sev,
                    cve=cve_m.group(1).upper() if cve_m else None, raw=line.strip(),
                ))

        elif tool_name == 'nuclei':
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                sev_m = re.search(r'\]\s*\[(critical|high|medium|low|info|unknown)\]', line)
                severity = sev_m.group(1) if sev_m else 'info'
                if severity == 'unknown':
                    severity = 'info'
                cve_m = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                findings.append(_finding(
                    'nuclei', title=line, type='cve' if cve_m else 'info',
                    severity=severity,
                    cve=cve_m.group(1).upper() if cve_m else None, raw=line,
                ))

        elif tool_name == 'whatweb':
            m = re.search(r'Summary\s*:\s*(.+)', content)
            if m:
                findings.append(_finding(
                    'whatweb', title=f"Fingerprint: {m.group(1).strip()}",
                    type='service', severity='info', raw=m.group(0).strip(),
                ))
            for line in content.splitlines():
                if 'CVE-' in line.upper() or 'vulnerable' in line.lower():
                    cve_m = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                    findings.append(_finding(
                        'whatweb', title=line.strip(), type='cve' if cve_m else 'config',
                        severity='medium',
                        cve=cve_m.group(1).upper() if cve_m else None, raw=line.strip(),
                    ))

        elif tool_name == 'sslyze':
            if output_file.suffix == '.json':
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    data = None
                if data is not None:
                    findings.extend(parse_sslyze_results(data))

    except Exception as e:
        logger.error(f"Error parsing {tool_name} output: {e}")

    return findings


def parse_sslyze_results(data):
    """
    Turn an sslyze JSON report into structured findings.

    A host with no TLS service (connectivity ERROR / ERROR_NO_CONNECTIVITY) is
    NOT an error here — sslyze ran fine, the host just doesn't speak TLS on 443.
    That produces no findings (and no noise). When a host does answer, weak
    protocols, weak ciphers and certificate problems are surfaced.
    """
    findings = []

    weak_protocols = {
        'ssl_2_0_cipher_suites': ('SSLv2 enabled', 'critical'),
        'ssl_3_0_cipher_suites': ('SSLv3 enabled (POODLE)', 'high'),
        'tls_1_0_cipher_suites': ('TLS 1.0 enabled (deprecated)', 'medium'),
        'tls_1_1_cipher_suites': ('TLS 1.1 enabled (deprecated)', 'medium'),
    }

    for server in data.get('server_scan_results', []):
        loc = server.get('server_location', {}) or {}
        host = loc.get('hostname') or loc.get('ip_address') or '?'

        status = server.get('scan_status') or server.get('connectivity_status')
        if status in ('ERROR_NO_CONNECTIVITY', 'ERROR') or not server.get('scan_result'):
            continue

        scan_result = server.get('scan_result', {}) or {}

        for key, (title, sev) in weak_protocols.items():
            node = scan_result.get(key, {}) or {}
            res = node.get('result', {}) if isinstance(node, dict) else {}
            accepted = res.get('accepted_cipher_suites') if isinstance(res, dict) else None
            if accepted:
                findings.append(_finding(
                    'sslyze', title=f"{host}: {title}", type='tls', severity=sev,
                    raw=f"{host} {key}",
                ))

        cert_node = (scan_result.get('certificate_info', {}) or {}).get('result', {}) or {}
        for deployment in cert_node.get('certificate_deployments', []) or []:
            for validation in deployment.get('path_validation_results', []) or []:
                if validation.get('was_validation_successful') is False:
                    store = (validation.get('trust_store') or {}).get('name', 'trust store')
                    findings.append(_finding(
                        'sslyze', title=f"{host}: certificate failed validation ({store})",
                        type='tls', severity='medium', raw=f"{host} cert validation",
                    ))
                    break

        vuln_checks = {
            'heartbleed': ('Heartbleed (CVE-2014-0160)', 'critical', 'is_vulnerable_to_heartbleed'),
            'openssl_ccs_injection': ('CCS injection (CVE-2014-0224)', 'high', 'is_vulnerable_to_ccs_injection'),
            'robot': ('ROBOT attack', 'high', 'robot_result'),
        }
        for key, (title, sev, flag) in vuln_checks.items():
            node = (scan_result.get(key, {}) or {}).get('result', {}) or {}
            val = node.get(flag)
            is_vuln = val is True or (isinstance(val, str) and 'VULNERABLE' in val.upper()
                                      and 'NOT' not in val.upper())
            if is_vuln:
                findings.append(_finding(
                    'sslyze', title=f"{host}: {title}", type='tls', severity=sev,
                    raw=f"{host} {key}",
                ))

    return findings


def parse_services(tool_name, output_file):
    """Parse detected services from nmap output (open ports only)."""
    services = []

    if tool_name != 'nmap' or not output_file.exists():
        return services

    try:
        with open(output_file, 'r', errors='ignore') as f:
            content = f.read()

        service_pattern = re.compile(
            r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$', re.MULTILINE
        )
        for port, proto, service, version in service_pattern.findall(content):
            services.append({
                'port': f'{port}/{proto}',
                'service': service,
                'version': version.strip(),
            })

    except Exception as e:
        logger.error(f"Error parsing services: {e}")

    return services


def parse_openvas_output(output_file):
    """Parse OpenVAS XML output for vulnerabilities."""
    findings = []

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(output_file)
        root = tree.getroot()

        for result in root.findall('.//result'):
            nvt = result.find('.//nvt/name')
            severity = result.find('.//severity')

            if nvt is not None:
                score = severity.text if severity is not None else None
                findings.append(_finding(
                    'openvas', title=nvt.text or '', type='cve',
                    severity=cvss_to_severity(score), cvss=_safe_float(score),
                    raw=f"{nvt.text} (Severity: {score})",
                ))

    except Exception as e:
        logger.error(f"Error parsing OpenVAS output: {e}")

    return findings


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None



def send_ip_change_notification(test, log_scan, test_ip):
    """Send email notification when the set of live IPs changes."""
    subject = 'Změna IP rozsahu'
    message = (
        f"Pro sken {test.nickname} s id {test.id} byla nalezena změna živých IP adres. "
        f"ID adres: {test_ip.id}. ID k logu tohoto skenu je {log_scan.id}"
    )

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
    """Send email notification when a scan fails multiple times."""
    subject = 'Selhání skenu'
    message = (
        f"Sken {test.nickname} s id {test.id} nebyl proveden správně. "
        f"Problémové IP: {', '.join(problematic_ips)}. Log skenu: {log_scan.id}\n\n"
        f"Periodické skenování bylo deaktivováno. Sken bude opakován za 8 hodin."
    )

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


def send_vulnerability_notification(test, log_scan, findings, path_to_file):
    """Send email notification when vulnerabilities are found."""
    subject = 'Nalezena zranitelnost'

    lines = [format_finding(f) for f in findings[:10]]
    vulners_summary = '\n'.join(lines)
    if len(findings) > 10:
        vulners_summary += f"\n... a dalších {len(findings) - 10} zranitelností"

    counts = {}
    for f in findings:
        sev = f.get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1
    breakdown = ', '.join(
        f"{sev}: {counts[sev]}" for sev in reversed(SEVERITY_ORDER) if counts.get(sev)
    )

    message = (
        f"Pro sken {test.nickname} s id {test.id} byla nalezena zranitelnost:\n\n"
        f"{vulners_summary}\n\n"
        f"Celkem nalezeno: {len(findings)} zranitelností ({breakdown})\n"
        f"Výpis skenu lze nalézt na {path_to_file} nebo na webové aplikaci."
    )

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
    """Send daily report at 8:00 AM with the previous day's scan statistics."""
    from backend.models import LogScan

    logger.info("Generating daily report...")

    today = timezone.now().date()
    yesterday_start = timezone.make_aware(datetime.combine(today - timedelta(days=1), datetime.min.time()))
    yesterday_end = timezone.make_aware(datetime.combine(today, datetime.min.time()))

    scans = LogScan.objects.filter(
        timestamp_start__gte=yesterday_start,
        timestamp_start__lt=yesterday_end,
    )

    total_scans = scans.count()
    failed_scans = scans.filter(status='failed').count()
    completed_scans = scans.filter(status='completed').count()
    total_vulns = sum(scan.vulnerabilities for scan in scans)

    subject = 'Report'
    message = (
        f"Počet provedených skenů: {total_scans} z toho neúspěšných {failed_scans}.\n\n"
        f"Statistiky za {(today - timedelta(days=1)).strftime('%d.%m.%Y')}:\n"
        f"- Celkem skenů: {total_scans}\n"
        f"- Úspěšných: {completed_scans}\n"
        f"- Neúspěšných: {failed_scans}\n"
        f"- Nalezených zranitelností: {total_vulns}\n"
    )

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


@shared_task
def cleanup_old_scans(days=90):
    from backend.models import LogScan
    from datetime import timedelta
    import shutil
    from pathlib import Path
    from zipfile import ZIP_DEFLATED, ZipFile

    logger.info(f"Starting archival of scans older than {days} days...")

    cutoff_date = timezone.now() - timedelta(days=days)
    old_scans = list(
        LogScan.objects.filter(timestamp_start__lt=cutoff_date).only(
            'id', 'timestamp_start', 'path_to_file'
        )
    )
    archive_root = Path(settings.BASE_DIR) / 'scan_archives'
    archive_root.mkdir(parents=True, exist_ok=True)
    archived_scan_ids = []
    archived_directories = set()

    for scan in old_scans:
        if not scan.path_to_file:
            archived_scan_ids.append(scan.id)
            continue

        file_path = Path(scan.path_to_file)
        log_dir = file_path.parent
        if not log_dir.exists():
            archived_scan_ids.append(scan.id)
            continue
        if log_dir in archived_directories:
            archived_scan_ids.append(scan.id)
            continue

        quarter = ((scan.timestamp_start.month - 1) // 3) + 1
        archive_path = archive_root / f'{scan.timestamp_start.year}-Q{quarter}.zip'
        try:
            with ZipFile(archive_path, mode='a', compression=ZIP_DEFLATED) as archive:
                existing_names = set(archive.namelist())
                for output_file in log_dir.rglob('*'):
                    if output_file.is_file():
                        archive_name = output_file.relative_to(settings.BASE_DIR).as_posix()
                        if archive_name not in existing_names:
                            archive.write(output_file, archive_name)
            shutil.rmtree(log_dir)
            archived_directories.add(log_dir)
            archived_scan_ids.append(scan.id)
            logger.info(f"Archived scan outputs from {log_dir} to {archive_path}")
        except Exception as error:
            logger.error(f"Error archiving scan directory {log_dir}: {error}")

    deleted = LogScan.objects.filter(id__in=archived_scan_ids).delete()[0]

    logger.info(f"Archived outputs and deleted {deleted} old scan logs")
    return {'deleted': deleted, 'archives': str(archive_root)}
