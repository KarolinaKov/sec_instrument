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


logger = logging.getLogger('backend')


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
        # exits non-zero when a server is non-compliant
        'command': [
            'sslyze',
            '--sslv2', '--sslv3', '--tlsv1', '--tlsv1_1', '--tlsv1_2', '--tlsv1_3',
            '--heartbleed', '--openssl_ccs', '--robot', '--reneg', '--compression',
            '--fallback', '--elliptic_curves', '--ems', '--certinfo', '--resum',
            '--quiet', '--json_out={output}', '{ip}'
        ]
    },
}

NOTIFICATION_EMAIL = getattr(settings, 'SCAN_NOTIFICATION_EMAIL', 'admin@example.com')

SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'UNKNOWN': 5}
_SEV_IN_STR = re.compile(r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)\]')

WEAK_CIPHER_TOKENS = ('RC4', '3DES', '_DES_', 'NULL', 'EXPORT', '_MD5', 'ANON', 'IDEA', 'SEED', 'CBC_SHA')


def _severity_from_cvss(score):
    """Map a CVSS numeric score to a severity bucket."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 'UNKNOWN'
    if s >= 9.0:
        return 'CRITICAL'
    if s >= 7.0:
        return 'HIGH'
    if s >= 4.0:
        return 'MEDIUM'
    if s > 0.0:
        return 'LOW'
    return 'INFO'


def _sort_findings(findings):
    """Sort finding strings worst-first by the [SEVERITY] tag they carry."""
    def key(s):
        m = _SEV_IN_STR.search(s)
        return SEVERITY_RANK.get(m.group(1) if m else 'UNKNOWN', 9)
    return sorted(findings, key=key)


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
    from backend.models import LogScan
    from backend.scheduler import schedule_next_vulnerability_scan, schedule_retry

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
            Test.objects.filter(id=test.id).update(
            last_test = timezone.now())
            test.last_test = timezone.now()

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

        # Keep the overall list worst-first so summaries/alerts lead with the
        # most severe findings.
        all_vulnerabilities = _sort_findings(all_vulnerabilities)

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
                timestamp_start__lt=log_scan.timestamp_start,
                status__in=['completed', 'failed'],
            ).order_by('-timestamp_start')

            consecutive_count = 0
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
                    logger.error(f"Test {test.id} failed 3 times consecutively. Aplying 8-hour delay.")
                    schedule_retry(test, log_scan, reason=3, hours_delay=8)
                    send_scan_failure_notification(test, log_scan, problematic_ips)
                else:
                    logger.warning(f"Test {test.id} had partial failure. Scheduling immediate retry.")
                    schedule_retry(test, log_scan, reason=2, hours_delay=0, high_priority=True)
            else:
                schedule_next_vulnerability_scan(test)

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

            alert_vulnerabilities = _sort_findings(
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

    results['vulnerabilities'] = _sort_findings(results['vulnerabilities'])

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
        if tool_name == 'openvas': #UNUSED
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

        # nikto and sslyze both return a non-zero exit code on good
        # runs (nikto when it finds issues, sslyze when the target is not
        # compliant with the Mozilla TLS config), so for these two success is
        # defined by the output file being produced with content.
        if tool_name in ('nikto', 'sslyze'):
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
            error_detail = f"Exit code {result.returncode}"
            if result.stderr:
                error_detail += f": {result.stderr.strip()[:200]}"
            return {
                'success': False,
                'error': error_detail,
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


def run_openvas_scan(ip, output_dir, timeout, log_scan_id): #UNUSED
    """
    UNUSED - Run OpenVAS scan using GVM CLI
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
    Every finding is returned as a single string tagged with the source tool
    and severity:
        "[nmap][CRITICAL] CVE-2017-14493 CVSS 9.8 — dnsmasq 2.51 (53/tcp) <url>"
        "[nmap][HIGH][EXPLOIT] EDB-ID:42946 CVSS 7.8 — dnsmasq 2.51 (53/tcp) <url>"
        "[nuclei][MEDIUM] CVE-2023-48795 — 1.2.3.4:22 Vulnerable to Terrapin"
        "[sslyze][CRITICAL] Vulnerable to Heartbleed (CVE-2014-0160) — host:443"
    Strings stay hashable/joinable so the existing new-vulnerability diffing
    and e-mail summaries keep working.
    """
    vulnerabilities = []

    if not output_file.exists():
        return vulnerabilities

    try:
        if tool_name == 'sslyze':
            return _parse_sslyze_output(output_file)

        with open(output_file, 'r', errors='ignore') as f:
            content = f.read()

        if tool_name == 'nmap':
            vulnerabilities = _parse_nmap_output(content)
        elif tool_name == 'nikto':
            vulnerabilities = _parse_nikto_output(content)
        elif tool_name == 'nuclei':
            vulnerabilities = _parse_nuclei_output(content)
        elif tool_name == 'whatweb':
            vulnerabilities = _parse_whatweb_output(content)

    except Exception as e:
        logger.error(f"Error parsing {tool_name} output: {e}")

    return _sort_findings(vulnerabilities)

_NMAP_PORT_RE = re.compile(r'^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)$')
_NMAP_CPE_RE = re.compile(r'cpe:/[aoh]:([^\s:]+(?::[^\s:]+)*)')
_NMAP_VULNERS_RE = re.compile(
    r'^[|_\s]*([A-Za-z0-9][\w:.\-]+)\s+(\d+\.\d+)\s+(https?://\S+)(\s+\*EXPLOIT\*)?\s*$'
)
_NMAP_EXPLOIT_ID_RE = re.compile(r'^(EDB-ID|EXPLOITPACK|SSV|PACKETSTORM|MSF|1337DAY)', re.I)

def _parse_nmap_output(content):
    findings = []
    seen = set()
    current_port = ''
    current_service = ''
    current_product = ''

    def add(entry):
        if entry not in seen:
            seen.add(entry)
            findings.append(entry)

    for raw in content.split('\n'):
        line = raw.rstrip()
        stripped = line.strip()

        port_m = _NMAP_PORT_RE.match(stripped)
        if port_m:
            current_port = port_m.group(1)
            current_service = port_m.group(2)
            current_product = port_m.group(3).strip()
            continue

        cpe_m = _NMAP_CPE_RE.search(line)
        if cpe_m and 'vulners' not in line.lower():
            current_product = cpe_m.group(1).replace(':', ' ')

        upper = line.upper()
        if 'NOT VULNERABLE' in upper:
            continue

        vm = _NMAP_VULNERS_RE.match(line)
        if vm:
            vid, score, url, exploit_flag = vm.group(1), vm.group(2), vm.group(3), bool(vm.group(4))
            sev = _severity_from_cvss(score)
            is_cve = vid.upper().startswith('CVE-')
            is_exploit = exploit_flag or bool(_NMAP_EXPLOIT_ID_RE.match(vid)) or ('exploit' in url.lower())
            tag = f"[nmap][{sev}]" + ("[EXPLOIT]" if is_exploit else "")
            ctx = (current_product or current_service or '').strip()
            where = f" ({current_port})" if current_port else ""
            add(f"{tag} {vid} CVSS {score} — {ctx}{where} {url}".strip())
            continue

        if 'VULNERABLE' in upper:
            text = line.lstrip('|_ ').strip()
            if text and not text.upper().startswith('CPE:'):
                where = f" ({current_port})" if current_port else ""
                add(f"[nmap][HIGH] {text}{where}")

    return findings

def _parse_nikto_output(content):
    findings = []
    seen = set()
    ignored_prefixes = ('+ Target Host:', '+ Target Port:', '+ Target IP:',
                        '+ Start Time:', '+ End Time:', '+ Server:')
    for line in content.split('\n'):
        if not line.startswith('+ '):
            continue
        if line.startswith(ignored_prefixes):
            continue
        if 'Unable to connect' in line or 'host(s) tested' in line:
            continue
        text = line[2:].strip()
        if not text:
            continue
        sev = 'MEDIUM' if ('CVE-' in text.upper() or 'OSVDB' in text.upper()) else 'LOW'
        entry = f"[nikto][{sev}] {text}"
        if entry not in seen:
            seen.add(entry)
            findings.append(entry)
    return findings

_NUCLEI_ROW_RE = re.compile(r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)$')
_NUCLEI_SEV = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
               'low': 'LOW', 'info': 'INFO', 'unknown': 'UNKNOWN'}
_NUCLEI_INFO_KEEP_RE = re.compile(
    r'(missing-security-headers|security-headers|'
    r'exposure|exposed|disclosure|default-login|default-cred|'
    r'takeover|backup|directory-listing|'
    r'cve-\d{4}|xss|sqli|rce|lfi|ssrf|traversal|open-redirect|injection)',
    re.I
)
_NUCLEI_INFO_DROP_RE = re.compile(
    r'(tech-detect|waf-detect|-detect$|fingerprint|'
    r'ssh-auth-methods|ssh-password-auth|ssh-server-enumeration|'
    r'options-method|form-detection|ptr-fingerprint|http-trace|favicon)',
    re.I
)

def _parse_nuclei_output(content):
    """
    Normalise nuclei findings into tagged, deduplicated strings.
    """
    findings = []
    seen = set()
    for raw in content.split('\n'):
        line = raw.strip()
        if not line:
            continue
        m = _NUCLEI_ROW_RE.match(line)
        if not m:
            continue
        template, _proto, sev_raw, target, extra = m.groups()
        sev = _NUCLEI_SEV.get(sev_raw.lower(), 'UNKNOWN')
        extra_clean = re.sub(r'[\[\]"\\]', ' ', extra or '')
        extra_clean = ' '.join(extra_clean.split())[:120]

        if sev in ('INFO', 'UNKNOWN'):
            haystack = f"{template} {extra_clean}"
            keep = (bool(_NUCLEI_INFO_KEEP_RE.search(haystack))
                    and not _NUCLEI_INFO_DROP_RE.search(template))
            if not keep:
                continue
            sev = 'INFO'

        entry = f"[nuclei][{sev}] {template} — {target}"
        if extra_clean:
            entry += f" {extra_clean}"
        if entry not in seen:
            seen.add(entry)
            findings.append(entry)
    return findings

def _parse_whatweb_output(content):
    findings = []
    seen = set()
    for line in content.split('\n'):
        upper = line.upper()
        if 'CVE-' in upper or 'VULNERABLE' in upper:
            if 'NOT VULNERABLE' in upper:
                continue
            text = line.strip()
            sev = 'MEDIUM' if 'CVE-' in upper else 'LOW'
            entry = f"[whatweb][{sev}] {text}"
            if entry not in seen:
                seen.add(entry)
                findings.append(entry)
    return findings

def _parse_sslyze_output(output_file):
    findings = []
    seen = set()

    def add(entry):
        if entry not in seen:
            seen.add(entry)
            findings.append(entry)

    try:
        with open(output_file, 'r', errors='ignore') as jf:
            data = json.load(jf)
    except Exception as e:
        logger.error(f"Error parsing sslyze output: {e}")
        return [f"[sslyze][UNKNOWN] could not parse JSON output: {e}"]

    for server in data.get('server_scan_results', []):
        loc = server.get('server_location', {}) or {}
        host = loc.get('hostname') or loc.get('ip_address') or '?'
        port = loc.get('port') or 443
        where = f"{host}:{port}"

        scan = server.get('scan_result') or {}
        if not scan:
            status = server.get('connectivity_status') or server.get('scan_status') or 'UNKNOWN'
            add(f"[sslyze][UNKNOWN] TLS scan did not complete ({status}) — {where}")
            continue

        def result_of(cmd):
            node = scan.get(cmd) or {}
            if node.get('status') == 'COMPLETED':
                return node.get('result') or {}
            return None
        deprecated = {
            'ssl_2_0_cipher_suites': ('SSL 2.0', 'CRITICAL'),
            'ssl_3_0_cipher_suites': ('SSL 3.0 (POODLE)', 'HIGH'),
            'tls_1_0_cipher_suites': ('TLS 1.0 (deprecated)', 'MEDIUM'),
            'tls_1_1_cipher_suites': ('TLS 1.1 (deprecated)', 'MEDIUM'),
        }
        for cmd, (label, sev) in deprecated.items():
            r = result_of(cmd)
            if r and (r.get('is_tls_version_supported') or r.get('accepted_cipher_suites')):
                add(f"[sslyze][{sev}] {label} supported — {where}")

        weak = set()
        for cmd in ('ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                    'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites'):
            r = result_of(cmd)
            if not r:
                continue
            for acc in (r.get('accepted_cipher_suites') or []):
                name = ((acc.get('cipher_suite') or {}).get('name')) or ''
                if any(tok in name.upper() for tok in WEAK_CIPHER_TOKENS):
                    weak.add(name)
        for name in sorted(weak):
            add(f"[sslyze][MEDIUM] Weak cipher suite accepted: {name} — {where}")

        r = result_of('heartbleed')
        if r and r.get('is_vulnerable_to_heartbleed'):
            add(f"[sslyze][CRITICAL] Vulnerable to Heartbleed (CVE-2014-0160) — {where}")

        r = result_of('openssl_ccs_injection')
        if r and r.get('is_vulnerable_to_ccs_injection'):
            add(f"[sslyze][HIGH] Vulnerable to OpenSSL CCS Injection (CVE-2014-0224) — {where}")

        r = result_of('robot')
        if r and str(r.get('robot_result', '')).startswith('VULNERABLE'):
            add(f"[sslyze][HIGH] Vulnerable to ROBOT attack ({r.get('robot_result')}) — {where}")

        r = result_of('tls_compression')
        if r and r.get('supports_compression'):
            add(f"[sslyze][MEDIUM] TLS compression enabled (CRIME) — {where}")

        r = result_of('session_renegotiation')
        if r:
            if r.get('is_vulnerable_to_client_renegotiation_dos'):
                add(f"[sslyze][MEDIUM] Vulnerable to client-initiated renegotiation DoS — {where}")
            if r.get('supports_secure_renegotiation') is False:
                add(f"[sslyze][MEDIUM] Secure renegotiation not supported — {where}")

        r = result_of('tls_fallback_scsv')
        if r and r.get('supports_fallback_scsv') is False:
            add(f"[sslyze][LOW] TLS_FALLBACK_SCSV not supported (downgrade protection missing) — {where}")

        r = result_of('certificate_info')
        if r:
            for dep in (r.get('certificate_deployments') or []):
                pv = dep.get('path_validation_results') or []
                if pv and all(p.get('was_validation_successful') is False for p in pv):
                    errs = sorted({p.get('validation_error') for p in pv if p.get('validation_error')})
                    detail = ('; '.join(errs)[:140]) if errs else 'not trusted by any store'
                    add(f"[sslyze][MEDIUM] Certificate chain not trusted: {detail} — {where}")
                if dep.get('verified_chain_has_sha1_signature'):
                    add(f"[sslyze][MEDIUM] Certificate chain uses SHA-1 signature — {where}")
                if dep.get('received_chain_has_valid_order') is False:
                    add(f"[sslyze][LOW] Certificate chain is out of order — {where}")

    return findings


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


def parse_openvas_output(output_file): #UNUSED
    """
    UNUSED Parse OpenVAS XML output for vulnerabilities 
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


def send_ip_change_notification(test, log_scan, live_ips):
    """
    Send email notification when IP count changes
    """
    subject = 'Změna IP rozsahu'
    message = f"""Pro sken {test.nickname} s id {test.id} byl nalezena změna živých IP adres. ID adres: {live_ips.id}. ID k logu tohoto skenu je {log_scan.id}"""

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