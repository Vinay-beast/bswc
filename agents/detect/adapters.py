"""Read-only security-tool adapters and bounded public advisory/metadata requests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, unquote

from .core import finding, now, redact, write_json

ROOT = Path(__file__).resolve().parents[2]


def http_json(url, payload=None, timeout=30, limit=20_000_000):
    headers = {'User-Agent': 'Guardian-Detect/1', 'Accept': 'application/json'}
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(url, data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError('Response exceeded configured byte limit')
            return json.loads(data)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            time.sleep(min(8, 2 ** attempt))


def tool_path(name):
    executable = name + ('.exe' if os.name == 'nt' else '')
    for path in [ROOT / 'tools/bin' / executable, Path(sys.executable).parent / executable]:
        if path.is_file():
            return str(path)
    return shutil.which(name)


def run_tool(name, args, output, *, accepted=(0,), timeout=360, module=None):
    executable = tool_path(name)
    if module:
        command = [sys.executable, '-m', module, *map(str, args)]
    elif executable:
        command = [executable, *map(str, args)]
    else:
        return {'tool': name, 'status': 'unavailable', 'reason': 'Executable not installed', 'command': [name, *map(str, args)]}
    record = {'tool': name, 'command': command, 'started_at': now(), 'status': 'running'}
    env = {k: v for k, v in os.environ.items() if not any(term in k.upper() for term in ('API_KEY', 'GROQ', 'TOKEN', 'PASSWORD', 'SECRET'))}
    env['PYTHONUTF8'] = '1'
    try:
        result = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace',
                                timeout=timeout, stdin=subprocess.DEVNULL, env=env)
        record.update({'exit_code': result.returncode, 'status': 'ok' if result.returncode in accepted else 'failed',
                       'stderr_tail': redact(result.stderr[-3500:])})
        if result.stdout.strip():
            Path(output).write_text(redact(result.stdout), encoding='utf-8')
        if record['status'] == 'ok' and not result.stdout.strip():
            record.update(status='failed', reason='Tool produced no output')
    except OSError as error:
        record.update(status='blocked' if getattr(error, 'winerror', None) in (4551, 577, 1260) else 'failed', reason=redact(str(error)))
    except subprocess.TimeoutExpired:
        record.update(status='timeout', reason=f'Exceeded {timeout}s; coverage is incomplete')
    return record


def severity_from_osv(advisory):
    label = advisory.get('database_specific', {}).get('severity')
    if label and label.upper() in ('CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'):
        return 'MEDIUM' if label.upper() == 'MODERATE' else label.upper()
    try:
        from cvss import CVSS2, CVSS3, CVSS4
        scores = []
        for record in advisory.get('severity', []):
            vector = record.get('score', '')
            cls = CVSS4 if vector.startswith('CVSS:4') else CVSS3 if vector.startswith('CVSS:3') else CVSS2
            scores.append(float(cls(vector).scores()[0]))
        score = max(scores) if scores else 0
        return 'CRITICAL' if score >= 9 else 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW' if score > 0 else 'UNKNOWN'
    except Exception:
        return 'UNKNOWN'


def osv_findings(packages, directory, request=http_json):
    eligible = [p for p in packages if p.get('version') and p.get('purl') and p.get('ecosystem') != 'githubactions']
    batches, errors, answers = [], [], []
    queries = [{'package': {'purl': p['purl'].split('?', 1)[0]}} for p in eligible]
    def fetch_batch(offset):
        payload = {'queries': queries[offset:offset + 100]}
        response = request('https://api.osv.dev/v1/querybatch', payload)
        results = response.get('results', [])
        if len(results) != len(payload['queries']):
            raise ValueError('OSV response did not preserve batch query count')
        records = []
        for i, item in enumerate(results):
            records.append({'package_id': eligible[offset+i]['id'], 'purl': eligible[offset+i]['purl'], 'vulns': item.get('vulns', [])})
            token = item.get('next_page_token')
            seen_tokens = set()
            while token:
                if token in seen_tokens:
                    raise ValueError('OSV returned a repeated pagination token')
                seen_tokens.add(token)
                page = request('https://api.osv.dev/v1/query', {**payload['queries'][i], 'page_token': token})
                records[-1]['vulns'].extend(page.get('vulns', []))
                token = page.get('next_page_token')
        return records
    with ThreadPoolExecutor(max_workers=4) as executor:
        pending = {executor.submit(fetch_batch, i): i for i in range(0, len(queries), 100)}
        for future in as_completed(pending):
            try:
                answers.extend(future.result())
            except Exception as error:
                errors.append(f'OSV batch {pending[future]}: {type(error).__name__}: {getattr(error, "code", "request failed")}')
    ids = sorted({v['id'] for answer in answers for v in answer['vulns']})
    advisories = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        pending = {executor.submit(request, 'https://api.osv.dev/v1/vulns/' + quote(vid, safe='')): vid for vid in ids}
        for future in as_completed(pending):
            try:
                advisory = future.result()
                if not advisory.get('withdrawn'):
                    advisories[pending[future]] = advisory
            except Exception as error:
                errors.append(f'OSV advisory {pending[future]}: {type(error).__name__}')
    write_json(Path(directory) / 'osv-query-results.json', answers)
    write_json(Path(directory) / 'osv-advisories.json', advisories)
    findings = []
    by_id = {package['id']: package for package in eligible}
    for answer in answers:
        for hit in answer['vulns']:
            advisory = advisories.get(hit['id'])
            if not advisory:
                continue
            aliases = advisory.get('aliases', [])
            primary = next((v for v in aliases if v.startswith('CVE-')), None) or advisory['id']
            fixed = sorted({event['fixed'] for affected in advisory.get('affected', []) if affected.get('package', {}).get('name') == by_id[answer['package_id']]['name']
                            for version_range in affected.get('ranges', []) for event in version_range.get('events', []) if event.get('fixed')})
            category = 'known-malicious-package' if advisory['id'].startswith('MAL-') else 'known-vulnerability'
            findings.append(finding(category, advisory.get('summary') or advisory['id'], tool='OSV API',
                 severity=severity_from_osv(advisory), confidence='high', status='database-match',
                 package_id=answer['package_id'], advisory_id=primary,
                 evidence=[{'source': 'OSV', 'url': 'https://osv.dev/vulnerability/' + advisory['id'], 'osv_id': advisory['id'],
                            'aliases': aliases, 'matched_purl': answer['purl'], 'published': advisory.get('published'), 'modified': advisory.get('modified')}],
                 remediation=['Review the advisory and upgrade through an affected direct dependency where required.'],
                 aliases=sorted(set([advisory['id'], *aliases])), fixed_versions=fixed,
                 advisory_severity=advisory.get('severity', [])))
    unversioned = sum(not p.get('version') for p in packages if p.get('ecosystem') != 'githubactions')
    coverage = {'status': 'complete' if not errors and not unversioned else 'partial', 'queried_packages': len(answers),
                'eligible_packages': len(eligible), 'advisories_loaded': len(advisories), 'errors': errors,
                'unversioned_packages_not_matched': unversioned,
                'databases': {'OSV': 'queried', 'GHSA': 'included through OSV advisory records', 'NVD': 'CVE identifiers retained; NVD not independently queried'},
                'note': 'Database affected-version matching; runtime exploitability is not established.'}
    return findings, coverage


def trivy_findings(document, packages):
    result = []
    for target in document.get('Results', []):
        for vuln in target.get('Vulnerabilities', []) or []:
            matches = [p for p in packages if p['name'] == vuln.get('PkgName') and p.get('version') == vuln.get('InstalledVersion')]
            for package in matches:
                result.append(finding('known-vulnerability', vuln.get('Title') or vuln['VulnerabilityID'], tool='Trivy',
                  severity=vuln.get('Severity', 'UNKNOWN'), confidence='high', status='database-match', package_id=package['id'],
                  advisory_id=vuln['VulnerabilityID'], evidence=[{'source': 'Trivy', 'url': vuln.get('PrimaryURL'),
                  'data_source': vuln.get('DataSource'), 'target': target.get('Target')}],
                  fixed_versions=[vuln['FixedVersion']] if vuln.get('FixedVersion') else [], aliases=[vuln['VulnerabilityID']]))
    return result


def osv_scanner_findings(document, packages):
    findings = []
    for source in document.get('results', []):
        for entry in source.get('packages', []):
            package = entry.get('package', {})
            matched = [p for p in packages if p['name'] == package.get('name') and p.get('version') == package.get('version')]
            for advisory in entry.get('vulnerabilities', []):
                aliases = advisory.get('aliases', [])
                primary = next((a for a in aliases if a.startswith('CVE-')), advisory.get('id'))
                for node in matched:
                    findings.append(finding('known-malicious-package' if advisory['id'].startswith('MAL-') else 'known-vulnerability',
                      advisory.get('summary') or advisory['id'], tool='OSV-Scanner', severity=severity_from_osv(advisory),
                      confidence='high', status='database-match', package_id=node['id'], advisory_id=primary,
                      evidence=[{'source': 'OSV-Scanner', 'osv_id': advisory['id'], 'url': 'https://osv.dev/vulnerability/' + advisory['id']}],
                      aliases=sorted(set([advisory['id'], *aliases]))))
    return findings
