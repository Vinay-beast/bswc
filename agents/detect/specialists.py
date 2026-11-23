"""Six specialists exchange evidence through the orchestrator's shared JSON state."""
from __future__ import annotations

from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
import urllib.error
from urllib.parse import quote, unquote

import yaml

from .adapters import http_json, osv_findings, run_tool, trivy_findings, osv_scanner_findings
from .core import AgentResult, finding, write_json


class DiscoveryAgent:
    name = 'DiscoveryAgent'

    def run(self, context):
        folder, target = context['discovery_dir'], context['target']
        graph = json.loads((folder / 'dependency-graph.json').read_text(encoding='utf-8'))
        source = json.loads((folder / 'source-analysis.json').read_text(encoding='utf-8'))
        nodes = {n['id']: n for n in graph['nodes']}
        if any(e['from'] not in nodes or e['to'] not in nodes for e in graph['edges']):
            raise ValueError('Discovery graph has dangling edges; detection cannot establish dependency paths')
        if Path(graph['analyzedPath']).resolve() != target.resolve():
            raise ValueError('Discovery report targets a different source directory')
        stale = []
        for record in source['files']:
            if record['kind'] in ('manifest', 'lockfile', 'workflow'):
                file = (target / record['path']).resolve()
                if not file.is_relative_to(target):
                    raise ValueError('Source evidence path escapes the target')
                if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != record['sha256']:
                    stale.append(record['path'])
        if stale:
            raise ValueError('Dependency/workflow evidence changed; refresh discovery before detection: ' + ', '.join(stale[:10]))
        packages = [n for n in nodes.values() if n['kind'] == 'package']
        context.update(graph=graph, source=source, packages=packages, nodes=nodes,
                       sbom=folder / 'cyclonedx-sbom.json')
        return AgentResult(self.name, coverage={'discovery': {'status': 'complete', 'packages': len(packages),
                           'source_files': source['summary']['files'], 'source_commit': graph.get('source', {}).get('commit'),
                           'validated': 'Graph endpoints and manifest/lockfile/workflow hashes'}},
                           artifacts={'graph': str(folder / 'dependency-graph.json'), 'sbom': str(context['sbom'])})


class VulnerabilityDetectionAgent:
    name = 'VulnerabilityDetectionAgent'

    def run(self, context):
        output, packages = context['raw'], context['packages']
        tools, findings = [], []
        tasks = {
            'osv-api': lambda: osv_findings(packages, output),
            'trivy': lambda: run_tool('trivy', ['sbom', '--scanners', 'vuln', '--format', 'json', context['sbom']], output / 'trivy.json'),
            'osv-scanner': lambda: run_tool('osv-scanner', ['scan', 'source', '--sbom', context['sbom'], '--format', 'json'], output / 'osv-scanner.json', accepted=(0, 1)),
        }
        coverage = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            pending = {executor.submit(task): name for name, task in tasks.items()}
            for future in as_completed(pending):
                name = pending[future]
                try:
                    result = future.result()
                    if name == 'osv-api':
                        matches, status = result
                        findings.extend(matches)
                        coverage['known_vulnerabilities'] = status
                        print(f'[VulnerabilityDetectionAgent] OSV matched {len(matches)} package/advisory records.', flush=True)
                    else:
                        tools.append(result)
                        if name == 'trivy' and result['status'] == 'ok':
                            findings.extend(trivy_findings(json.loads((output / 'trivy.json').read_text(encoding='utf-8')), packages))
                        elif name == 'osv-scanner' and result['status'] == 'ok':
                            findings.extend(osv_scanner_findings(json.loads((output / 'osv-scanner.json').read_text(encoding='utf-8')), packages))
                except Exception as error:
                    coverage[name] = {'status': 'failed', 'reason': type(error).__name__}
        coverage.setdefault('known_vulnerabilities', {'status': 'failed', 'reason': 'No successful advisory match completed'})
        coverage['sca_tools'] = {'status': 'complete' if all(t['status'] == 'ok' for t in tools) else 'partial',
                                 'tools': [{k: t.get(k) for k in ['tool', 'status', 'reason']} for t in tools],
                                 'note': 'Both Trivy and OSV can detect direct and transitive vulnerabilities; graph analysis classifies the relationship.'}
        return AgentResult(self.name, findings, coverage, tools)


CODE_RULES = [
    ('dynamic-evaluation', 'Potential dynamic code evaluation', 'HIGH', r'\b(?:eval|new\s+Function)\s*\('),
    ('sql-construction', 'Potential SQL query constructed from request input', 'HIGH', r'(?:sequelize\.)?query\s*\(.*(?:req\.(?:body|query|params)|\$\{)'),
    ('command-execution', 'Potential command execution using request input', 'HIGH', r'\b(?:exec|execSync|spawn|spawnSync)\s*\(.*req\.(?:body|query|params)'),
    ('html-trust-bypass', 'HTML security trust bypass requires review', 'MEDIUM', r'\bbypassSecurityTrust(?:Html|Script|ResourceUrl)\s*\('),
    ('request-filesystem-path', 'Request data used in a filesystem path', 'MEDIUM', r'\b(?:readFile|readFileSync|sendFile|unlink|writeFile)\s*\(.*req\.(?:body|query|params)'),
]


class CodeSecurityAgent:
    name = 'CodeSecurityAgent'

    def run(self, context):
        findings, reviewed, skipped = [], 0, []
        for record in context['source']['files']:
            if record['kind'] != 'source' or record.get('bytes', 0) > 2_000_000:
                continue
            if record.get('language') not in ('JavaScript', 'TypeScript', 'Python', 'Vue', 'Svelte'):
                continue
            path = (context['target'] / record['path']).resolve()
            if not path.is_relative_to(context['target']):
                continue
            try:
                lines = path.read_text(encoding='utf-8-sig').splitlines()
                reviewed += 1
            except (OSError, UnicodeError):
                skipped.append(record['path'])
                continue
            for number, line in enumerate(lines, 1):
                if line.lstrip().startswith(('//', '#', '*')):
                    continue
                for rule, title, severity, pattern in CODE_RULES:
                    if re.search(pattern, line) and len(findings) < 350:
                        findings.append(finding('code-security', title, tool='Guardian static patterns', severity=severity,
                          confidence='medium', location={'path': record['path'], 'line': number},
                          evidence=[{'rule': rule, 'snippet': line.strip()[:350], 'technique': 'static-pattern',
                                     'scope': 'reference-snippet' if record['path'].startswith('data/static/codefixes/') else 'test-fixture' if record['path'].startswith(('test/', 'tests/', 'rsn/', 'cypress/')) else 'application'}],
                          remediation=['Review input provenance and the surrounding function; static patterns do not establish exploitability.']))
        tools = []
        record = run_tool('bandit', ['-r', context['target'], '-f', 'json', '-q'], context['raw'] / 'bandit.json', accepted=(0, 1), module='bandit', timeout=90)
        tools.append(record)
        if record['status'] == 'ok':
            try:
                document = json.loads((context['raw'] / 'bandit.json').read_text(encoding='utf-8'))
                for item in document.get('results', []):
                    path = Path(item['filename']).resolve()
                    findings.append(finding('code-security', item['issue_text'], tool='Bandit', severity=item['issue_severity'],
                      confidence=item.get('issue_confidence', 'medium').lower(), location={'path': str(path.relative_to(context['target'])), 'line': item['line_number']},
                      evidence=[{'rule': item['test_id'], 'url': item.get('more_info')}]))
                skipped.extend(e.get('filename', '') for e in document.get('errors', []))
            except (ValueError, KeyError):
                record['status'] = 'failed'
        semgrep = run_tool('semgrep', ['scan', '--config', 'p/ci', '--json', '--disable-version-check', context['target']],
                           context['raw'] / 'semgrep.json', timeout=180)
        tools.append(semgrep)
        if semgrep['status'] == 'ok':
            document = json.loads((context['raw'] / 'semgrep.json').read_text(encoding='utf-8'))
            for item in document.get('results', []):
                findings.append(finding('code-security', item.get('extra', {}).get('message', item['check_id']), tool='Semgrep',
                    severity={'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}.get(item.get('extra', {}).get('severity'), 'UNKNOWN'),
                    location={'path': item['path'], 'line': item.get('start', {}).get('line')}, evidence=[{'rule': item['check_id']}]))
        for item in findings:
            path = (item.get('location') or {}).get('path', '').replace('\\', '/')
            item['source_scope'] = 'reference-snippet' if path.startswith('data/static/codefixes/') else 'test-fixture' if path.startswith(('test/', 'tests/', 'rsn/', 'cypress/')) else 'application'
        return AgentResult(self.name, findings, {'code_security': {'status': 'partial', 'source_files_reviewed': reviewed,
             'unparsed_files': sorted(set(skipped)), 'note': 'Pattern evidence plus available SAST tools; no whole-program taint or runtime reachability proof.'}}, tools)


POPULAR = {
    'npm': ['express', 'lodash', 'react', 'react-dom', 'typescript', 'axios', 'chalk', 'debug', 'commander', 'dotenv', 'webpack',
            'vite', 'vitest', 'eslint', 'prettier', 'jsonwebtoken', 'jquery', 'moment', 'mongoose', 'sequelize', 'sqlite3',
            'request', 'cross-env', 'cross-fetch', 'node-fetch', 'body-parser', 'cookie-parser', 'cors', 'zod', 'semver', 'minimist', 'rimraf'],
    'pypi': ['requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'fastapi', 'pydantic', 'pytest', 'setuptools', 'cryptography'],
}


def similar_name(package):
    name = package['name']
    if name.startswith('@'):
        return None  # Do not equate a scoped namespace with an unrelated unscoped package.
    baseline = POPULAR.get(package.get('ecosystem'), [])
    if name in baseline or len(name) < 5:
        return None
    candidates = [(SequenceMatcher(None, name.lower(), item.lower()).ratio(), item) for item in baseline]
    score, closest = max(candidates, default=(0, ''))
    return {'similar_to': closest, 'similarity': round(score, 3)} if score >= .86 else None


def workflow_rules(target):
    findings = []
    for file in sorted((target / '.github/workflows').glob('*')):
        if file.suffix not in ('.yml', '.yaml'):
            continue
        path = file.relative_to(target).as_posix()
        text = file.read_text(encoding='utf-8-sig')
        try:
            document = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            findings.append(finding('coverage-gap', 'Workflow YAML could not be parsed', tool='Guardian workflow rules',
                 severity='LOW', confidence='high', status='coverage-gap', location={'path': path, 'line': 1},
                 evidence=[{'reason': 'Workflow checks are incomplete for this file.'}]))
            continue
        if not isinstance(document, dict):
            findings.append(finding('coverage-gap', 'Workflow document is not a mapping', tool='Guardian workflow rules',
                 severity='LOW', status='coverage-gap', location={'path': path, 'line': 1}))
            continue
        def emit(title, severity, line, rule, note):
            findings.append(finding('ci-cd', title, tool='Guardian workflow rules', severity=severity, status='configuration-risk',
                location={'path': path, 'line': line}, evidence=[{'rule': rule, 'observation': note}],
                remediation=['Review effective permissions, pinning and input trust boundaries; no workflow execution was performed.']))
        if 'permissions' not in document:
            emit('Workflow does not declare token permissions', 'LOW', 1, 'implicit-permissions', 'Effective repository defaults were not verified; write access is not assumed.')
        lines = text.splitlines()
        for line, value in enumerate(lines, 1):
            if re.search(r'permissions:\s*write-all', value):
                emit('Workflow grants broad write permissions', 'MEDIUM', line, 'write-all', 'Explicit permissions: write-all')
            match = re.search(r'''\buses:\s*['"]?([^\s'"#]+)''', value)
            if match:
                uses = match[1]
                if not uses.startswith(('./', 'docker://')) and '@' in uses and not re.fullmatch('[a-fA-F0-9]{40}', uses.rsplit('@', 1)[1]):
                    emit('External action uses a mutable ref', 'MEDIUM', line, 'mutable-action-ref', uses)
                if uses.startswith('docker://') and '@sha256:' not in uses:
                    emit('Workflow container action is not digest-pinned', 'MEDIUM', line, 'mutable-container', uses)
            if re.search(r'\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion)\.(?:title|body|head\.ref)', value):
                # Determine whether the expression occurs in a run block, not an arbitrary display label.
                block = '\n'.join(lines[max(0, line-12):line])
                if re.search(r'\brun:\s*', block):
                    emit('Potential untrusted event interpolation in shell script', 'HIGH', line, 'event-script-injection', value.strip()[:300])
        if 'pull_request_target' in text and re.search(r'github\.event\.pull_request\.head\.(?:sha|ref|repo)', text):
            emit('Privileged PR trigger references untrusted PR head', 'HIGH', 1, 'pr-target-untrusted-head', 'Review checkout and execution context together; configuration pattern requires validation.')
    return findings


class SupplyChainAgent:
    name = 'SupplyChainAgent'

    def run(self, context):
        findings, tools, coverage = workflow_rules(context['target']), [], {}
        packages = [p for p in context['packages'] if p.get('ecosystem') == 'npm' and p.get('version')]
        direct_ids = {e['to'] for e in context['graph']['edges'] if e['kind'] == 'declares'}
        suspects = {p['id']: similar_name(p) for p in packages}
        selected = sorted(packages, key=lambda p: (p['id'] not in direct_ids, not bool(suspects[p['id']]), p['name']))[:context['config']['max_registry_packages']]
        metadata, errors = {}, []
        with ThreadPoolExecutor(max_workers=8) as executor:
            pending = {executor.submit(http_json, 'https://registry.npmjs.org/' + quote(p['name'], safe='') + '/' + quote(p['version'], safe='')): p for p in selected}
            for future in as_completed(pending):
                package = pending[future]
                try:
                    document = future.result()
                    metadata[package['id']] = document
                    scripts = document.get('scripts', {})
                    for hook in ('preinstall', 'install', 'postinstall', 'prepare'):
                        command = scripts.get(hook, '')
                        signals = []
                        if re.search(r'(?:curl|wget|Invoke-WebRequest).*(?:\|\s*(?:sh|bash|powershell)|;\s*(?:sh|bash))', command, re.I):
                            signals.append('download-and-execute shell pattern')
                        if re.search(r'\.ssh|\.npmrc|\.aws/credentials|id_rsa', command):
                            signals.append('credential-path reference')
                        if re.search(r'(?:eval|exec)\s*\(.*(?:base64|fromCharCode|atob)', command):
                            signals.append('obfuscated execution pattern')
                        if signals:
                            findings.append(finding('install-script', 'Suspicious install-hook pattern: ' + package['name'],
                              tool='npm registry metadata + Guardian patterns', severity='HIGH', package_id=package['id'],
                              evidence=[{'hook': hook, 'signals': signals, 'command': command[:500],
                                         'url': 'https://registry.npmjs.org/' + quote(package['name'], safe='') + '/' + package['version']}],
                              remediation=['Inspect the published artifact and expected installer behavior; this heuristic does not prove malware.']))
                    if suspects[package['id']]:
                        findings.append(finding('typosquatting', 'Package name resembles a reference name: ' + package['name'],
                          tool='Guardian name similarity', severity='LOW', confidence='low', package_id=package['id'],
                          evidence=[{**suspects[package['id']], 'registry_exists': True}],
                          remediation=['Check package ownership and intent. Similarity alone is not evidence of a malicious package.']))
                except Exception as error:
                    errors.append({'package_id': package['id'], 'error': type(error).__name__, 'http_status': getattr(error, 'code', None)})
                    if getattr(error, 'code', None) == 404:
                        findings.append(finding('slopsquatting', 'Resolved package version is unavailable from the public npm registry',
                          tool='npm registry metadata', severity='MEDIUM', confidence='medium', package_id=package['id'],
                          evidence=[{'http_status': 404, 'note': 'Could be unpublished, private, or unavailable; hallucination is not established.'}]))
        write_json(context['raw'] / 'registry-manifests.json', metadata)
        coverage['typosquatting_slopsquatting'] = {'status': 'partial', 'names_compared': len(packages),
                 'registry_versions_checked': len(metadata), 'registry_budget': len(selected), 'errors': errors,
                 'note': 'Name similarity is heuristic. Public-registry existence does not prove package trust; age/download checks are not inferred.'}
        coverage['install_scripts'] = {'status': 'partial', 'manifests_inspected': len(metadata),
                 'note': 'Static published hook metadata only. No install hooks or untrusted package code were executed; dynamic sandboxing and full artifact scans were not run.'}
        coverage['dependency_confusion'] = {'status': 'not-run', 'reason': 'Deprioritized by requested scope. Namespacing alone does not eliminate private/public registry confusion.'}
        scorecard = {}
        try:
            scorecard = http_json('https://api.scorecard.dev/projects/github.com/juice-shop/juice-shop')
            for check in scorecard.get('checks', []):
                if 0 <= check.get('score', -1) <= 3:
                    findings.append(finding('project-health', 'Low OpenSSF Scorecard check: ' + check['name'],
                      tool='OpenSSF Scorecard API', severity='LOW', status='health-signal', confidence='high',
                      evidence=[{'check': check['name'], 'score': check['score'], 'reason': check.get('reason'), 'date': scorecard.get('date')}],
                      remediation=['Review the specific project-control weakness. This does not establish malicious maintainers or account takeover.']))
            coverage['maintainer_project_health'] = {'status': 'partial', 'score': scorecard.get('score'), 'date': scorecard.get('date'),
                        'reason': 'Published target-project health only; package-maintainer account takeover and historical changes are not established.'}
        except Exception as error:
            coverage['maintainer_project_health'] = {'status': 'unavailable', 'reason': type(error).__name__}
        write_json(context['raw'] / 'scorecard.json', scorecard)
        workflow_output = context['raw'] / 'zizmor.json'
        record = run_tool('zizmor', ['--offline', '--format', 'json', '--no-exit-codes', context['target'] / '.github/workflows'], workflow_output)
        tools.append(record)
        if record['status'] == 'ok':
            try:
                document = json.loads(workflow_output.read_text(encoding='utf-8'))
                records = document if isinstance(document, list) else document.get('findings', [])
                for item in records:
                    audit = item.get('ident') or item.get('audit', {}).get('id') or item.get('rule_id') or 'workflow-audit'
                    determinations = item.get('determinations', {})
                    findings.append(finding('ci-cd', item.get('desc') or item.get('description') or str(audit), tool='zizmor',
                      severity=str(determinations.get('severity', item.get('severity', 'UNKNOWN'))).upper(),
                      confidence='high', status='tool-finding', location={'path': str(item.get('locations', [{}])[0].get('input', {}).get('key', 'workflow'))},
                      evidence=[{'rule': audit, 'raw_evidence': item}]))
            except (ValueError, AttributeError, IndexError):
                record['status'] = 'parse-failed'
        coverage['ci_cd'] = {'status': 'complete' if record['status'] == 'ok' else 'partial', 'zizmor': record['status'],
                 'note': 'GitHub Actions source patterns and available zizmor audits; other CI platforms are not present in this target.'}
        image = context['config'].get('image')
        if image:
            image_output = context['raw'] / 'container-trivy.json'
            image_record = run_tool('trivy', ['image', '--scanners', 'vuln', '--format', 'json', image], image_output, timeout=360)
            tools.append(image_record)
            coverage['container_artifacts'] = {'status': image_record['status'], 'image': image,
                                              'reason': 'Image content is scanned without running the container.'}
            if image_record['status'] == 'ok':
                data = json.loads(image_output.read_text(encoding='utf-8'))
                for target in data.get('Results', []):
                    for issue in target.get('Vulnerabilities', []) or []:
                        findings.append(finding('container-vulnerability', issue.get('Title') or issue['VulnerabilityID'], tool='Trivy image',
                            severity=issue.get('Severity', 'UNKNOWN'), confidence='high', status='database-match', advisory_id=issue['VulnerabilityID'],
                            evidence=[{'image': image, 'package': issue.get('PkgName'), 'version': issue.get('InstalledVersion'), 'url': issue.get('PrimaryURL')}]))
        else:
            coverage['container_artifacts'] = {'status': 'not-run', 'reason': 'No --image provided. Source image references do not establish image contents or CVEs.'}
        baseline = context['config'].get('baseline')
        if baseline:
            before = json.loads(Path(baseline).read_text(encoding='utf-8-sig'))
            root = before.get('metadata', {}).get('component', {})
            if root.get('name') != 'juice-shop':
                coverage['dependency_drift'] = {'status': 'not-run', 'reason': 'Baseline belongs to a different project'}
            else:
                def pairs(items):
                    values = set()
                    for item in items:
                        if item.get('purl'):
                            values.add(unquote(item['purl'].split('?', 1)[0]))
                        values.update(pairs(item.get('components', [])))
                    return values
                old = pairs(before.get('components', []))
                current = {unquote(p['purl'].split('?', 1)[0]) for p in context['packages'] if p.get('purl')}
                diff = {'added': sorted(current-old), 'removed': sorted(old-current),
                        'note': 'Scope/commit differences can produce legitimate drift; unexpectedness is not assumed.'}
                write_json(context['raw'] / 'sbom-drift.json', diff)
                context['drift_added'] = set(diff['added'])
                coverage['dependency_drift'] = {'status': 'complete', 'added': len(diff['added']), 'removed': len(diff['removed']), 'baseline': str(baseline)}
        else:
            coverage['dependency_drift'] = {'status': 'not-run', 'reason': 'A comparable prior --baseline SBOM was not supplied; no drift is invented.'}
        return AgentResult(self.name, findings, coverage, tools, artifacts={'registry_manifest_count': len(metadata)})


class DependencyAnalysisAgent:
    name = 'DependencyAnalysisAgent'

    def run(self, context, findings):
        graph, nodes = context['graph'], context['nodes']
        outgoing = {}
        direct = {edge['to'] for edge in graph['edges'] if edge['kind'] == 'declares'}
        for edge in graph['edges']:
            if edge['kind'] == 'depends-on':
                outgoing.setdefault(edge['from'], []).append(edge['to'])
        roots = [node['id'] for node in graph['nodes'] if node['kind'] == 'project']
        paths = {}
        for root in roots:
            seen = {root}
            queue = deque([(root, [root])])
            while queue:
                parent, path = queue.popleft()
                for child in outgoing.get(parent, []):
                    if child not in seen:
                        seen.add(child)
                        child_path = [*path, child]
                        paths.setdefault(child, []).append(child_path)
                        queue.append((child, child_path))
        imports = context['source'].get('imports', [])
        for item in findings:
            package = nodes.get(item.get('package_id'))
            if not package:
                continue
            package_paths = paths.get(package['id'], [])
            item['dependency_relationship'] = 'direct' if package['id'] in direct else 'transitive' if package_paths else 'unattributed'
            item['dependency_paths'] = [{'ids': path, 'names': [nodes[n]['name'] for n in path]} for path in package_paths[:4]]
            matches = [imp for imp in imports if imp['reference'] == package['name'] or imp['reference'].startswith(package['name'] + '/')]
            item['reachability'] = {'status': 'import-observed' if matches else 'unknown',
                'reason': 'Package import evidence is not vulnerable-function reachability. No finding was suppressed on this basis.',
                'source_references': matches[:10]}
            item['new_in_baseline'] = unquote(package.get('purl', '').split('?', 1)[0]) in context.get('drift_added', set())
        context['dependency_paths'] = paths
        return AgentResult(self.name, coverage={'dependency_analysis': {'status': 'complete',
            'packages_with_project_paths': len(paths), 'project_roots': len(roots),
            'function_reachability': 'unknown', 'note': 'Shortest dependency paths and static imports are evidence, not exploitability proof.'}},
            artifacts={'classified_findings': len([f for f in findings if f.get('package_id')])})


class ReportingAgent:
    name = 'ReportingAgent'

    def run(self, context, findings, state):
        severity = Counter(item['severity'] for item in findings)
        categories = Counter(item['category'] for item in findings)
        summary = {'findings': len(findings), 'by_severity': dict(severity), 'by_category': dict(categories),
                   'known_vulnerability_matches': sum(f['status'] == 'database-match' for f in findings),
                   'potential_or_configuration_findings': sum(f['status'] != 'database-match' for f in findings),
                   'direct_vulnerability_matches': sum(f['category'] == 'known-vulnerability' and f.get('dependency_relationship') == 'direct' for f in findings),
                   'transitive_vulnerability_matches': sum(f['category'] == 'known-vulnerability' and f.get('dependency_relationship') == 'transitive' for f in findings)}
        summary['source_findings_by_scope'] = dict(Counter(item.get('source_scope', 'unknown') for item in findings if item['category'] == 'code-security'))
        state.data['summary'] = summary
        return AgentResult(self.name, coverage={'reporting': {'status': 'complete', 'summary': summary}}, artifacts={'summary': summary})
