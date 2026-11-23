"""Master orchestrator: parallel evidence collection, dependency analysis, Groq review and reporting."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

from .core import WorkflowState, finding, now, redact, write_json
from .groq_client import GroqClient
from .specialists import (DiscoveryAgent, VulnerabilityDetectionAgent, CodeSecurityAgent,
                          SupplyChainAgent, DependencyAnalysisAgent, ReportingAgent)


def merge_findings(items):
    """Collapse advisory aliases per affected package, preserving corroborating evidence."""
    parent = {}
    def root(value):
        parent.setdefault(value, value)
        if parent[value] != value:
            parent[value] = root(parent[value])
        return parent[value]
    for item in items:
        aliases = [v for v in [item.get('advisory_id'), *item.get('aliases', [])] if v]
        for alias in aliases[1:]:
            parent[root(alias)] = root(aliases[0])
    merged = {}
    ranks = {'UNKNOWN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    for original in items:
        item = deepcopy(original)
        key = (item['category'], item.get('package_id'), root(item['advisory_id'])) if item.get('advisory_id') and item.get('package_id') else item['id']
        if key not in merged:
            merged[key] = item
        else:
            target = merged[key]
            for field in ('tools', 'evidence', 'aliases', 'fixed_versions'):
                for value in item.get(field, []):
                    if value not in target.setdefault(field, []):
                        target[field].append(value)
            if ranks.get(item['severity'], 0) > ranks.get(target['severity'], 0):
                target['severity'] = item['severity']
    return sorted(merged.values(), key=lambda f: (-ranks.get(f['severity'], 0), f['category'], f['title']))


def followups(context, state, reviews):
    allowed = {'source_import_context', 'dependency_path'}
    requested = []
    for review in reviews:
        if review and review.get('status') == 'ok':
            candidates = review.get('analysis', {}).get('requested_followups', [])
            if isinstance(candidates, list):
                requested.extend(candidates)
    for request in requested[:4]:
        if not isinstance(request, dict) or request.get('check') not in allowed or request.get('package_id') not in context['nodes']:
            state.data['followups'].append({'status': 'rejected', 'reason': 'Unknown check or package identifier'})
            continue
        package = context['nodes'][request['package_id']]
        record = {'check': request['check'], 'package_id': package['id'], 'requested_by': 'Groq evidence reviewer', 'status': 'complete'}
        if request['check'] == 'dependency_path':
            record['result'] = context.get('dependency_paths', {}).get(package['id'], [])[:4]
        else:
            refs = [r for r in context['source'].get('imports', []) if r['reference'] == package['name'] or r['reference'].startswith(package['name'] + '/')]
            record['result'] = []
            for source in refs[:3]:
                path = (context['target'] / source['path']).resolve()
                if path.is_relative_to(context['target']) and path.is_file():
                    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
                    line = int(source.get('line') or 1)
                    record['result'].append({**source, 'source_context': '\n'.join(lines[max(0, line-4):line+8])[:2000]})
        state.data['followups'].append(record)
        state.event('MasterOrchestrator', 'DependencyAnalysisAgent', 'Execute allowlisted evidence follow-up', check=record['check'], package_id=package['id'])


def sarif(findings, context):
    rules = {}
    results = []
    for item in findings:
        rule = item.get('advisory_id') or item['category']
        rules.setdefault(rule, {'id': rule, 'shortDescription': {'text': item['title']}})
        result = {'ruleId': rule, 'level': 'error' if item['severity'] in ('CRITICAL', 'HIGH') else 'warning' if item['severity'] == 'MEDIUM' else 'note',
                  'message': {'text': item['title']}, 'properties': {'finding_id': item['id'], 'status': item['status'],
                  'confidence': item['confidence'], 'reachability': item.get('reachability'), 'package_id': item.get('package_id')}}
        location = item.get('location')
        if location and location.get('path'):
            result['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': str(location['path']).replace('\\', '/')},
                                     'region': {'startLine': max(1, int(location.get('line') or 1))}}}]
        results.append(result)
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': 'Guardian Detect', 'version': '1.0.0', 'rules': list(rules.values())}}, 'results': results}]}


def render_dashboard(context, state):
    template = Path(__file__).resolve().parents[2] / 'guardian_scanner/scanner_dashboard.html'
    html = template.read_text(encoding='utf-8')
    folder = context['discovery_dir']
    payloads = {'GRAPH': context['graph'], 'SOURCE': context['source'], 'SBOM': json.loads(context['sbom'].read_text(encoding='utf-8')),
                'WORKFLOWS': json.loads((folder / 'workflow-recursive.cdx.json').read_text(encoding='utf-8')) if (folder / 'workflow-recursive.cdx.json').exists() else None,
                'DETECTION': state.data}
    for marker, value in payloads.items():
        html = html.replace(f'/*__{marker}__*/null', json.dumps(redact(value), ensure_ascii=False).replace('<', '\\u003c'))
    (state.output / 'dashboard.html').write_text(html, encoding='utf-8')


class MasterOrchestrator:
    def __init__(self, target, discovery_dir, output, *, client=None, config=None):
        self.client = client or GroqClient()
        self.config = {'max_registry_packages': 200, 'baseline': None, 'image': None, **(config or {})}
        self.state = WorkflowState(target, output, {**self.config, 'groq_model': self.client.model, 'llm_requested': self.client.enabled})
        self.context = {'target': Path(target).resolve(), 'discovery_dir': Path(discovery_dir).resolve(),
                        'raw': Path(output).resolve() / 'raw', 'config': self.config}

    def _run(self, agent):
        self.state.start(agent.name)
        print('[' + agent.name + '] Starting evidence collection ...', flush=True)
        result = agent.run(self.context)
        result.llm_review = self.client.review(agent.name, result.findings, result.coverage)
        self.state.finish(result)
        print(f'[{agent.name}] Complete: {len(result.findings)} findings.', flush=True)
        return result

    def execute(self):
        self.context['raw'].mkdir(parents=True, exist_ok=True)
        state = self.state
        try:
            self._run(DiscoveryAgent())
        except Exception as error:
            state.fail('DiscoveryAgent', error)
            state.data['status'] = 'failed'
            state.checkpoint()
            raise
        plan = self.client.ask('MasterOrchestrator', 'Plan defensive evidence checks for the provided inventory. Use only the three available collectors; no shell commands.',
               {'packages': len(self.context['packages']), 'source_commit': self.context['graph'].get('source'),
                'available_agents': ['VulnerabilityDetectionAgent', 'CodeSecurityAgent', 'SupplyChainAgent']},
               {'agents': ['VulnerabilityDetectionAgent', 'CodeSecurityAgent', 'SupplyChainAgent'], 'rationale': 'string', 'important_gaps': ['string']})
        state.data['plan'] = plan
        state.event('MasterOrchestrator', 'all', 'Dispatch independent security collectors in parallel')
        reviews = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            tasks = {executor.submit(self._run, agent): agent.name for agent in [VulnerabilityDetectionAgent(), CodeSecurityAgent(), SupplyChainAgent()]}
            for future in as_completed(tasks):
                try:
                    reviews.append(future.result().llm_review)
                except Exception as error:
                    state.fail(tasks[future], error)
        state.data['findings'] = merge_findings(state.data['findings'])
        agent = DependencyAnalysisAgent()
        state.start(agent.name)
        result = agent.run(self.context, state.data['findings'])
        result.llm_review = self.client.review(agent.name, state.data['findings'], result.coverage)
        reviews.append(result.llm_review)
        state.finish(result)
        gap_review = self.client.ask('MasterOrchestrator', 'Review missing evidence and request at most two useful allowlisted follow-ups. Do not retry blocked executables or claim missing checks passed.',
             {'coverage': state.data['coverage'], 'package_ids': [f['package_id'] for f in state.data['findings'][:15] if f.get('package_id')]},
             {'summary': 'string', 'requested_followups': [{'check': 'dependency_path or source_import_context', 'package_id': 'existing id', 'reason': 'string'}]})
        reviews.append(gap_review)
        state.data['gap_review'] = gap_review
        followups(self.context, state, reviews)
        reporter = ReportingAgent()
        state.start(reporter.name)
        report = reporter.run(self.context, state.data['findings'], state)
        report.llm_review = self.client.review(reporter.name, state.data['findings'], state.data['coverage'])
        state.finish(report)
        state.data['llm'] = {'enabled': self.client.enabled, 'model': self.client.model, 'calls': self.client.calls,
                             'successful_calls': sum(r['status'] == 'ok' for r in self.client.records), 'requests': self.client.records}
        state.data['status'] = 'partial' if any(a['status'] == 'failed' for a in state.data['agents'].values()) or any(c.get('status') != 'complete' for c in state.data['coverage'].values()) else 'complete'
        state.data['finished_at'] = now()
        state.event('ReportingAgent', 'MasterOrchestrator', 'Unified detection report available', status=state.data['status'])
        state.checkpoint()
        write_json(state.output / 'findings.json', state.data['findings'])
        write_json(state.output / 'coverage.json', state.data['coverage'])
        write_json(state.output / 'report.sarif.json', sarif(state.data['findings'], self.context))
        render_dashboard(self.context, state)
        return state.data

    def resume_llm_reviews(self):
        """Retry missing reasoning only; do not repeat registry/database/tool scans."""
        state = self.state
        state.data = json.loads((state.output / 'workflow-state.json').read_text(encoding='utf-8'))
        if Path(state.data['target']).resolve() != self.context['target']:
            raise ValueError('Cannot resume reasoning against a different target')
        DiscoveryAgent().run(self.context)
        for item in state.data['findings']:
            if item['category'] == 'code-security':
                path = (item.get('location') or {}).get('path', '').replace('\\', '/')
                item['source_scope'] = 'reference-snippet' if path.startswith('data/static/codefixes/') else 'test-fixture' if path.startswith(('test/', 'tests/', 'rsn/', 'cypress/')) else 'application'
                for evidence in item.get('evidence', []):
                    if evidence.get('technique') == 'static-pattern':
                        evidence['scope'] = item['source_scope']
        report = ReportingAgent().run(self.context, state.data['findings'], state)
        state.data['coverage'].update(report.coverage)
        state.data['agents']['ReportingAgent']['coverage'] = report.coverage
        state.data['agents']['ReportingAgent']['artifacts'] = report.artifacts
        old_requests = state.data.get('llm', {}).get('requests', [])
        old_calls = state.data.get('llm', {}).get('calls', 0)
        for name, agent in state.data['agents'].items():
            if (agent.get('llm_review') or {}).get('status') == 'ok':
                continue
            state.event('MasterOrchestrator', name, 'Retry missing Groq review without re-running security collectors')
            relevant = state.data['findings'] if name in ('DependencyAnalysisAgent', 'ReportingAgent') else agent.get('findings', [])
            agent['llm_review'] = self.client.review(name, relevant, agent.get('coverage', state.data['coverage']))
        records = [*old_requests, *self.client.records]
        state.data['llm'] = {'enabled': self.client.enabled, 'model': self.client.model, 'calls': old_calls+self.client.calls,
                             'successful_calls': sum(r['status'] == 'ok' for r in records), 'requests': records}
        state.data['finished_at'] = now()
        state.checkpoint()
        write_json(state.output / 'findings.json', state.data['findings'])
        write_json(state.output / 'coverage.json', state.data['coverage'])
        write_json(state.output / 'report.sarif.json', sarif(state.data['findings'], self.context))
        render_dashboard(self.context, state)
        return state.data


def main(argv=None):
    parser = argparse.ArgumentParser(description='Groq-assisted multi-agent supply chain vulnerability detection')
    parser.add_argument('--target', type=Path, required=True, help='Local source tree matching the discovery report')
    parser.add_argument('--discovery-dir', type=Path, required=True, help='Directory containing Guardian graph, source analysis and CycloneDX SBOM')
    parser.add_argument('--output', type=Path, default=Path('outputs/detection/juice-shop'))
    parser.add_argument('--model', default='openai/gpt-oss-120b')
    parser.add_argument('--no-llm', action='store_true')
    parser.add_argument('--resume-llm', action='store_true', help='Retry missing Groq reviews from saved state without repeating scanner/API collection')
    parser.add_argument('--api-key-stdin', action='store_true', help='Read the Groq credential from stdin without writing it to disk')
    parser.add_argument('--max-registry-packages', type=int, default=200)
    parser.add_argument('--baseline', type=Path, help='Comparable prior CycloneDX SBOM; differing scopes require review')
    parser.add_argument('--image', help='Optional container image to scan; no image is executed')
    args = parser.parse_args(argv)
    if args.max_registry_packages < 0 or args.max_registry_packages > 2000:
        parser.error('--max-registry-packages must be between 0 and 2000')
    key = None
    if args.api_key_stdin:
        import getpass
        key = getpass.getpass('Groq API key (hidden): ')
    client = GroqClient(key=None if args.no_llm else key, model=args.model)
    if args.no_llm:
        client._key = None
    config = {'max_registry_packages': args.max_registry_packages,
              'baseline': str(args.baseline.resolve()) if args.baseline else None, 'image': args.image}
    try:
        orchestrator = MasterOrchestrator(args.target, args.discovery_dir, args.output, client=client, config=config)
        result = orchestrator.resume_llm_reviews() if args.resume_llm else orchestrator.execute()
    except Exception as error:
        print('Detection failed: ' + redact(str(error)), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['status'], 'summary': result['summary'], 'llm': result['llm'], 'output': str(args.output.resolve())}, indent=2))
    return 0
