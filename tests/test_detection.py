"""Detect-stage contracts and security boundaries. All network/model results are synthetic fixtures."""
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from agents.detect.adapters import osv_findings, osv_scanner_findings, run_tool, trivy_findings
from agents.detect.core import AgentResult, WorkflowState, finding, redact, write_json
from agents.detect.groq_client import GroqClient
from agents.detect.orchestrator import MasterOrchestrator, followups, merge_findings, sarif
from agents.detect.specialists import DependencyAnalysisAgent, DiscoveryAgent, similar_name, workflow_rules


def package(pid='lib', name='example-lib', version='1.0.0'):
    return {'id': pid, 'name': name, 'version': version, 'kind': 'package', 'ecosystem': 'npm',
            'purl': f'pkg:npm/{name}@{version}'}


def advisory(vid='GHSA-fixture', withdrawn=False):
    result = {'id': vid, 'summary': 'Synthetic advisory for testing', 'aliases': ['CVE-2024-0001'],
              'database_specific': {'severity': 'HIGH'}, 'affected': [
                  {'package': {'name': 'example-lib'}, 'ranges': [{'events': [{'introduced': '0'}, {'fixed': '1.1.0'}]}]},
                  {'package': {'name': 'other-lib'}, 'ranges': [{'events': [{'fixed': '99.0.0'}]}]}]}
    if withdrawn:
        result['withdrawn'] = '2024-01-01T00:00:00Z'
    return result


def test_advisory_alias_dedup_is_per_package_and_preserves_sources():
    first = finding('known-vulnerability', 'first', tool='OSV', package_id='lib-a', advisory_id='CVE-2024-0001',
                    aliases=['GHSA-fixture'], severity='MEDIUM', evidence=[{'source': 'OSV'}])
    second = finding('known-vulnerability', 'second', tool='Trivy', package_id='lib-a', advisory_id='GHSA-fixture',
                     aliases=['CVE-2024-0001'], severity='HIGH', evidence=[{'source': 'Trivy'}])
    different = finding('known-vulnerability', 'third', tool='OSV', package_id='lib-b', advisory_id='CVE-2024-0001')
    result = merge_findings([first, second, different])
    assert len(result) == 2
    merged = next(f for f in result if f['package_id'] == 'lib-a')
    assert set(merged['tools']) == {'OSV', 'Trivy'}
    assert merged['severity'] == 'HIGH'
    assert len(merged['evidence']) == 2


def test_osv_queries_exact_identity_and_filters_other_package_fixes(tmp_path):
    seen = []
    def request(url, payload=None):
        seen.append((url, payload))
        return {'results': [{'vulns': [{'id': 'GHSA-fixture'}]}]} if url.endswith('querybatch') else advisory()
    findings, coverage = osv_findings([package()], tmp_path, request)
    assert seen[0][1]['queries'][0]['package']['purl'] == 'pkg:npm/example-lib@1.0.0'
    assert coverage['status'] == 'complete'
    assert findings[0]['fixed_versions'] == ['1.1.0']
    assert findings[0]['status'] == 'database-match'
    assert findings[0]['reachability']['status'] == 'unknown'


def test_osv_withdrawn_advisory_not_reported(tmp_path):
    def request(url, payload=None):
        return {'results': [{'vulns': [{'id': 'GHSA-fixture'}]}]} if url.endswith('querybatch') else advisory(withdrawn=True)
    result, _ = osv_findings([package()], tmp_path, request)
    assert result == []


def test_osv_failure_is_incomplete_not_clean(tmp_path):
    def request(url, payload=None):
        raise OSError('network unavailable')
    findings, coverage = osv_findings([package()], tmp_path, request)
    assert not findings
    assert coverage['status'] == 'partial'
    assert coverage['queried_packages'] == 0
    assert coverage['errors']


def test_osv_unversioned_packages_are_coverage_gaps(tmp_path):
    unresolved = package()
    unresolved['version'] = None
    result, coverage = osv_findings([unresolved], tmp_path, lambda *args: pytest.fail('Should not query unresolved version'))
    assert result == []
    assert coverage['status'] == 'partial'
    assert coverage['unversioned_packages_not_matched'] == 1


def test_osv_pagination_is_followed(tmp_path):
    def request(url, payload=None):
        if url.endswith('querybatch'):
            return {'results': [{'vulns': [{'id': 'GHSA-one'}], 'next_page_token': 'page-2'}]}
        if url.endswith('/query'):
            assert payload['page_token'] == 'page-2'
            return {'vulns': [{'id': 'GHSA-two'}]}
        return advisory(url.rsplit('/', 1)[-1])
    result, coverage = osv_findings([package()], tmp_path, request)
    assert coverage['advisories_loaded'] == 2
    assert len(result) == 2


def test_osv_and_trivy_normalizers_map_to_inventory_ids():
    node = package()
    osv = {'results': [{'packages': [{'package': {'name': node['name'], 'version': node['version']}, 'vulnerabilities': [advisory()]}]}]}
    trivy = {'Results': [{'Target': 'fixture', 'Vulnerabilities': [{'PkgName': node['name'], 'InstalledVersion': node['version'],
               'VulnerabilityID': 'CVE-2024-0001', 'Severity': 'HIGH'}]}]}
    assert osv_scanner_findings(osv, [node])[0]['package_id'] == 'lib'
    assert trivy_findings(trivy, [node])[0]['package_id'] == 'lib'
    assert len(merge_findings([*osv_scanner_findings(osv, [node]), *trivy_findings(trivy, [node])])) == 1


def test_dependency_paths_are_cycle_safe_and_imports_are_not_reachability():
    a, b = package('a', 'direct-lib'), package('b', 'indirect-lib')
    nodes = {'root': {'id': 'root', 'kind': 'project', 'name': 'app'}, 'a': a, 'b': b}
    context = {'nodes': nodes, 'graph': {'nodes': list(nodes.values()), 'edges': [
        {'from': 'root', 'to': 'a', 'kind': 'depends-on'}, {'from': 'a', 'to': 'b', 'kind': 'depends-on'},
        {'from': 'b', 'to': 'a', 'kind': 'depends-on'}, {'from': 'manifest', 'to': 'a', 'kind': 'declares'}]},
        'source': {'imports': [{'path': 'main.js', 'line': 1, 'reference': 'direct-lib'}]}}
    items = [finding('known-vulnerability', 'direct', tool='OSV', package_id='a'), finding('known-vulnerability', 'indirect', tool='OSV', package_id='b')]
    DependencyAnalysisAgent().run(context, items)
    assert items[0]['dependency_relationship'] == 'direct'
    assert items[1]['dependency_relationship'] == 'transitive'
    assert items[1]['dependency_paths'][0]['names'] == ['app', 'direct-lib', 'indirect-lib']
    assert items[0]['reachability']['status'] == 'import-observed'
    assert 'not vulnerable-function' in items[0]['reachability']['reason']


def test_followups_reject_shell_tools_and_unknown_packages(tmp_path):
    state = WorkflowState(tmp_path, tmp_path / 'out', {})
    context = {'nodes': {'lib': package()}, 'dependency_paths': {'lib': [['root', 'lib']]}}
    followups(context, state, [{'status': 'ok', 'analysis': {'requested_followups': [
        {'check': 'shell', 'package_id': 'lib', 'command': 'unsafe'},
        {'check': 'dependency_path', 'package_id': 'missing'},
        {'check': 'dependency_path', 'package_id': 'lib'}]}}])
    assert [r['status'] for r in state.data['followups']] == ['rejected', 'rejected', 'complete']


def test_secret_redaction_before_persistence(tmp_path):
    secret = 'gsk_' + 'a' * 40
    path = tmp_path / 'report.json'
    write_json(path, {'config': {'api_key': secret}, 'message': 'Bearer sensitive', 'nested': [secret]})
    text = path.read_text(encoding='utf-8')
    assert secret not in text
    assert 'Bearer sensitive' not in text
    assert '[REDACTED]' in text


def test_model_cannot_add_new_findings_and_key_is_not_in_prompt():
    payloads = []
    def transport(payload):
        payloads.append(payload)
        return {'choices': [{'message': {'content': json.dumps({'summary': 'review', 'finding_reviews': [
            {'finding_id': 'existing', 'priority': 'P1'}, {'finding_id': 'invented', 'priority': 'P0'}]})}}]}
    secret = 'gsk_' + 'b' * 40
    client = GroqClient(secret, transport=transport)
    item = finding('code-security', 'Fixture pattern', tool='fixture')
    item['id'] = 'existing'
    result = client.review('CodeSecurityAgent', [item], {})
    assert [r['finding_id'] for r in result['analysis']['finding_reviews']] == ['existing']
    assert secret not in json.dumps(payloads)
    assert 'UNTRUSTED DATA' in payloads[0]['messages'][0]['content']


def test_missing_model_configuration_does_not_invent_a_review():
    with patch.dict(os.environ, {}, clear=True):
        client = GroqClient()
        assert client.review('agent', [], {})['status'] == 'disabled'
        assert client.calls == 0


def test_external_tool_does_not_receive_model_credential(tmp_path):
    captured = {}
    def process(command, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout='{}', stderr='')
    with patch.dict(os.environ, {'GROQ_API_KEY': 'fixture-value'}), patch('agents.detect.adapters.tool_path', return_value='fixture-exe'), patch('agents.detect.adapters.subprocess.run', side_effect=process):
        assert run_tool('fixture', [], tmp_path / 'tool.json')['status'] == 'ok'
    assert 'GROQ_API_KEY' not in captured['env']


def test_workflow_pinning_rules_preserve_sha_and_detect_tag(tmp_path):
    folder = tmp_path / '.github/workflows'
    folder.mkdir(parents=True)
    folder.joinpath('ci.yml').write_text('permissions: read-all\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@' + 'a'*40 + '\n      - uses: actions/setup-node@v4\n', encoding='utf-8')
    result = workflow_rules(tmp_path)
    assert len(result) == 1
    assert result[0]['evidence'][0]['rule'] == 'mutable-action-ref'


def test_unparseable_workflow_is_reported_as_gap(tmp_path):
    folder = tmp_path / '.github/workflows'
    folder.mkdir(parents=True)
    folder.joinpath('bad.yml').write_text('jobs: [bad', encoding='utf-8')
    result = workflow_rules(tmp_path)
    assert result[0]['status'] == 'coverage-gap'


def test_similarity_is_candidate_signal_not_malware_verdict():
    assert similar_name(package(name='express')) is None
    assert similar_name(package(name='expres'))['similar_to'] == 'express'
    assert similar_name(package(name='@internal/express')) is None


def test_discovery_refuses_changed_manifests(tmp_path):
    target, output = tmp_path / 'repo', tmp_path / 'discovery'
    target.mkdir()
    output.mkdir()
    target.joinpath('package.json').write_text('{}', encoding='utf-8')
    graph = {'analyzedPath': str(target), 'nodes': [], 'edges': []}
    source = {'files': [{'kind': 'manifest', 'path': 'package.json', 'sha256': 'wrong'}], 'summary': {'files': 1}}
    write_json(output / 'dependency-graph.json', graph)
    write_json(output / 'source-analysis.json', source)
    with pytest.raises(ValueError, match='changed'):
        DiscoveryAgent().run({'target': target, 'discovery_dir': output})


def test_sarif_keeps_evidence_status_distinct_from_severity():
    item = finding('code-security', 'Potential issue', tool='fixture', severity='HIGH', location={'path': 'main.js', 'line': 4})
    result = sarif([item], {})
    entry = result['runs'][0]['results'][0]
    assert entry['properties']['status'] == 'potential'
    assert entry['locations'][0]['physicalLocation']['region']['startLine'] == 4


def test_blocked_tool_is_not_recorded_as_success(tmp_path):
    error = OSError(4551, 'Application Control blocked this file')
    error.winerror = 4551
    with patch('agents.detect.adapters.tool_path', return_value='fixture.exe'), patch('agents.detect.adapters.subprocess.run', side_effect=error):
        result = run_tool('fixture', [], tmp_path / 'tool.json')
    assert result['status'] == 'blocked'


def test_tool_empty_output_does_not_reuse_previous_run(tmp_path):
    output = tmp_path / 'tool.json'
    output.write_text('{"stale":true}', encoding='utf-8')
    with patch('agents.detect.adapters.tool_path', return_value='fixture.exe'), patch('agents.detect.adapters.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='', stderr='')):
        result = run_tool('fixture', [], output)
    assert result['status'] == 'failed'
    assert result['reason'] == 'Tool produced no output'


def test_master_pipeline_keeps_partial_coverage_and_emits_reports(tmp_path):
    target, discovery, output = tmp_path / 'repo', tmp_path / 'discovery', tmp_path / 'detect'
    target.mkdir()
    discovery.mkdir()
    node = package()
    graph = {'analyzedPath': str(target), 'nodes': [{'id': 'app', 'name': 'app', 'kind': 'project'}, node],
             'edges': [{'from': 'app', 'to': 'lib', 'kind': 'declares'}, {'from': 'app', 'to': 'lib', 'kind': 'depends-on'}]}
    write_json(discovery / 'dependency-graph.json', graph)
    write_json(discovery / 'source-analysis.json', {'files': [], 'summary': {'files': 0}, 'imports': []})
    write_json(discovery / 'cyclonedx-sbom.json', {'bomFormat': 'CycloneDX', 'components': []})
    item = finding('known-vulnerability', 'Fixture advisory', tool='fixture', package_id='lib',
                   advisory_id='CVE-2024-0001', status='database-match', severity='HIGH')
    def transport(payload):
        return {'choices': [{'message': {'content': json.dumps({'summary': 'Fixture review', 'requested_followups': None})}}]}
    client = GroqClient(transport=transport)
    with patch('agents.detect.orchestrator.VulnerabilityDetectionAgent.run', return_value=AgentResult('VulnerabilityDetectionAgent', [item], {'osv': {'status': 'complete'}})), \
         patch('agents.detect.orchestrator.CodeSecurityAgent.run', return_value=AgentResult('CodeSecurityAgent', coverage={'static': {'status': 'complete'}})), \
         patch('agents.detect.orchestrator.SupplyChainAgent.run', return_value=AgentResult('SupplyChainAgent', coverage={'sandbox': {'status': 'not-run'}})):
        state = MasterOrchestrator(target, discovery, output, client=client).execute()
    assert state['status'] == 'partial'
    assert len(state['agents']) == 6
    assert all(agent['status'] == 'complete' for agent in state['agents'].values())
    assert state['summary']['direct_vulnerability_matches'] == 1
    assert state['llm']['successful_calls'] == 8
    for name in ('workflow-state.json', 'coverage.json', 'findings.json', 'report.sarif.json', 'dashboard.html'):
        assert (output / name).is_file()
    html = (output / 'dashboard.html').read_text(encoding='utf-8')
    assert '/*__DETECTION__*/null' not in html
    assert 'CVE-2024-0001' in html
