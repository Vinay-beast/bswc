"""Resolved, multi-tool Juice Shop scan. Raw tool outputs are retained beside the union BOM."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile

from collect_juice_evidence import collect
from merge_evidence import merge
from scanner import RepositoryScanner, save
from workflow_evidence import collect as collect_workflows

ROOT = Path(__file__).resolve().parent


def render(graph, bom, source, destination, workflows=None):
    template = (ROOT / 'scanner_dashboard.html').read_text(encoding='utf-8')
    for marker, data in [('GRAPH', graph), ('SBOM', bom), ('SOURCE', source), ('WORKFLOWS', workflows)]:
        template = template.replace(f'/*__{marker}__*/null', json.dumps(data, ensure_ascii=False).replace('<', '\\u003c'))
    (destination / 'dashboard.html').write_text(template, encoding='utf-8')


def execute(repository, output, syft=None, excludes=(), timeout=900, reference=None):
    repository, output = Path(repository).resolve(), Path(output).resolve()
    if output == repository or output in repository.parents:
        raise ValueError('Output must not overwrite the source repository root or its ancestor')
    excludes = list(excludes)
    if output.is_relative_to(repository):
        excludes.append(output.relative_to(repository).as_posix() + '/**')
    source_marker = repository / 'GUARDIAN_SOURCE.json'
    manifest = json.loads((repository / 'package.json').read_text(encoding='utf-8'))
    if manifest.get('name') != 'juice-shop' or not source_marker.exists():
        raise ValueError('Full scan targets the acquired, provenance-recorded Juice Shop source. Run python fetch_juice_shop.py first.')
    with tempfile.TemporaryDirectory(prefix='guardian-full-') as folder:
        stage = Path(folder)
        metadata = collect(repository, stage)
        workflow = collect_workflows(repository, stage)
        metadata['records'].append({'tool': 'Guardian workflow metadata', 'path': 'workflow-recursive.cdx.json',
                                    'workspace': 'workflows', 'evidence': '.github/workflows'})
        base = stage / 'base'
        RepositoryScanner(repository, base, syft, excludes, timeout).execute()
        graph = json.loads((base / 'dependency-graph.json').read_text(encoding='utf-8'))
        bom = json.loads((base / 'cyclonedx-sbom.json').read_text(encoding='utf-8'))
        sources = [{**record, 'path': stage / record['path']} for record in metadata['records']]
        native = json.loads((base / 'syft-sbom.json').read_text(encoding='utf-8'))
        graph, bom = merge(graph, bom, repository, sources, native)
        graph['toolDiagnostics'] = metadata['diagnostics']
        graph['workflowCoverage'] = {key: value for key, value in workflow.items() if key != 'metadata'}
        graph['warnings'].extend(record['tool'] + ': ' + record['message'] for record in metadata['diagnostics'])
        graph['warnings'].extend(workflow['warnings'])
        graph['limitations'] = [v for v in graph['limitations'] if not v.startswith('Docker base images and workflow actions')]
        graph['limitations'].extend(workflow['limitations'])
        graph['limitations'].append('Container base images are references only; their OS packages are not included in this application/workflow SBOM.')
        source = json.loads((base / 'source-analysis.json').read_text(encoding='utf-8'))
        trace = json.loads((base / 'agent-trace.json').read_text(encoding='utf-8'))
        trace.update({'engine': graph['engine'], 'source': metadata['source'], 'tools': graph['toolCoverage'],
                      'toolDiagnostics': metadata['diagnostics'], 'workflowCoverage': graph['workflowCoverage'],
                      'completedAt': datetime.now(timezone.utc).isoformat()})
        for path in base.iterdir():
            if path.is_file():
                shutil.copy2(path, stage / path.name)
        save(stage / 'dependency-graph.json', graph)
        save(stage / 'cyclonedx-sbom.json', bom)
        save(stage / 'agent-trace.json', trace)
        save(stage / 'evidence-index.json', metadata)
        if reference:
            from compare_boms import compare
            comparison = compare(reference, stage / 'cyclonedx-sbom.json', stage / 'reference-comparison.json')
            graph['referenceComparison'] = {'referencePackageRecords': comparison['reference']['packageRecords'],
                                             'referenceUniqueIdentities': comparison['reference']['uniqueNameVersionPairs'],
                                             'matchingExactIdentities': comparison['commonExactNameVersionPairs'],
                                             'missingExactIdentities': len(comparison['referenceOnlyExactVersions'])}
            save(stage / 'dependency-graph.json', graph)
            target_file = ROOT / '.guardian-target.json'
            if target_file.exists():
                target = json.loads(target_file.read_text(encoding='utf-8'))
                target['referencePath'] = str(Path(reference).resolve())
                save(target_file, target)
        render(graph, bom, source, stage, json.loads((stage / 'workflow-recursive.cdx.json').read_text(encoding='utf-8')))
        output.mkdir(parents=True, exist_ok=True)
        for path in sorted(stage.iterdir(), key=lambda p: p.name == 'dashboard.html'):
            if path.is_file():
                shutil.copy2(path, output / path.name)
    return graph
