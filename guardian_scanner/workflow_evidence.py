"""Read workflow/action YAML recursively; never execute action code or workflow steps."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.request
from urllib.parse import quote
import uuid


def collect(repository, destination, max_depth=15, max_actions=400):
    import yaml
    repository, destination = Path(repository).resolve(), Path(destination).resolve()
    components, dependencies, nodes, queue, warnings, downloads = {}, {}, {}, [], [], []
    workflow_refs = []
    def component(uses, parent, context, depth):
        if not isinstance(uses, str) or not uses:
            return
        ref = 'action:' + hashlib.sha256(uses.encode()).hexdigest()[:24]
        dependencies.setdefault(parent, set()).add(ref)
        if ref in components:
            nodes[ref]['contexts'].add(context)
            return
        if len(components) >= max_actions:
            warnings.append('Workflow action limit reached; remaining references are incomplete')
            dependencies[parent].discard(ref)
            return
        status = 'local' if uses.startswith('./') else 'container' if uses.startswith('docker://') else 'symbolic-ref'
        item = {'type': 'container' if status == 'container' else 'application', 'bom-ref': ref,
                'name': uses, 'properties': [{'name': 'guardian:workflow:uses', 'value': uses},
                                            {'name': 'guardian:workflow:resolution', 'value': status}]}
        if not uses.startswith(('./', 'docker://')) and '@' in uses:
            path, version = uses.rsplit('@', 1)
            item['version'] = version
            item['name'] = path
            item['purl'] = 'pkg:github/' + quote(path, safe='/') + '@' + quote(version, safe='')
        components[ref] = item
        nodes[ref] = {'uses': uses, 'depth': depth, 'contexts': {context}, 'status': status}
        dependencies.setdefault(ref, set())
        if depth <= max_depth:
            queue.append((ref, uses, context, depth))
        else:
            warnings.append(uses + ': maximum workflow recursion depth reached')

    def uses_in_document(document):
        if not isinstance(document, dict):
            return []
        result = []
        runs = document.get('runs', {})
        if isinstance(runs, dict):
            for step in runs.get('steps', []) or []:
                if isinstance(step, dict) and isinstance(step.get('uses'), str):
                    result.append(step['uses'])
        jobs = document.get('jobs', {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                if isinstance(job.get('uses'), str):
                    result.append(job['uses'])
                for step in job.get('steps', []) or []:
                    if isinstance(step, dict) and isinstance(step.get('uses'), str):
                        result.append(step['uses'])
        return result

    for file in sorted((repository / '.github/workflows').glob('*')):
        if file.suffix not in ('.yml', '.yaml'):
            continue
        relative = file.relative_to(repository).as_posix()
        root_ref = 'workflow:' + hashlib.sha256(relative.encode()).hexdigest()[:24]
        workflow_refs.append(root_ref)
        components[root_ref] = {'type': 'application', 'name': relative, 'bom-ref': root_ref,
                                'properties': [{'name': 'guardian:workflow:file', 'value': relative}]}
        nodes[root_ref] = {'uses': relative, 'depth': 0, 'contexts': {relative}, 'status': 'workflow'}
        dependencies[root_ref] = set()
        try:
            doc = yaml.safe_load(file.read_text(encoding='utf-8-sig'))
            for uses in uses_in_document(doc):
                component(uses, root_ref, relative, 1)
        except (OSError, yaml.YAMLError) as error:
            warnings.append(relative + ': ' + str(error))

    def retrieve(task):
        ref, uses, context, depth = task
        if uses.startswith('docker://') or '${{' in uses:
            return task, None, None, None
        if uses.startswith('./'):
            local = (repository / uses).resolve()
            if not local.is_relative_to(repository):
                return task, None, None, 'Local action path escapes source root'
            for file in [local / 'action.yml', local / 'action.yaml', local]:
                if file.is_file():
                    return task, file.read_text(encoding='utf-8-sig'), str(file), None
            return task, None, None, 'Local action metadata not found'
        if '@' not in uses:
            return task, None, None, 'Action reference lacks a ref'
        path, version = uses.rsplit('@', 1)
        parts = path.split('/')
        if len(parts) < 2 or not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[0]) or not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[1]):
            return task, None, None, 'Unsupported action reference'
        subpath = '/'.join(parts[2:])
        filenames = [subpath] if subpath.endswith(('.yml', '.yaml')) else [(subpath + '/' if subpath else '') + 'action.yml', (subpath + '/' if subpath else '') + 'action.yaml']
        errors = []
        for filename in filenames:
            url = f'https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{quote(version, safe="")}/{filename}'
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'Guardian-workflow-evidence/3'})
                with urllib.request.urlopen(request, timeout=25) as response:
                    data = response.read(2_000_001)
                if len(data) > 2_000_000:
                    return task, None, url, 'Action metadata exceeds the 2 MB limit'
                return task, data.decode('utf-8-sig'), url, None
            except (OSError, UnicodeError) as error:
                errors.append(str(error))
        return task, None, None, '; '.join(errors)

    while queue:
        batch, queue = queue, []
        print(f'[workflows] Reading {len(batch)} action/workflow metadata documents ...', flush=True)
        with ThreadPoolExecutor(max_workers=8) as executor:
            for future in as_completed([executor.submit(retrieve, task) for task in batch]):
                task, text, source, error = future.result()
                ref, uses, context, depth = task
                if error:
                    warnings.append(uses + ': ' + error)
                    nodes[ref]['status'] = 'unresolved'
                    continue
                if text is None:
                    continue
                digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
                downloads.append({'uses': uses, 'url': source, 'sha256': digest})
                components[ref]['properties'].extend([{'name': 'guardian:workflow:metadataUrl', 'value': source},
                                                       {'name': 'guardian:workflow:metadataSha256', 'value': digest}])
                nodes[ref]['status'] = 'metadata-read'
                try:
                    document = yaml.safe_load(text)
                    for child in uses_in_document(document):
                        if child.startswith('./') and not uses.startswith('./'):
                            # Relative paths in remote actions depend on the calling checkout.
                            warnings.append(uses + ': relative child action ' + child + ' retained as unresolved context')
                            continue
                        component(child, ref, context, depth + 1)
                except yaml.YAMLError as error:
                    warnings.append(uses + ': ' + str(error))
    for ref, item in components.items():
        item['properties'].extend([{'name': 'guardian:workflow:contexts', 'value': ' | '.join(sorted(nodes[ref]['contexts']))},
                                   {'name': 'guardian:workflow:depth', 'value': str(nodes[ref]['depth'])},
                                   {'name': 'guardian:workflow:metadataStatus', 'value': nodes[ref]['status']}])
    root = {'type': 'application', 'name': 'juice-shop-workflows', 'bom-ref': 'guardian:workflow-root'}
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': 'urn:uuid:' + str(uuid.uuid4()), 'version': 1,
           'metadata': {'timestamp': datetime.now(timezone.utc).isoformat(), 'component': root,
                        'tools': {'components': [{'type': 'application', 'name': 'guardian-workflow-evidence', 'version': '3.0.0'}]}},
           'components': list(components.values()),
           'dependencies': [{'ref': root['bom-ref'], 'dependsOn': workflow_refs}] +
                           [{'ref': ref, 'dependsOn': sorted(children)} for ref, children in sorted(dependencies.items())]}
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'workflow-recursive.cdx.json').write_text(json.dumps(bom, indent=2) + '\n', encoding='utf-8')
    details = {'workflows': len(workflow_refs), 'actionReferences': len(components) - len(workflow_refs),
               'metadataDocumentsRead': len(downloads), 'warnings': warnings, 'metadata': downloads,
               'limitations': ['Only workflow uses and composite action uses are followed; bundled JavaScript action dependencies and arbitrary shell downloads are not inferred.',
                               'Mutable refs are preserved. Metadata content SHA-256 is recorded; commit resolution is not claimed.']}
    (destination / 'workflow-resolution.json').write_text(json.dumps(details, indent=2) + '\n', encoding='utf-8')
    return details
