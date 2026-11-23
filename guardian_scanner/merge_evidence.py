"""Merge independently generated BOMs by package identity, preserving tool provenance."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote


def flatten(components):
    for item in components:
        yield item
        yield from flatten(item.get('components', []))


def package_key(component):
    purl = component.get('purl') or ''
    if purl:
        decoded = unquote(purl.split('?', 1)[0])
        if decoded.startswith('pkg:github/'):
            body, _, fragment = decoded[len('pkg:github/'):].partition('#')
            if '@' in body:
                path, ref = body.rsplit('@', 1)
                parts = path.split('/')
                if len(parts) >= 2:
                    subpath = '/'.join(parts[2:]) or fragment
                    return 'pkg:github/' + '/'.join(parts[:2]).lower() + '@' + ref + ('#' + subpath if subpath else '')
        return decoded.split('#', 1)[0]
    name = component.get('name', '')
    if component.get('group'):
        name = component['group'] + '/' + name
    return 'unidentified:' + component.get('type', 'library') + ':' + name + '@' + str(component.get('version') or '')


def merge(graph, bom, repository, sources, native=None):
    repository = Path(repository)
    graph = deepcopy(graph)
    original_packages = [n for n in graph['nodes'] if n['kind'] == 'package']
    original_components = {c['bom-ref']: c for c in flatten(bom.get('components', [])) if c.get('bom-ref')}
    native_actions = {a['id']: (a.get('metadata') or {}).get('value') for a in (native or {}).get('artifacts', []) if a.get('type') == 'github-action'}
    graph_nodes = {n['id']: n for n in graph['nodes'] if n['kind'] != 'package'}
    root_id = next(n['id'] for n in graph['nodes'] if n['kind'] == 'repository')
    components, entities, identity_to_id, old_ids, old_refs = {}, {}, {}, {}, {}
    manifests = {}
    for workspace, relative in [('backend', ''), ('frontend', 'frontend')]:
        manifests[workspace] = json.loads((repository / relative / 'package.json').read_text(encoding='utf-8'))

    def relative_path(value):
        value = str(value or '').replace('\\', '/')
        prefix = str(repository).replace('\\', '/').rstrip('/') + '/'
        if value.lower().startswith(prefix.lower()):
            return value[len(prefix):]
        return value.lstrip('/')

    def add_component(component, tool, workspace, evidence, existing=None):
        component = deepcopy(component)
        component.pop('components', None)
        props = component.get('properties', [])
        properties = {p['name']: p['value'] for p in props}
        purl = component.get('purl') or ''
        is_workflow = 'pkg:github/' in purl or workspace == 'workflows'
        is_workflow_file = properties.get('guardian:workflow:file')
        is_project = component.get('type') == 'application' and not purl and not is_workflow
        key = package_key(component)
        if existing and existing.get('versionStatus') == 'declared-only':
            key = 'declaration:' + existing['id']
        if is_workflow_file:
            key = 'workflow-file:' + is_workflow_file
        if key in identity_to_id:
            nid = identity_to_id[key]
            node = entities[nid]
            target = components[nid]
            for field in ['licenses', 'hashes', 'externalReferences']:
                target.setdefault(field, [])
                for value in component.get(field, []):
                    if value not in target[field]:
                        target[field].append(value)
            for value in props:
                if value not in target.setdefault('properties', []):
                    target['properties'].append(value)
        else:
            existing_file = next((n for n in graph_nodes.values() if n.get('path') == is_workflow_file), None) if is_workflow_file else None
            nid = existing_file['id'] if existing_file else 'component:' + hashlib.sha256(key.encode()).hexdigest()[:24]
            identity_to_id[key] = nid
            component['bom-ref'] = nid
            components[nid] = component
            ecosystem = 'githubactions' if is_workflow else purl.split(':', 1)[-1].split('/', 1)[0] if purl else existing.get('ecosystem', 'unknown') if existing else 'unknown'
            name = component.get('name', '')
            if component.get('group') and not name.startswith(component['group'] + '/'):
                name = component['group'] + '/' + name
            node = {'id': nid, 'bomRef': nid, 'name': name,
                    'kind': 'workflow' if is_workflow_file else 'project' if is_project else 'package',
                    'ecosystem': ecosystem, 'type': component.get('type', 'library'),
                    'version': component.get('version'), 'versionStatus': 'reference' if is_workflow else 'lockfile-record',
                    'usage': 'build' if is_workflow else 'unknown', 'direct': None,
                    'purl': purl or None, 'locations': [], 'cataloger': tool,
                    'licenses': [], 'declarations': [], 'tools': [], 'workspaces': []}
            if existing:
                for field in ['versionStatus', 'usage', 'direct', 'declarations', 'locations', 'licenses']:
                    node[field] = deepcopy(existing.get(field, node[field]))
            entities[nid] = node
            if existing_file:
                for field in ['path', 'sha256']:
                    if field in existing_file:
                        node[field] = existing_file[field]
        if tool not in node['tools']:
            node['tools'].append(tool)
        if workspace and workspace not in node['workspaces']:
            node['workspaces'].append(workspace)
        for value in [evidence, properties.get('SrcFile'), properties.get('guardian:workflow:file'), properties.get('cdx:github:workflow:file')]:
            path = relative_path(value)
            if path and path not in node['locations']:
                node['locations'].append(path)
        if is_workflow:
            workflow = node.setdefault('workflow', {'contexts': []})
            for value in [properties.get('guardian:workflow:contexts'), properties.get('cdx:github:workflow:file')]:
                for context in (value or '').split(' | '):
                    context = relative_path(context)
                    if context and context not in workflow['contexts']:
                        workflow['contexts'].append(context)
            for field, prop in [('metadataUrl', 'guardian:workflow:metadataUrl'), ('metadataSha256', 'guardian:workflow:metadataSha256'),
                                ('metadataStatus', 'guardian:workflow:metadataStatus'), ('depth', 'guardian:workflow:depth')]:
                if properties.get(prop):
                    workflow[field] = properties[prop]
        for license_value in components[nid].get('licenses', []):
            value = license_value.get('expression') or license_value.get('license', {}).get('id') or license_value.get('license', {}).get('name')
            if value and value not in node['licenses']:
                node['licenses'].append(value)
        if existing:
            for declaration in existing.get('declarations', []):
                if declaration not in node['declarations']:
                    node['declarations'].append(declaration)
            for location in existing.get('locations', []):
                if location not in node['locations']:
                    node['locations'].append(location)
        return nid

    # Start with actual Syft findings; declaration records are never merged into guessed versions.
    for node in original_packages:
        component = original_components.get(node.get('bomRef'))
        if not component:
            component = {'type': 'library', 'name': node['name'], 'purl': node.get('purl'), 'version': node.get('version')}
            component = {k: v for k, v in component.items() if v is not None}
        uses = native_actions.get(node['id'])
        if uses and '@' in uses:
            component = deepcopy(component)
            path, ref = uses.rsplit('@', 1)
            component.setdefault('properties', []).append({'name': 'guardian:workflow:originalUses', 'value': uses})
            if component.get('version') != ref:
                component['properties'].append({'name': 'guardian:workflow:syftReportedVersion', 'value': component.get('version', '')})
            component['version'] = ref
            component['purl'] = package_key({'purl': 'pkg:github/' + path + '@' + ref})
            node = deepcopy(node)
            node['version'] = ref
            node['purl'] = component['purl']
        workspace = 'frontend' if any(path.startswith('frontend/') for path in node['locations']) else 'workflows' if node['ecosystem'] == 'githubactions' else 'backend'
        nid = add_component(component, 'Syft' if node['cataloger'] != 'Guardian declaration reader' else 'Guardian declarations', workspace, None, node)
        old_ids[node['id']] = nid
        if node.get('bomRef'):
            old_refs[node['bomRef']] = nid
    # Identify repository application roots separately from third-party packages.
    projects = {}
    for workspace, manifest in manifests.items():
        name, version = manifest['name'], manifest.get('version')
        match = next((n for n in entities.values() if n['name'] == name and n['version'] == version and n['ecosystem'] == 'npm'), None)
        if match:
            match['kind'] = 'project'
            components[match['id']]['type'] = 'application'
            projects[workspace] = match['id']
        else:
            nid = 'project:' + workspace
            graph_nodes[nid] = {'id': nid, 'name': name, 'kind': 'project', 'ecosystem': 'npm', 'version': version}
            components[nid] = {'type': 'application', 'name': name, 'version': version, 'bom-ref': nid}
            projects[workspace] = nid
    relationships = {}
    def edge(start, end, kind, tool, evidence=None, **extra):
        if start == end:
            return
        key = (start, end, kind)
        if key not in relationships:
            relationships[key] = {'from': start, 'to': end, 'kind': kind, 'tools': [], 'evidence': evidence or tool, **extra}
        if tool not in relationships[key]['tools']:
            relationships[key]['tools'].append(tool)
    for item in graph['edges']:
        edge(old_ids.get(item['from'], item['from']), old_ids.get(item['to'], item['to']), item['kind'], 'Syft/Guardian', item.get('evidence'),
             **{k: v for k, v in item.items() if k in ['requested', 'usage', 'line']})
    for workspace, nid in projects.items():
        edge(root_id, nid, 'contains', 'Guardian', 'project workspace: ' + workspace)
    tool_counts, diagnostics = [], []
    for source in sources:
        document = json.loads(Path(source['path']).read_text(encoding='utf-8'))
        tool, workspace, evidence = source['tool'], source.get('workspace'), source.get('evidence')
        local_refs = {}
        before_ids = set(graph_nodes) | set(entities)
        for component in flatten(document.get('components', [])):
            if not component.get('bom-ref'):
                continue
            nid = add_component(component, tool, workspace, evidence)
            local_refs[component['bom-ref']] = nid
            if evidence:
                file_node = next((n for n in graph_nodes.values() if n.get('path') == evidence), None)
                if file_node:
                    edge(file_node['id'], nid, 'evidences', tool, evidence)
        metadata_root = document.get('metadata', {}).get('component', {})
        if metadata_root.get('bom-ref'):
            local_refs[metadata_root['bom-ref']] = projects.get(workspace, root_id)
        # cdxgen can put subproject roots under metadata.component.components.
        for component in flatten(metadata_root.get('components', [])):
            if component.get('bom-ref'):
                local_refs[component['bom-ref']] = projects.get('frontend' if component.get('name') == 'frontend' else 'backend', root_id)
        for dependency in document.get('dependencies', []):
            start = local_refs.get(dependency['ref'])
            for ref in dependency.get('dependsOn', []):
                end = local_refs.get(ref)
                if not start or not end:
                    diagnostics.append(f'{tool}: unmapped dependency reference {dependency["ref"]} -> {ref}')
                    continue
                edge(start, end, 'depends-on', tool, evidence)
        tool_counts.append({'tool': tool, 'file': Path(source['path']).name, 'rawComponents': len(list(flatten(document.get('components', [])))),
                            'addedEntities': len((set(graph_nodes) | set(entities)) - before_ids), 'scope': workspace})
    graph_nodes.update(entities)
    graph_nodes[root_id]['name'] = manifests['backend']['name']
    # Scope is taken from lockfile records, not guessed from package names.
    usages = {}
    for workspace, prefix in [('backend', ''), ('frontend', 'frontend/')]:
        lock = json.loads((repository / prefix / 'package-lock.json').read_text(encoding='utf-8'))
        for path, info in lock.get('packages', {}).items():
            if not path or not info.get('version') or 'node_modules/' not in path:
                continue
            name = info.get('name') or path.rsplit('node_modules/', 1)[-1]
            key = 'pkg:npm/' + name + '@' + info['version']
            nid = identity_to_id.get(key)
            if nid:
                usages.setdefault(nid, set()).add('development' if info.get('dev') else 'optional' if info.get('optional') else 'runtime')
                if workspace not in entities[nid]['workspaces']:
                    entities[nid]['workspaces'].append(workspace)
    for nid, values in usages.items():
        entities[nid]['usage'] = 'runtime' if 'runtime' in values else 'optional' if 'optional' in values else 'development'
    # Put each known file/evidence/project/reference node into the standard BOM as well.
    for nid, node in graph_nodes.items():
        if nid == root_id or nid in components:
            continue
        components[nid] = {'type': 'application' if node['kind'] in ('project', 'workflow') else 'file',
                           'name': node['name'], 'bom-ref': nid}
        if node.get('sha256'):
            components[nid]['hashes'] = [{'alg': 'SHA-256', 'content': node['sha256']}]
    for nid, node in entities.items():
        components[nid].setdefault('properties', []).append({'name': 'guardian:sourceTools', 'value': ', '.join(sorted(node['tools']))})
        components[nid]['properties'].append({'name': 'guardian:workspaces', 'value': ', '.join(sorted(node['workspaces']))})
    ref_dependencies = {ref: set() for ref in components}
    ref_dependencies[root_id] = set(projects.values())
    for item in relationships.values():
        if item['kind'] == 'depends-on':
            ref_dependencies.setdefault(item['from'], set()).add(item['to'])
    source_info = json.loads((repository / 'GUARDIAN_SOURCE.json').read_text(encoding='utf-8'))
    final = {'bomFormat': 'CycloneDX', 'specVersion': bom['specVersion'], 'serialNumber': bom['serialNumber'], 'version': 1,
             'metadata': deepcopy(bom['metadata']), 'components': list(components.values()),
             'dependencies': [{'ref': ref, 'dependsOn': sorted(deps)} for ref, deps in sorted(ref_dependencies.items())]}
    final['metadata']['component'] = {'type': 'application', 'name': manifests['backend']['name'],
                                      'version': manifests['backend']['version'], 'bom-ref': root_id,
                                      'externalReferences': [{'type': 'vcs', 'url': source_info['repository'] + '/tree/' + source_info['commit']}]}
    final['metadata'].setdefault('properties', []).append({'name': 'guardian:sourceCommit', 'value': source_info['commit']})
    final['metadata']['tools']['components'].extend([{'type': 'application', 'name': 'npm', 'version': '11.19.1'},
                                                    {'type': 'application', 'name': 'cdxgen', 'version': '12.9.3'},
                                                    {'type': 'application', 'name': 'guardian-workflow-evidence', 'version': '3.0.0'}])
    graph['nodes'] = list(graph_nodes.values())
    graph['edges'] = list(relationships.values())
    graph['project'] = manifests['backend']['name']
    graph['source'] = source_info
    packages = [n for n in entities.values() if n['kind'] == 'package']
    graph['ecosystems'] = dict(Counter(n['ecosystem'] for n in packages).most_common())
    graph['summary'].update({'packages': len(packages), 'distinctPackageIdentities': len(packages),
                              'rawSyftPackageRecords': len(original_packages),
                              'declaredOnlyPackages': sum(n['versionStatus'] == 'declared-only' for n in packages),
                              'recordedVersions': sum(bool(n['version']) for n in packages),
                              'dependencyEdges': sum(e['kind'] == 'depends-on' for e in graph['edges']),
                              'evidenceEdges': sum(e['kind'] in ('declares', 'evidences') for e in graph['edges']),
                              'ecosystems': len(graph['ecosystems']),
                              'applicationPackages': sum(n['ecosystem'] == 'npm' for n in packages),
                              'workflowActions': sum(n['ecosystem'] == 'githubactions' for n in packages),
                              'workflowFiles': sum(n['kind'] == 'workflow' for n in graph['nodes']),
                              'projectApplications': sum(n['kind'] == 'project' for n in graph['nodes'])})
    graph['toolCoverage'] = tool_counts
    graph['warnings'].extend(sorted(set(diagnostics)))
    graph['engine']['name'] = 'Syft + npm + cdxgen + workflow metadata'
    graph['limitations'].append('npm versions were resolved at scan time from current registry metadata. They are not an assertion of the exact environment used by the supplied reference SBOM.')
    return graph, final
