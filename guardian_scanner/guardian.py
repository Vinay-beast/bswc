#!/usr/bin/env python3
"""Guardian: multi-ecosystem Syft scanner, CycloneDX SBOM, and supply chain view.

General scans read existing source evidence without running repository code.
The original two-workspace npm workflow remains available via --engine legacy.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import pathlib
import re
import subprocess
import sys
import uuid
from urllib.parse import quote

ROOT = pathlib.Path(__file__).resolve().parent
WORKSPACES = [('backend', ''), ('frontend', 'frontend')]
REPO_URL = 'https://github.com/juice-shop/juice-shop'


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def npm_purl(name, version=None):
    out = 'pkg:npm/' + quote(name, safe='/')
    return out + ('@' + quote(version, safe='') if version else '')


class DiscoveryAgent:
    def __init__(self, repository):
        self.repository = pathlib.Path(repository)

    def run(self):
        result = {}
        for workspace, relative in WORKSPACES:
            base = self.repository / relative
            manifest = base / 'package.json'
            if not manifest.exists():
                raise FileNotFoundError(f'No manifest at {manifest}')
            result[workspace] = {'base': base, 'manifest': load_json(manifest), 'lockfile': base/'package-lock.json'}
        return result


class NpmResolverAgent:
    def __init__(self, workspaces):
        self.workspaces = workspaces
        self.warnings = []

    def create_lockfiles(self):
        for work, ws in self.workspaces.items():
            if ws['lockfile'].exists():
                continue
            cmd = ['npm', 'install', '--package-lock-only', '--package-lock=true',
                   '--ignore-scripts', '--no-audit', '--no-fund', '--legacy-peer-deps']
            print(f'[{work}] Resolving dependency metadata via npm (lifecycle scripts disabled) ...', flush=True)
            result = subprocess.run(cmd, cwd=str(ws['base']), text=True, capture_output=True)
            if result.returncode:
                self.warnings.append(f'{work}: npm resolution failed (exit {result.returncode}): '
                                     + (result.stderr or result.stdout)[-700:])
                print(self.warnings[-1], file=sys.stderr)

    @staticmethod
    def find_package_path(installed, origin, dep):
        """Implement npm nested node_modules lookup; don't invent edges if not found."""
        cursor = origin
        while True:
            candidate = f'{cursor}/node_modules/{dep}' if cursor else f'node_modules/{dep}'
            if candidate in installed:
                return candidate
            if not cursor:
                return None
            if '/node_modules/' in cursor:
                cursor = cursor.rsplit('/node_modules/', 1)[0]
            else:
                cursor = ''

    @staticmethod
    def installed_name(path, info):
        return info.get('name') or path.rsplit('node_modules/', 1)[-1]

    def run(self):
        nodes = []
        edges = []
        for work, ws in self.workspaces.items():
            manifest = ws['manifest']
            app = f'app:{work}'
            nodes.append({'id': app, 'name': manifest.get('name', work),
                          'version': manifest.get('version'), 'workspace': work,
                          'category': 'application', 'usage': 'runtime',
                          'source': str((ws['base']/'package.json').name if work=='backend' else 'frontend/package.json'),
                          'resolved': True, 'direct': True,
                          'license': manifest.get('license'), 'declaredRange': None,
                          'evidence': 'package.json'})
            if ws['lockfile'].exists():
                subnodes, subedges = self._from_lock(work, ws, app)
                nodes.extend(subnodes); edges.extend(subedges)
            else:
                self.warnings.append(f'{work}: no package-lock.json; only direct declarations available, exact installed versions and transitive packages unknown')
                subnodes, subedges = self._from_manifest(work, manifest, app)
                nodes.extend(subnodes); edges.extend(subedges)
        # Connect the frontend application as a workspace component.
        edges.append({'from': 'app:backend', 'to': 'app:frontend', 'kind': 'workspace',
                      'requested': None, 'evidence': 'repository/frontend/package.json'})
        unique = list({(e['from'], e['to'], e['kind']): e for e in edges}.values())
        return nodes, unique

    def _from_manifest(self, work, manifest, app):
        nodes, edges = [], []
        for field, usage in [('dependencies', 'runtime'), ('devDependencies', 'development')]:
            for name, rng in sorted(manifest.get(field, {}).items()):
                nid = f'declared:{work}:{usage}:{name}'
                nodes.append({'id': nid, 'name': name, 'version': None,
                              'declaredRange': rng, 'workspace': work, 'category': 'library',
                              'usage': usage, 'source': ('frontend/' if work=='frontend' else '') + 'package.json',
                              'resolved': False, 'direct': True, 'license': None,
                              'evidence': f'{field}[{name!r}]'})
                edges.append({'from': app, 'to': nid, 'kind': 'direct', 'requested': rng,
                              'evidence': f'{field}[{name!r}]'})
        return nodes, edges

    def _from_lock(self, work, ws, app):
        content = load_json(ws['lockfile'])
        packages = content.get('packages')
        if not isinstance(packages, dict):
            self.warnings.append(f'{work}: unsupported lockfile structure, falling back to declarations')
            return self._from_manifest(work, ws['manifest'], app)
        installed = {k:v for k,v in packages.items() if k and 'node_modules/' in k and isinstance(v, dict)}
        nodes, edges = [], []
        manifest = ws['manifest']
        runtime = manifest.get('dependencies', {})
        dev = manifest.get('devDependencies', {})
        path_to_id = {path: f'lock:{work}:{path}' for path in installed}
        for path, info in sorted(installed.items()):
            name = self.installed_name(path, info)
            is_direct = self.find_package_path(installed, '', name) == path and name in (runtime | dev)
            requested = runtime.get(name) or dev.get(name) if is_direct else None
            usage = ('runtime' if name in runtime and is_direct else
                     'development' if info.get('dev') else 'runtime')
            nodes.append({'id': path_to_id[path], 'name': name,
                          'version': info.get('version'), 'declaredRange': requested,
                          'workspace': work, 'category': 'library', 'usage': usage,
                          'source': (f'{work}/' if work=='frontend' else '') + 'package-lock.json:' + path,
                          'resolved': bool(info.get('version')), 'direct': bool(is_direct),
                          'license': info.get('license'), 'evidence': 'package-lock.json'})
        roots = [('dependencies', runtime), ('devDependencies', dev)]
        for field, deps in roots:
            for name, spec in deps.items():
                path = self.find_package_path(installed, '', name)
                if path:
                    edges.append({'from': app, 'to': path_to_id[path], 'kind': 'direct',
                                  'requested': spec, 'evidence': f'package.json:{field}'})
                else:
                    self.warnings.append(f'{work}: declared {name} ({spec}) not found in lockfile')
        for path, info in installed.items():
            for field, kind in [('dependencies','transitive'),('optionalDependencies','optional')]:
                for name, spec in info.get(field, {}).items():
                    child = self.find_package_path(installed, path, name)
                    if child:
                        edges.append({'from': path_to_id[path], 'to': path_to_id[child],
                                      'kind': kind, 'requested': spec, 'evidence': 'package-lock.json'})
        return nodes, edges


class SBOMAgent:
    @staticmethod
    def run(nodes, edges):
        components = []
        for n in nodes:
            props = [
                {'name': 'guardian:workspace', 'value': n['workspace']},
                {'name': 'guardian:usage', 'value': n['usage']},
                {'name': 'guardian:resolution', 'value': 'resolved' if n['resolved'] else 'declared-only'},
                {'name': 'guardian:manifestOrLockPath', 'value': n['source']},
            ]
            if n.get('declaredRange'):
                props.append({'name': 'guardian:versionConstraint', 'value': n['declaredRange']})
            item = {'type': n['category'], 'bom-ref': n['id'], 'name': n['name'], 'properties': props}
            if n.get('version'):
                item['version'] = n['version']
            if n['category']=='library':
                item['purl'] = npm_purl(n['name'], n['version'] if n['resolved'] else None)
            if n.get('license') and isinstance(n['license'], str):
                item['licenses'] = [{'license': {'id': n['license']}}] if re.fullmatch(r'[A-Za-z0-9-.+]+', n['license']) else []
            components.append(item)
        by_id = {n['id']: [] for n in nodes}
        for e in edges:
            if e['from'] in by_id and e['to'] in by_id:
                by_id[e['from']].append(e['to'])
        return {'bomFormat':'CycloneDX', 'specVersion':'1.6',
                'serialNumber':'urn:uuid:' + str(uuid.uuid4()), 'version':1,
                'metadata': {'timestamp':datetime.now(timezone.utc).isoformat(timespec='seconds'),
                             'tools':{'components':[{'type':'application','name':'guardian-sbom-graph', 'version':'1.0.0'}]},
                             'component': next(c for c in components if c['bom-ref']=='app:backend'),
                             'properties': [
                                 {'name':'guardian:sourceRepository','value':REPO_URL},
                                 {'name':'guardian:unresolvedVersionsPresent',
                                  'value':'true' if any(not n['resolved'] for n in nodes if n['category']=='library') else 'false'}]},
                'components':[c for c in components if c['bom-ref']!='app:backend'],
                'dependencies':[{'ref':pid,'dependsOn':sorted(set(dests))} for pid,dests in by_id.items()]}


class GraphAgent:
    @staticmethod
    def run(nodes, edges, warnings, repo):
        kinds = Counter(n['usage'] for n in nodes if n['category']=='library')
        resolved = sum(n['resolved'] for n in nodes if n['category']=='library')
        # Count unique, fully-known name+version pairs separately from path-distinct installations.
        return {'schema':'guardian-graph-1', 'project':'OWASP Juice Shop',
                'repository':REPO_URL,'analyzedPath':str(repo),
                'generatedAt':datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'summary': {'components':len(nodes), 'packages':len(nodes)-2, 'edges':len(edges),
                            'runtimePackages':kinds['runtime'], 'developmentPackages':kinds['development'],
                            'resolvedPackages':resolved, 'unresolvedPackages':len(nodes)-2-resolved,
                            'transitiveEdges':sum(e['kind'] in ('transitive','optional') for e in edges)},
                'warnings':warnings, 'nodes':nodes, 'edges':edges}


class ReportAgent:
    @staticmethod
    def run(graph, dest):
        template = (ROOT/'dashboard_template.html').read_text(encoding='utf-8')
        embedded = json.dumps(graph, ensure_ascii=False).replace('</','<\\/')
        sbom = json.dumps(load_json(dest/'cyclonedx-sbom.json'), ensure_ascii=False).replace('</','<\\/')
        report = template.replace('/*__EMBED_GRAPH__*/null', embedded).replace('/*__EMBED_SBOM__*/null', sbom)
        (dest/'dashboard.html').write_text(report, encoding='utf-8')


class GuardianOrchestrator:
    """One controller, multiple evidence-producing agents, with explicit decisions."""
    def __init__(self, repo, out, resolve=False):
        self.repo = pathlib.Path(repo)
        self.out = pathlib.Path(out).resolve()
        self.resolve = resolve
        self.trace = []

    def execute(self):
        workspaces = DiscoveryAgent(self.repo).run()
        self.trace.append({'agent':'DiscoveryAgent', 'action':'inspect_manifests',
                           'evidence':[str(ws['base']/'package.json') for ws in workspaces.values()],
                           'result':'backend and frontend workspaces detected'})
        resolver = NpmResolverAgent(workspaces)
        missing = [name for name, ws in workspaces.items() if not ws['lockfile'].exists()]
        if missing and self.resolve:
            self.trace.append({'agent':'GuardianOrchestrator','decision':'resolve_missing_lockfiles',
                               'reason':'Exact transitive versions need package-lock.json',
                               'workspaces':missing, 'safety':'npm --ignore-scripts'})
            resolver.create_lockfiles()
        elif missing:
            self.trace.append({'agent':'GuardianOrchestrator','decision':'manifest_only',
                               'reason':'No lockfiles found; --resolve not requested',
                               'workspaces':missing, 'consequence':'Transitive dependencies not determined'})
        else:
            self.trace.append({'agent':'GuardianOrchestrator','decision':'consume_existing_lockfiles',
                               'reason':'Lockfiles already exist; npm execution unnecessary'})
        nodes, edges = resolver.run()
        self.trace.append({'agent':'NpmResolverAgent','action':'parse_dependency_evidence',
                           'components':len(nodes), 'edges':len(edges), 'warnings':resolver.warnings})
        self.out.mkdir(parents=True, exist_ok=True)
        bom = SBOMAgent.run(nodes, edges)
        save_json(self.out/'cyclonedx-sbom.json',bom)
        self.trace.append({'agent':'SBOMAgent', 'action':'produce_cyclonedx_1.6',
                           'status':'written', 'artifact':'cyclonedx-sbom.json'})
        graph = GraphAgent.run(nodes, edges, resolver.warnings, self.repo)
        save_json(self.out/'dependency-graph.json',graph)
        ReportAgent.run(graph,self.out)
        self.trace.append({'agent':'GraphAgent', 'action':'visualize_same_dependency_data',
                           'status':'written', 'artifacts':['dependency-graph.json','dashboard.html']})
        save_json(self.out/'agent-trace.json',{'schema':'guardian-trace-1','steps':self.trace,
                       'nextAction': ('Review the visualized dependency graph and optionally run CVE matching'
                                      if graph['summary']['unresolvedPackages']==0 else
                                      'Resolve npm lockfiles to obtain exact installed versions and transitive paths')})
        return graph


def main(argv=None):
    parser = argparse.ArgumentParser(description='General repository scanner, CycloneDX SBOM and supply chain view powered by Syft')
    target_file = ROOT/'.guardian-target.json'
    default_target = pathlib.Path(load_json(target_file)['repositoryPath']) if target_file.exists() else ROOT/'targets'/'juice-shop'
    parser.add_argument('--repo', type=pathlib.Path, default=default_target, help='Repository directory; defaults to the acquired Juice Shop source')
    parser.add_argument('--out', type=pathlib.Path, default=ROOT/'output', help='Output folder')
    parser.add_argument('--engine', choices=['syft', 'legacy'], default='syft', help='Syft scans general repositories; legacy retains the original two-workspace npm demo')
    parser.add_argument('--syft', help='Path to the Syft executable (otherwise PATH or the locally installed pinned release)')
    parser.add_argument('--exclude', action='append', default=[], help='Root-relative glob or directory to exclude; may be repeated, e.g. --exclude "vendor/**"')
    parser.add_argument('--timeout', type=int, default=900, help='Maximum Syft execution time in seconds')
    parser.add_argument('--open', action='store_true', help='Open the generated dashboard in the default browser')
    parser.add_argument('--full', action=argparse.BooleanOptionalAction, default=None, help='Resolved multi-tool Juice Shop scan (default for the configured Juice Shop target); --no-full selects Syft only')
    default_reference = load_json(target_file).get('referencePath') if target_file.exists() else None
    parser.add_argument('--reference', type=pathlib.Path, default=default_reference, help='Optional reference SBOM for comparison only; never used as scan input')
    parser.add_argument('--resolve', action='store_true', help='Legacy engine only: generate missing npm lockfiles; network required')
    args = parser.parse_args(argv)
    if args.full is None:
        args.full = args.engine == 'syft' and args.repo.resolve() == default_target.resolve()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    if args.resolve and args.engine != 'legacy':
        parser.error('--resolve applies only to --engine legacy. Syft mode reads existing files without installing dependencies.')
    try:
        if args.full:
            from full_scan import execute
            graph = execute(args.repo, args.out, args.syft, args.exclude, args.timeout, args.reference)
        elif args.engine == 'legacy':
            graph = GuardianOrchestrator(args.repo, args.out, args.resolve).execute()
        else:
            from scanner import RepositoryScanner
            graph = RepositoryScanner(args.repo, args.out, args.syft, args.exclude, args.timeout).execute()
    except (RuntimeError, ValueError, OSError) as error:
        print('ERROR:', error, file=sys.stderr)
        return 1
    print(json.dumps(graph['summary'], indent=2))
    for warning in graph['warnings']:
        print('WARNING:',warning, file=sys.stderr)
    for file in ['cyclonedx-sbom.json','dependency-graph.json','dashboard.html','agent-trace.json']:
        print('Saved:', args.out.resolve()/file)
    if args.open:
        import webbrowser
        webbrowser.open((args.out.resolve()/'dashboard.html').as_uri())
    return 0


if __name__=='__main__':
    sys.exit(main())
