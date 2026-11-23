"""General repository inventory, Syft integration, and evidence-based supply chain graph.

Reads files only: no builds, package installation, or execution of repository code.
Python 3.11+ (tomllib) and the external Syft executable are required.
"""
from __future__ import annotations

import ast
from collections import Counter
import configparser
from copy import deepcopy
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from urllib.parse import quote
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
DEFAULT_EXCLUDES = ['**/.git/**', '**/__pycache__/**', '**/.tools/**', '**/.guardian-work/**']
LANGUAGES = {
    '.py': 'Python', '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
    '.jsx': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.java': 'Java',
    '.kt': 'Kotlin', '.kts': 'Kotlin', '.go': 'Go', '.rs': 'Rust', '.rb': 'Ruby',
    '.php': 'PHP', '.cs': 'C#', '.fs': 'F#', '.vb': 'Visual Basic', '.c': 'C',
    '.h': 'C/C++', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.hpp': 'C++',
    '.swift': 'Swift', '.m': 'Objective-C', '.mm': 'Objective-C++', '.dart': 'Dart',
    '.ex': 'Elixir', '.exs': 'Elixir', '.erl': 'Erlang', '.hs': 'Haskell',
    '.scala': 'Scala', '.r': 'R', '.lua': 'Lua', '.pl': 'Perl', '.sh': 'Shell',
    '.ps1': 'PowerShell', '.sql': 'SQL', '.vue': 'Vue', '.svelte': 'Svelte',
    '.html': 'HTML', '.css': 'CSS', '.scss': 'SCSS', '.tf': 'Terraform',
}
MANIFESTS = {
    'package.json': 'npm', 'package-lock.json': 'npm', 'npm-shrinkwrap.json': 'npm',
    'yarn.lock': 'npm', 'pnpm-lock.yaml': 'npm', 'bun.lock': 'npm', 'bun.lockb': 'npm',
    'deno.json': 'npm', 'deno.lock': 'npm', 'pyproject.toml': 'pypi',
    'requirements.txt': 'pypi', 'Pipfile': 'pypi', 'Pipfile.lock': 'pypi',
    'poetry.lock': 'pypi', 'uv.lock': 'pypi', 'setup.py': 'pypi', 'setup.cfg': 'pypi',
    'go.mod': 'golang', 'go.sum': 'golang', 'Cargo.toml': 'cargo', 'Cargo.lock': 'cargo',
    'pom.xml': 'maven', 'build.gradle': 'maven', 'build.gradle.kts': 'maven',
    'gradle.lockfile': 'maven', 'packages.lock.json': 'nuget', 'packages.config': 'nuget',
    'Directory.Packages.props': 'nuget', 'composer.json': 'composer', 'composer.lock': 'composer',
    'Gemfile': 'gem', 'Gemfile.lock': 'gem', 'pubspec.yaml': 'pub', 'pubspec.lock': 'pub',
    'Package.swift': 'swift', 'Package.resolved': 'swift', 'Podfile': 'cocoapods',
    'Podfile.lock': 'cocoapods', 'conanfile.txt': 'conan', 'conanfile.py': 'conan',
    'conan.lock': 'conan', 'vcpkg.json': 'vcpkg', 'mix.exs': 'hex', 'mix.lock': 'hex',
    'rebar.lock': 'hex', 'DESCRIPTION': 'cran', 'renv.lock': 'cran',
    '.terraform.lock.hcl': 'terraform', 'environment.yml': 'conda',
}
TYPE_ECOSYSTEM = {
    'python': 'pypi', 'go-module': 'golang', 'rust-crate': 'cargo',
    'java-archive': 'maven', 'dotnet': 'nuget', 'php-composer': 'composer',
    'github-action': 'githubactions', 'dart-pub': 'pub', 'ruby': 'gem',
}
LIMITATIONS = [
    'Source scan only: a manifest or lockfile does not prove a package is installed or shipped.',
    'Dependency coverage varies by Syft cataloger and available files; missing edges are unknown, not absent dependencies.',
    'Static imports are source references, not verified package identities or runtime reachability.',
    'Docker base images and workflow actions are recorded references; images and external actions are not downloaded or scanned.',
    'No vulnerability, secret, malicious-code, or semantic security analysis is performed.',
]


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def identity(*parts):
    return hashlib.sha256('\0'.join(map(str, parts)).encode()).hexdigest()[:24]


def excluded(path, patterns):
    path = path.replace('\\', '/').strip('/')
    for pattern in patterns:
        pattern = pattern.replace('\\', '/').removeprefix('./').strip('/')
        alternatives = [pattern]
        if pattern.startswith('**/'):
            alternatives.append(pattern[3:])
        for candidate in alternatives:
            if fnmatch.fnmatchcase(path, candidate):
                return True
            prefix = candidate.removesuffix('/**')
            if path == prefix or path.startswith(prefix + '/'):
                return True
            if candidate.endswith('/**') and fnmatch.fnmatchcase(path + '/placeholder', candidate):
                return True
    return False


def normalize_exclusions(repository, patterns):
    """Use Syft's required ./ or **/ prefixes, also understood by source discovery."""
    result = []
    for pattern in patterns:
        pattern = pattern.replace('\\', '/').removeprefix('./')
        if not pattern or pattern.startswith('/') or ':' in pattern or '..' in pattern.split('/'):
            raise ValueError('Exclusions must be root-relative paths or globs: ' + pattern)
        if not any(char in pattern for char in '*?[') and (repository / pattern).is_dir():
            pattern = pattern.rstrip('/') + '/**'
        if not pattern.startswith(('**/', '*/')):
            pattern = './' + pattern
        result.append(pattern)
    return list(dict.fromkeys(result))


def file_kind(path):
    name = path.name
    if name in MANIFESTS or name.startswith('requirements') and path.suffix == '.txt':
        ecosystem = MANIFESTS.get(name, 'pypi')
        lock = 'lock' in name.lower() or name in ('go.sum', 'Package.resolved')
        return ('lockfile' if lock else 'manifest'), ecosystem
    if path.suffix in ('.csproj', '.fsproj', '.vbproj'):
        return 'manifest', 'nuget'
    text = path.as_posix()
    if '.github/workflows/' in text or name in ('.gitlab-ci.yml', 'Jenkinsfile', 'azure-pipelines.yml'):
        return 'workflow', None
    if name.startswith('Dockerfile') or name.endswith('.Dockerfile') or name in ('Containerfile', 'docker-compose.yml', 'compose.yml', 'compose.yaml'):
        return 'container', None
    if name in ('Makefile', 'CMakeLists.txt', 'build.xml', '.dockerignore') or path.suffix == '.tf':
        return 'build', None
    return ('source' if path.suffix.lower() in LANGUAGES else 'other'), None


def source_imports(text, language, path, warnings):
    result = []
    if language == 'Python':
        try:
            tree = ast.parse(text, filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    result.extend({'path': path, 'line': node.lineno, 'language': language,
                                   'reference': alias.name, 'method': 'Python AST'} for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    result.append({'path': path, 'line': node.lineno, 'language': language,
                                   'reference': '.' * node.level + (node.module or ''), 'method': 'Python AST'})
        except SyntaxError as error:
            warnings.append(f'{path}:{error.lineno}: import extraction failed: {error.msg}')
        return result
    patterns = {
        'JavaScript': r'''(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]''',
        'TypeScript': r'''(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]''',
        'Java': r'^\s*import\s+(?:static\s+)?([\w.*]+)',
        'Kotlin': r'^\s*import\s+([\w.*]+)',
        'C#': r'^\s*(?:global\s+)?using\s+([\w.]+)\s*;',
        'Rust': r'^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([\w:]+)',
        'C': r'^\s*#\s*include\s*[<"]([^>"]+)',
        'C++': r'^\s*#\s*include\s*[<"]([^>"]+)',
        'C/C++': r'^\s*#\s*include\s*[<"]([^>"]+)',
        'Ruby': r'''^\s*(?:require|require_relative)\s*['"]([^'"]+)''',
        'PHP': r'^\s*use\s+([\w\\]+)',
        'Swift': r'^\s*import\s+([\w.]+)',
        'Dart': r'''^\s*(?:import|export)\s+['"]([^'"]+)''',
    }
    if language == 'Go':
        in_block = False
        for line, value in enumerate(text.splitlines(), 1):
            if re.match(r'^\s*import\s*\(', value):
                in_block = True
                continue
            if in_block and value.strip().startswith(')'):
                in_block = False
            if in_block or re.match(r'^\s*import\s', value):
                match = re.search(r'"([^"]+)"', value)
                if match:
                    result.append({'path': path, 'line': line, 'language': language,
                                   'reference': match[1], 'method': 'Static pattern'})
    elif language in patterns:
        for match in re.finditer(patterns[language], text, re.MULTILINE):
            result.append({'path': path, 'line': text.count('\n', 0, match.start()) + 1,
                           'language': language, 'reference': match[1], 'method': 'Static pattern'})
    return result


class RepositoryDiscovery:
    def __init__(self, repository, excludes=(), max_text_bytes=2_000_000):
        self.root = Path(repository).resolve()
        self.excludes = list(excludes)
        self.max_text_bytes = max_text_bytes

    def run(self):
        files, imports, references, warnings = [], [], [], []
        languages = Counter()
        skipped = Counter()
        def walk_error(error):
            warnings.append(f'Could not enumerate directory: {error.filename}: {error.strerror}')
        for directory, dirs, names in os.walk(self.root, followlinks=False, onerror=walk_error):
            base = Path(directory)
            kept = []
            for name in sorted(dirs):
                path = base / name
                rel = path.relative_to(self.root).as_posix()
                if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                    skipped['symlinks'] += 1
                elif excluded(rel, self.excludes):
                    skipped['excludedDirectories'] += 1
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(names):
                path = base / name
                rel = path.relative_to(self.root).as_posix()
                if excluded(rel, self.excludes):
                    skipped['excludedFiles'] += 1
                    continue
                if path.is_symlink() or not path.is_file():
                    skipped['symlinksOrSpecialFiles'] += 1
                    continue
                kind, ecosystem = file_kind(path)
                language = LANGUAGES.get(path.suffix.lower())
                try:
                    length = path.stat().st_size
                    digest = hashlib.sha256()
                    with path.open('rb') as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(block)
                    record = {'path': rel, 'kind': kind, 'ecosystem': ecosystem,
                              'language': language, 'bytes': length, 'sha256': digest.hexdigest()}
                    if language:
                        languages[language] += 1
                    if kind != 'other' and length <= self.max_text_bytes:
                        text = path.read_text(encoding='utf-8-sig')
                        record['lines'] = len(text.splitlines())
                        record['textAnalyzed'] = True
                        imports.extend(source_imports(text, language, rel, warnings))
                        if kind == 'container':
                            for line, value in enumerate(text.splitlines(), 1):
                                match = re.match(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', value, re.I)
                                if match:
                                    references.append({'path': rel, 'line': line, 'kind': 'docker-from', 'reference': match[1],
                                                       'status': 'Unresolved image or build-stage reference'})
                        if kind == 'workflow':
                            for line, value in enumerate(text.splitlines(), 1):
                                match = re.match(r'''^\s*(?:-\s*)?uses:\s*['"]?([^\s'"#]+)''', value)
                                if match:
                                    references.append({'path': rel, 'line': line, 'kind': 'workflow-uses', 'reference': match[1],
                                                       'status': 'Recorded reference; external content not scanned'})
                    elif kind != 'other':
                        record['textAnalyzed'] = False
                        warnings.append(f'{rel}: text analysis skipped: above {self.max_text_bytes} bytes; Syft still scans it')
                    files.append(record)
                except (OSError, UnicodeError) as error:
                    warnings.append(f'{rel}: {type(error).__name__}: {error}')
                    if 'record' in locals() and record.get('path') == rel and record not in files:
                        record['textAnalyzed'] = False
                        files.append(record)
        return {'schema': 'guardian-source-2', 'root': str(self.root), 'files': files, 'imports': imports,
                'buildReferences': references, 'languages': dict(languages.most_common()),
                'exclusions': self.excludes, 'skipped': dict(skipped), 'warnings': warnings,
                'summary': {'files': len(files), 'sourceFiles': sum(f['kind'] == 'source' for f in files),
                            'sourceLines': sum(f.get('lines', 0) for f in files if f['kind'] == 'source'),
                            'dependencyFiles': sum(f['kind'] in ('manifest', 'lockfile') for f in files),
                            'buildFiles': sum(f['kind'] in ('workflow', 'container', 'build') for f in files),
                            'importReferences': len(imports), 'bytes': sum(f['bytes'] for f in files)}}


def declarations(repository, inventory):
    """Supplement catalogers with explicit common manifest declarations, never guessed versions."""
    result, warnings = [], []
    root = Path(repository)
    def add(file, ecosystem, name, constraint, usage='runtime'):
        if not name or not isinstance(name, str):
            return
        result.append({'path': file, 'ecosystem': ecosystem, 'name': name,
                       'constraint': str(constraint or '*'), 'usage': usage})
    def requirement(file, value, usage='runtime'):
        match = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)', value)
        if match:
            add(file, 'pypi', match[1], match[2] or '*', usage)
    for file in inventory['files']:
        if file['kind'] != 'manifest' or not file.get('textAnalyzed'):
            continue
        rel = file['path']
        path = root / rel
        try:
            if path.name == 'package.json':
                data = json.loads(path.read_text(encoding='utf-8-sig'))
                for field, usage in [('dependencies', 'runtime'), ('devDependencies', 'development'),
                                     ('optionalDependencies', 'optional'), ('peerDependencies', 'peer')]:
                    for name, spec in data.get(field, {}).items():
                        add(rel, 'npm', name, spec, usage)
            elif path.name == 'composer.json':
                data = json.loads(path.read_text(encoding='utf-8-sig'))
                for field, usage in [('require', 'runtime'), ('require-dev', 'development')]:
                    for name, spec in data.get(field, {}).items():
                        if '/' in name:
                            add(rel, 'composer', name, spec, usage)
            elif path.name.startswith('requirements') and path.suffix == '.txt':
                for line in path.read_text(encoding='utf-8-sig').splitlines():
                    if line.strip() and not line.lstrip().startswith(('#', '-', 'http:', 'https:', 'git+')):
                        requirement(rel, line.split(' #', 1)[0])
            elif path.name == 'pyproject.toml':
                data = tomllib.loads(path.read_text(encoding='utf-8-sig'))
                for spec in data.get('project', {}).get('dependencies', []):
                    requirement(rel, spec)
                for specs in data.get('project', {}).get('optional-dependencies', {}).values():
                    for spec in specs:
                        requirement(rel, spec, 'optional')
                poetry = data.get('tool', {}).get('poetry', {})
                for name, spec in poetry.get('dependencies', {}).items():
                    if name.lower() != 'python':
                        add(rel, 'pypi', name, spec.get('version', '*') if isinstance(spec, dict) else spec)
                for group in data.get('dependency-groups', {}).values():
                    for spec in group:
                        if isinstance(spec, str):
                            requirement(rel, spec, 'development')
            elif path.name == 'setup.cfg':
                config = configparser.ConfigParser(interpolation=None)
                config.read_string(path.read_text(encoding='utf-8-sig'))
                for section, field, usage in [('options', 'install_requires', 'runtime'),
                                               ('options', 'tests_require', 'development'),
                                               ('metadata', 'requires-dist', 'runtime')]:
                    for spec in config.get(section, field, fallback='').splitlines():
                        requirement(rel, spec, usage)
                if config.has_section('options.extras_require'):
                    for _, specs in config.items('options.extras_require'):
                        for spec in specs.splitlines():
                            requirement(rel, spec, 'optional')
            elif path.name == 'setup.py':
                # Inspect only literal values and literal top-level variables. Never import/run setup.py.
                tree = ast.parse(path.read_text(encoding='utf-8-sig'), filename=rel)
                values = {}
                for statement in tree.body:
                    if isinstance(statement, ast.Assign):
                        try:
                            literal = ast.literal_eval(statement.value)
                        except (ValueError, TypeError, SyntaxError):
                            continue
                        for target in statement.targets:
                            if isinstance(target, ast.Name):
                                values[target.id] = literal
                for call in ast.walk(tree):
                    if not isinstance(call, ast.Call):
                        continue
                    function = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else None
                    if function != 'setup':
                        continue
                    for keyword in call.keywords:
                        if keyword.arg not in ('install_requires', 'tests_require', 'extras_require'):
                            continue
                        try:
                            literal = values[keyword.value.id] if isinstance(keyword.value, ast.Name) else ast.literal_eval(keyword.value)
                        except (KeyError, ValueError, TypeError, SyntaxError):
                            warnings.append(f'{rel}:{call.lineno}: dynamic {keyword.arg} cannot be determined without execution')
                            continue
                        if keyword.arg == 'extras_require' and isinstance(literal, dict):
                            for specs in literal.values():
                                if isinstance(specs, (list, tuple)):
                                    for spec in specs:
                                        if isinstance(spec, str):
                                            requirement(rel, spec, 'optional')
                        elif isinstance(literal, (list, tuple)):
                            for spec in literal:
                                if isinstance(spec, str):
                                    requirement(rel, spec, 'development' if keyword.arg == 'tests_require' else 'runtime')
            elif path.name == 'Cargo.toml':
                data = tomllib.loads(path.read_text(encoding='utf-8-sig'))
                for field, usage in [('dependencies', 'runtime'), ('dev-dependencies', 'development'), ('build-dependencies', 'build')]:
                    for name, spec in data.get(field, {}).items():
                        if isinstance(spec, dict):
                            add(rel, 'cargo', spec.get('package', name), spec.get('version') or spec.get('git') or spec.get('path') or 'workspace', usage)
                        else:
                            add(rel, 'cargo', name, spec, usage)
            elif path.name == 'pom.xml':
                tree = ET.parse(path)
                ns = {'m': 'http://maven.apache.org/POM/4.0.0'} if tree.getroot().tag.startswith('{') else {}
                prefix = 'm:' if ns else ''
                # Only direct project dependencies; dependencyManagement is not an installed dependency list.
                for dep in tree.getroot().findall(f'{prefix}dependencies/{prefix}dependency', ns):
                    group = dep.findtext(f'{prefix}groupId', namespaces=ns)
                    name = dep.findtext(f'{prefix}artifactId', namespaces=ns)
                    spec = dep.findtext(f'{prefix}version', namespaces=ns)
                    scope = dep.findtext(f'{prefix}scope', namespaces=ns) or 'runtime'
                    if group and name:
                        add(rel, 'maven', group + '/' + name, spec, 'development' if scope == 'test' else scope)
            elif path.suffix in ('.csproj', '.fsproj', '.vbproj') or path.name == 'Directory.Packages.props':
                for element in ET.parse(path).getroot().iter():
                    if element.tag.rsplit('}', 1)[-1] == 'PackageReference':
                        spec = element.get('Version') or next((child.text for child in element if child.tag.rsplit('}', 1)[-1] == 'Version'), '*')
                        add(rel, 'nuget', element.get('Include') or element.get('Update'), spec)
        except (ValueError, TypeError, AttributeError, OSError, SyntaxError, configparser.Error, ET.ParseError) as error:
            warnings.append(f'{rel}: declaration parsing failed: {error}')
    return result, warnings


def find_syft(explicit=None):
    from install_syft import VERSION
    name = 'syft.exe' if os.name == 'nt' else 'syft'
    candidate = explicit or shutil.which('syft') or ROOT / '.tools' / 'syft' / VERSION / name
    path = Path(candidate).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError('Syft is required. Run: python install_syft.py (or pass --syft /path/to/syft). No fallback scan was performed.')
    return path


def run_syft(repository, destination, executable, excludes, timeout=900):
    # Explicit configuration and clean SYFT_* env prevent project/user configuration
    # from changing output, enabling network enrichment, or excluding evidence silently.
    config = {'check-for-app-update': False, 'format': {'pretty': True},
              'javascript': {'include-dev-dependencies': True, 'search-remote-licenses': False},
              'python': {'guess-unpinned-requirements': False, 'search-remote-licenses': False},
              'golang': {'search-remote-licenses': False, 'search-local-mod-cache-licenses': False,
                         'search-local-vendor-licenses': False},
              'java': {'use-network': False, 'resolve-transitive-dependencies': False},
              'package': {'nested-archive-max-depth': 4}, 'exclude': excludes}
    env = {key: value for key, value in os.environ.items() if not key.startswith('SYFT_')}
    with tempfile.TemporaryDirectory(prefix='guardian-syft-') as work:
        config_path = Path(work) / 'syft.json'
        save(config_path, config)
        cmd = [str(executable), 'scan', 'dir:' + str(repository), '--source-name', repository.name,
               '--config', str(config_path), '--base-path', str(repository),
               '-o', 'syft-json=' + str(destination / 'syft-sbom.json'),
               '-o', 'cyclonedx-json=' + str(destination / 'syft-sbom.cdx.json')]
        try:
            completed = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                                       encoding='utf-8', errors='replace', timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f'Syft exceeded {timeout}s; scan not published') from error
        log = completed.stderr.strip()
        (destination / 'syft.log').write_text(log + '\n', encoding='utf-8')
        save(destination / 'scan-config.json', config)
        if completed.returncode:
            raise RuntimeError(f'Syft failed with exit {completed.returncode}: {log[-3000:]}')
        native = json.loads((destination / 'syft-sbom.json').read_text(encoding='utf-8'))
        bom = json.loads((destination / 'syft-sbom.cdx.json').read_text(encoding='utf-8'))
        if not isinstance(native.get('artifacts'), list) or bom.get('bomFormat') != 'CycloneDX':
            raise RuntimeError('Syft produced invalid report data')
        return native, bom, log, config


def package_name(name, ecosystem):
    if ecosystem == 'pypi':
        return re.sub(r'[-_.]+', '-', name).lower()
    return name.lower() if ecosystem == 'nuget' else name


def purl_for(ecosystem, name):
    return 'pkg:' + ecosystem + '/' + quote(package_name(name, ecosystem), safe='/')


def build_reports(repository, native, original_bom, inventory, declared):
    bom = deepcopy(original_bom)
    components = bom.setdefault('components', [])
    root_ref = bom['metadata']['component']['bom-ref']
    # Derive the link to the standard SBOM using Syft's package-id qualifier.
    refs = {}
    for component in components:
        match = re.search(r'(?:[?&])package-id=([^&#]+)', component.get('bom-ref', ''))
        if match:
            refs[match[1]] = component['bom-ref']
        elif component.get('bom-ref'):
            refs[component['bom-ref']] = component['bom-ref']
    nodes, edges = [], []
    repo_id = 'repository:' + identity(str(repository))
    nodes.append({'id': repo_id, 'name': repository.name, 'kind': 'repository', 'path': '.', 'ecosystem': 'repository'})
    evidence = {}
    file_index = {f['path']: f for f in inventory['files']}
    def evidence_node(path, kind='evidence', ecosystem=None):
        path = path.replace('\\', '/').lstrip('/')
        if path not in evidence:
            nid = 'file:' + identity(path)
            evidence[path] = nid
            info = file_index.get(path, {})
            nodes.append({'id': nid, 'name': path, 'path': path, 'kind': kind,
                          'ecosystem': ecosystem or info.get('ecosystem') or 'evidence',
                          'sha256': info.get('sha256')})
            edges.append({'from': repo_id, 'to': nid, 'kind': 'contains', 'evidence': path})
        return evidence[path]
    for f in inventory['files']:
        if f['kind'] in ('manifest', 'lockfile', 'workflow', 'container', 'build'):
            evidence_node(f['path'], f['kind'], f.get('ecosystem'))
    packages = []
    for artifact in native['artifacts']:
        ecosystem = TYPE_ECOSYSTEM.get(artifact['type'], artifact['type'])
        locations = sorted({loc.get('path', '').replace('\\', '/').lstrip('/') for loc in artifact.get('locations', []) if loc.get('path')})
        metadata = artifact.get('metadata') or {}
        if not isinstance(metadata, dict):
            metadata = {}
        found = artifact.get('foundBy', 'Syft')
        if 'installed' in found or 'binary' in found or 'archive' in found:
            status = 'artifact-metadata'
        elif any('lock' in Path(path).name.lower() or Path(path).name == 'Package.resolved' for path in locations):
            status = 'lockfile-record'
        elif artifact['type'] == 'github-action':
            status = 'reference'
        else:
            status = 'manifest-record'
        group = ((metadata.get('pomProperties') or metadata.get('pomProject') or {}).get('groupId'))
        match_name = group + '/' + artifact['name'] if ecosystem == 'maven' and group else artifact['name']
        n = {'id': artifact['id'], 'bomRef': refs.get(artifact['id']), 'name': artifact['name'],
             'matchName': match_name, 'kind': 'package', 'ecosystem': ecosystem,
             'type': artifact['type'], 'version': artifact.get('version') or None,
             'versionStatus': status, 'usage': 'unknown', 'direct': None,
             'purl': artifact.get('purl'), 'locations': locations, 'cataloger': found,
             'licenses': sorted({l.get('value', '') for l in artifact.get('licenses', []) if isinstance(l, dict) and l.get('value')}),
             'declarations': []}
        nodes.append(n)
        packages.append(n)
        for path in locations:
            file_id = evidence_node(path, ecosystem=ecosystem)
            edges.append({'from': file_id, 'to': n['id'], 'kind': 'evidences', 'evidence': path, 'cataloger': found})
    ids = {p['id'] for p in packages}
    for relation in native.get('artifactRelationships', []):
        # Syft parent DEPENDENCY_OF child means child depends on parent.
        if relation.get('type') == 'dependency-of' and relation['parent'] in ids and relation['child'] in ids:
            edges.append({'from': relation['child'], 'to': relation['parent'], 'kind': 'depends-on',
                          'evidence': 'Syft artifactRelationships', 'cataloger': 'Syft'})
    dep_map = {d['ref']: set(d.get('dependsOn', [])) for d in bom.get('dependencies', [])}
    package_index = {}
    for package in packages:
        key_name = package_name(package.get('matchName', package['name']), package['ecosystem'])
        for folder in {str(Path(path).parent).replace('\\', '/') for path in package['locations']}:
            package_index.setdefault((package['ecosystem'], key_name, folder), []).append(package)
    added_packages = {}
    for declaration in declared:
        ecosystem = declaration['ecosystem']
        name = package_name(declaration['name'], ecosystem)
        folder = str(Path(declaration['path']).parent).replace('\\', '/')
        candidates = package_index.get((ecosystem, name, folder), [])
        if len(candidates) > 1 and ecosystem == 'npm':
            lock = Path(repository) / folder / 'package-lock.json'
            if lock.exists():
                try:
                    entry = json.loads(lock.read_text(encoding='utf-8')).get('packages', {}).get('node_modules/' + declaration['name'], {})
                    pinned = entry.get('version')
                    candidates = [p for p in candidates if p['version'] == pinned] if pinned else candidates
                except (OSError, ValueError):
                    pass
        # Ambiguous versions/locations remain explicit declarations, rather than linking to a guessed version.
        if len(candidates) == 1:
            package = candidates[0]
        else:
            nid = 'declared:' + identity(folder, ecosystem, name, declaration['constraint'])
            package = added_packages.get(nid)
            if package is None:
                package = {'id': nid, 'bomRef': nid, 'name': declaration['name'], 'kind': 'package',
                           'ecosystem': ecosystem, 'type': ecosystem, 'version': None,
                           'versionStatus': 'declared-only', 'usage': 'unknown', 'direct': True,
                           'purl': purl_for(ecosystem, declaration['name']), 'locations': [declaration['path']],
                           'cataloger': 'Guardian declaration reader', 'licenses': [], 'declarations': []}
                nodes.append(package)
                packages.append(package)
                added_packages[nid] = package
                components.append({'type': 'library', 'bom-ref': nid, 'name': declaration['name'],
                                   'purl': package['purl'], 'properties': [
                                       {'name': 'guardian:evidence', 'value': declaration['path']},
                                       {'name': 'guardian:versionConstraint', 'value': declaration['constraint']},
                                       {'name': 'guardian:status', 'value': 'declared-only'}]})
            elif declaration['path'] not in package['locations']:
                package['locations'].append(declaration['path'])
                component = next(c for c in components if c['bom-ref'] == nid)
                component['properties'].append({'name': 'guardian:evidence', 'value': declaration['path']})
        package['declarations'].append(declaration)
        usages = {d['usage'] for d in package['declarations']}
        package['usage'] = 'runtime' if 'runtime' in usages else sorted(usages)[0]
        package['direct'] = True
        file_id = evidence_node(declaration['path'], 'manifest', ecosystem)
        edges.append({'from': file_id, 'to': package['id'], 'kind': 'declares',
                      'requested': declaration['constraint'], 'evidence': declaration['path'], 'usage': declaration['usage']})
        # Include project declarations as explicit workspace application components in CycloneDX.
        workspace_ref = 'project:' + identity(declaration['path'])
        if workspace_ref not in dep_map:
            components.append({'type': 'application', 'bom-ref': workspace_ref, 'name': declaration['path'],
                               'properties': [{'name': 'guardian:evidence', 'value': declaration['path']}]})
            dep_map[workspace_ref] = set()
            dep_map.setdefault(root_ref, set()).add(workspace_ref)
        if package.get('bomRef'):
            dep_map[workspace_ref].add(package['bomRef'])
    reference_ids = set()
    for reference in inventory['buildReferences']:
        nid = 'reference:' + identity(reference['kind'], reference['reference'])
        if nid not in reference_ids:
            reference_ids.add(nid)
            nodes.append({'id': nid, 'name': reference['reference'], 'kind': 'reference',
                          'ecosystem': reference['kind'], 'status': reference['status']})
        edges.append({'from': evidence_node(reference['path']), 'to': nid, 'kind': 'references',
                      'evidence': reference['path'], 'line': reference['line']})
    # Keep original Syft components and dependencies intact; annotate Guardian's additions.
    bom['dependencies'] = [{'ref': ref, 'dependsOn': sorted(deps)} for ref, deps in sorted(dep_map.items())]
    bom['metadata'].setdefault('tools', {}).setdefault('components', []).append(
        {'type': 'application', 'name': 'guardian', 'version': '2.0.0'})
    bom['metadata'].setdefault('properties', []).extend([
        {'name': 'guardian:scanMode', 'value': 'source-evidence'},
        {'name': 'guardian:declarationReader', 'value': 'Unresolved declarations omit version; constraints retained as properties'},
    ])
    ecosystems = dict(Counter(p['ecosystem'] for p in packages).most_common())
    summary = {'packages': len(packages), 'syftPackages': len(native['artifacts']),
               'declaredOnlyPackages': sum(p['versionStatus'] == 'declared-only' for p in packages),
               'recordedVersions': sum(bool(p['version']) for p in packages),
               'dependencyEdges': sum(e['kind'] == 'depends-on' for e in edges),
               'evidenceEdges': sum(e['kind'] in ('declares', 'evidences') for e in edges),
               'ecosystems': len(ecosystems), **inventory['summary']}
    warnings = list(inventory['warnings'])
    covered_paths = {path for p in packages for path in p['locations']}
    covered_paths.update(d['path'] for p in packages for d in p['declarations'])
    for file in inventory['files']:
        if file['kind'] in ('manifest', 'lockfile'):
            if file['path'] not in covered_paths:
                warnings.append(f"{file['path']}: no package records attributed to this dependency file; review cataloger support and available lockfiles")
    if not summary['dependencyEdges']:
        warnings.append('No package-to-package dependency edges were reported by Syft. Evidence links are not dependency edges.')
    if not packages:
        warnings.append('No packages detected. This is not evidence that the repository has no external dependencies.')
    graph = {'schema': 'guardian-supply-chain-2', 'project': repository.name, 'analyzedPath': str(repository),
             'generatedAt': stamp(), 'engine': {'name': 'Syft', 'version': native.get('descriptor', {}).get('version'),
             'catalogers': native.get('descriptor', {}).get('configuration', {}).get('catalogers', {}).get('used', [])},
             'summary': summary, 'ecosystems': ecosystems, 'nodes': nodes,
             'edges': list({(e['from'], e['to'], e['kind'], e.get('requested')): e for e in edges}.values()),
             'warnings': warnings, 'limitations': LIMITATIONS}
    return graph, bom


class RepositoryScanner:
    def __init__(self, repository, out, syft=None, excludes=(), timeout=900):
        self.repository = Path(repository).expanduser().resolve()
        self.out = Path(out).expanduser().resolve()
        self.syft = syft
        self.excludes = list(DEFAULT_EXCLUDES) + list(excludes)
        self.timeout = timeout

    def execute(self):
        if not self.repository.is_dir():
            raise ValueError(f'Repository directory does not exist: {self.repository}')
        if self.out == self.repository or self.out in self.repository.parents:
            raise ValueError('Output must be a separate directory, not the repository root or its ancestor')
        try:
            rel = self.out.relative_to(self.repository).as_posix()
            self.excludes.append(rel + '/**')
        except ValueError:
            pass
        self.excludes = normalize_exclusions(self.repository, self.excludes)
        executable = find_syft(self.syft)
        started = time.monotonic()
        started_at = stamp()
        print(f'[1/4] Recursively inspecting files: {self.repository}', flush=True)
        inventory = RepositoryDiscovery(self.repository, self.excludes).run()
        declared, warnings = declarations(self.repository, inventory)
        inventory['warnings'].extend(warnings)
        # Stage outside the source tree so Syft cannot ingest this run's own artifacts.
        with tempfile.TemporaryDirectory(prefix='guardian-report-') as folder:
            stage = Path(folder)
            print(f"[2/4] Syft cataloging ({inventory['summary']['files']} files discovered) ...", flush=True)
            native, original, log, config = run_syft(self.repository, stage, executable, self.excludes, self.timeout)
            print('[3/4] Building CycloneDX SBOM and supply chain evidence ...', flush=True)
            graph, bom = build_reports(self.repository, native, original, inventory, declared)
            if log:
                graph['warnings'].append('Syft emitted diagnostics; review syft.log for coverage warnings.')
            tree_digest = hashlib.sha256()
            for file in sorted(inventory['files'], key=lambda f: f['path']):
                tree_digest.update((file['path'] + '\0' + file['sha256'] + '\n').encode('utf-8'))
            trace = {'schema': 'guardian-scan-2', 'startedAt': started_at, 'durationSeconds': round(time.monotonic() - started, 2),
                     'repository': str(self.repository), 'syftExecutable': str(executable),
                     'sourceInventorySha256': tree_digest.hexdigest(),
                     'engine': graph['engine'], 'exclusions': self.excludes,
                     'steps': ['recursive file hashes and source references', 'Syft directory catalogers',
                               'explicit manifest declaration supplement', 'CycloneDX and evidence graph rendering'],
                     'limitations': LIMITATIONS}
            save(stage / 'cyclonedx-sbom.json', bom)
            save(stage / 'dependency-graph.json', graph)
            save(stage / 'source-analysis.json', inventory)
            save(stage / 'agent-trace.json', trace)
            template = (ROOT / 'scanner_dashboard.html').read_text(encoding='utf-8')
            for marker, data in [('GRAPH', graph), ('SBOM', bom), ('SOURCE', inventory)]:
                template = template.replace(f'/*__{marker}__*/null', json.dumps(data, ensure_ascii=False).replace('<', '\\u003c'))
            (stage / 'dashboard.html').write_text(template, encoding='utf-8')
            print('[4/4] Publishing report artifacts ...', flush=True)
            self.out.mkdir(parents=True, exist_ok=True)
            # Dashboard is published last, after the data files it references.
            for path in sorted(stage.iterdir(), key=lambda p: p.name == 'dashboard.html'):
                shutil.copy2(path, self.out / path.name)
        return graph
