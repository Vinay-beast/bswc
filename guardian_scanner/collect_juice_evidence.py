"""Collect independent npm, cdxgen and ABOM evidence from the real Juice Shop tree."""
from pathlib import Path
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from install_scan_tools import NODE_VERSION, ABOM_VERSION

ROOT = Path(__file__).resolve().parent


def node_command():
    base = ROOT / '.tools' / 'node' / NODE_VERSION
    node = base / ('node.exe' if os.name == 'nt' else 'bin/node')
    npm = base / ('node_modules/npm/bin/npm-cli.js' if os.name == 'nt' else 'lib/node_modules/npm/bin/npm-cli.js')
    if not node.exists() or not npm.exists():
        raise RuntimeError('Run python install_scan_tools.py to install portable Node.js/npm')
    return node, npm


def run(command, cwd, log, timeout=900, output=None):
    env = os.environ.copy()
    env['PATH'] = str(node_command()[0].parent) + os.pathsep + env.get('PATH', '')
    env['NPM_CONFIG_IGNORE_SCRIPTS'] = 'true'
    env['NPM_CONFIG_AUDIT'] = 'false'
    env['NPM_CONFIG_FUND'] = 'false'
    env['CDXGEN_INSTALL_DEPS'] = 'false'
    env['FETCH_LICENSE'] = 'false'
    env['CDXGEN_INCLUDE_FORMULATION'] = 'false'
    result = subprocess.run(list(map(str, command)), cwd=cwd, env=env, capture_output=True,
                            encoding='utf-8', errors='replace', timeout=timeout)
    Path(log).write_text(result.stderr + ('\n' + result.stdout if output is None else ''), encoding='utf-8')
    if result.returncode:
        raise RuntimeError(f'Tool exited {result.returncode}: {(result.stderr or result.stdout)[-2200:]}')
    if output:
        data = json.loads(result.stdout)
        Path(output).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    return result


def collect(repository, destination, resolve=True):
    repository, destination = Path(repository).resolve(), Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    node, npm = node_command()
    records, diagnostics = [], []
    workspaces = [(name, repository / relative) for name, relative in [('backend', ''), ('frontend', 'frontend')]]
    for name, folder in workspaces:
        if not (folder / 'package.json').exists():
            raise RuntimeError('Missing Juice Shop workspace manifest: ' + str(folder))
        lock = folder / 'package-lock.json'
        if resolve and not lock.exists():
            print(f'[npm] Resolving {name} runtime + development + optional + peer dependencies (scripts disabled) ...', flush=True)
            command = [node, npm, 'install', '--package-lock-only', '--package-lock=true', '--ignore-scripts',
                       '--no-audit', '--no-fund', '--include=dev', '--include=optional', '--include=peer']
            run(command, folder, destination / f'npm-{name}-resolution.log')
        if not lock.exists():
            raise RuntimeError('Cannot generate resolved npm SBOM without ' + str(lock))
        print(f'[npm] Generating {name} CycloneDX from lockfile ...', flush=True)
        output = destination / f'npm-{name}.cdx.json'
        run([node, npm, 'sbom', '--package-lock-only', '--sbom-format=cyclonedx', '--include=dev',
             '--include=optional', '--include=peer'], folder, destination / f'npm-{name}-sbom.log', output=output)
        records.append({'tool': 'npm', 'path': output.name, 'workspace': name,
                        'evidence': ('frontend/' if name == 'frontend' else '') + 'package-lock.json'})
        if name == 'backend':
            run([node, npm, 'sbom', '--package-lock-only', '--sbom-format=cyclonedx', '--omit=dev'],
                folder, destination / 'npm-backend-production.log', output=destination / 'npm-backend-production.cdx.json')
    abom = ROOT / '.tools' / 'abom' / ABOM_VERSION / ('abom.exe' if os.name == 'nt' else 'abom')
    print('[ABOM] Collecting GitHub Actions BOM ...', flush=True)
    try:
        output = destination / 'abom.cdx.json'
        run([abom, 'scan', repository, '--offline', '--depth', '20', '-o', 'cyclonedx-json', '-f', output],
            repository, destination / 'abom.log')
        records.append({'tool': 'ABOM', 'path': output.name, 'workspace': 'workflows', 'evidence': '.github/workflows'})
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        diagnostics.append({'tool': 'ABOM', 'status': 'blocked' if isinstance(error, OSError) else 'failed', 'message': str(error)})
        (destination / 'abom.log').write_text(str(error) + '\nNo attempt was made to bypass operating-system application control.\n', encoding='utf-8')
        print('[ABOM] Unavailable; recorded diagnostic. Using cdxgen workflow collector.', flush=True)
    cdxgen = ROOT / '.tools/cdxgen/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js'
    if not cdxgen.exists():
        raise RuntimeError('Install @cyclonedx/cdxgen into .tools/cdxgen with npm --ignore-scripts before a full scan')
    for kind, types in [('packages', ['js']), ('workflows', ['github'])]:
        print('[cdxgen] Generating ' + kind + ' BOM ...', flush=True)
        output = destination / f'cdxgen-{kind}.cdx.json'
        command = [node, cdxgen, '--no-install-deps', '--no-babel', '--spec-version', '1.6',
                   '--json-pretty', '--output', output]
        for project_type in types:
            command.extend(['-t', project_type])
        command.append(str(repository))
        run(command, ROOT, destination / f'cdxgen-{kind}.log')
        records.append({'tool': 'cdxgen', 'path': output.name, 'workspace': 'workflows' if kind == 'workflows' else 'repository',
                        'evidence': '.github/workflows' if kind == 'workflows' else 'npm lockfiles'})
    metadata = {'generatedAt': datetime.now(timezone.utc).isoformat(), 'repository': str(repository),
                'source': json.loads((repository / 'GUARDIAN_SOURCE.json').read_text(encoding='utf-8')),
                'records': records, 'diagnostics': diagnostics,
                'scope': 'backend + frontend + dev + optional + peers + workflow actions',
                'resolution': 'npm package-lock-only; ignore-scripts; no application execution'}
    (destination / 'evidence-index.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    return metadata


if __name__ == '__main__':
    target = json.loads((ROOT / '.guardian-target.json').read_text(encoding='utf-8'))['repositoryPath']
    collect(target, ROOT / '.guardian-work' / 'juice-evidence')
