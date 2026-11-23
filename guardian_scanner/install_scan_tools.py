"""Install checksum-verified portable Node.js/npm and ABOM into project-local .tools."""
from pathlib import Path
import hashlib
import io
import json
import platform
import tarfile
import zipfile

from install_syft import download

ROOT = Path(__file__).resolve().parent
NODE_VERSION = '24.22.3'
ABOM_VERSION = '0.2.1'


def verified_archive(base, filename, checksum_file):
    checksums = download(base + '/' + checksum_file).decode('utf-8')
    expected = next((line.split()[0] for line in checksums.splitlines()
                     if len(line.split()) >= 2 and line.split()[-1].lstrip('*') == filename), None)
    if not expected:
        raise RuntimeError('No published checksum for ' + filename)
    archive = download(base + '/' + filename)
    actual = hashlib.sha256(archive).hexdigest()
    if actual != expected:
        raise RuntimeError('Checksum mismatch for ' + filename)
    return archive, actual


def install_node():
    system = {'Windows': 'win', 'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()]
    arch = {'AMD64': 'x64', 'x86_64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
    stem = f'node-v{NODE_VERSION}-{system}-{arch}'
    extension = 'zip' if system == 'win' else 'tar.gz'
    filename = stem + '.' + extension
    base = f'https://nodejs.org/dist/v{NODE_VERSION}'
    destination = ROOT / '.tools' / 'node' / NODE_VERSION
    executable = destination / ('node.exe' if system == 'win' else 'bin/node')
    if executable.exists():
        return executable
    print('Installing official portable Node.js ' + NODE_VERSION, flush=True)
    data, digest = verified_archive(base, filename, 'SHASUMS256.txt')
    destination.mkdir(parents=True, exist_ok=True)
    entries = []
    if extension == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    entries.append((Path(*Path(info.filename).parts[1:]), archive.read(info)))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for info in archive.getmembers():
                if info.isfile():
                    entries.append((Path(*Path(info.name).parts[1:]), archive.extractfile(info).read()))
    for relative, content in entries:
        target = (destination / relative).resolve()
        if not target.is_relative_to(destination.resolve()):
            raise RuntimeError('Unsafe archive entry')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    executable.chmod(0o755)
    (destination / 'release.json').write_text(json.dumps({'url': base + '/' + filename, 'sha256': digest}), encoding='utf-8')
    return executable


def install_abom():
    system = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()]
    arch = {'AMD64': 'amd64', 'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
    extension = 'zip' if system == 'windows' else 'tar.gz'
    filename = f'abom_{system}_{arch}.{extension}'
    base = f'https://github.com/JulietSecurity/abom/releases/download/v{ABOM_VERSION}'
    destination = ROOT / '.tools' / 'abom' / ABOM_VERSION
    name = 'abom.exe' if system == 'windows' else 'abom'
    target = destination / name
    if target.exists():
        return target
    print('Installing official ABOM ' + ABOM_VERSION, flush=True)
    data, digest = verified_archive(base, filename, 'checksums.txt')
    if extension == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            binary = archive.extractfile(name).read()
    destination.mkdir(parents=True, exist_ok=True)
    target.write_bytes(binary)
    target.chmod(0o755)
    (destination / 'release.json').write_text(json.dumps({'url': base + '/' + filename, 'sha256': digest}), encoding='utf-8')
    return target


if __name__ == '__main__':
    node = install_node()
    print(node)
    print(install_abom())
    import subprocess
    npm = node.parent / ('node_modules/npm/bin/npm-cli.js' if platform.system() == 'Windows' else '../lib/node_modules/npm/bin/npm-cli.js')
    subprocess.run([str(node), str(npm), 'install', '--prefix', str(ROOT / '.tools/cdxgen'),
                    '@cyclonedx/cdxgen@12.9.3', '--ignore-scripts', '--no-audit', '--no-fund', '--omit=optional'], check=True)
