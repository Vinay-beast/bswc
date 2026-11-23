"""Install a pinned official Syft binary locally, verifying its release SHA-256."""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import platform
import re
import tarfile
import urllib.request
import zipfile

VERSION = '1.57.2'
ROOT = Path(__file__).resolve().parent


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'Guardian-SBOM/2'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def install(version=VERSION, destination=None):
    version = version.removeprefix('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Use an explicit release version, such as 1.57.2')
    system = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
    arch = {'AMD64': 'amd64', 'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine())
    if not system or not arch:
        raise RuntimeError('Unsupported platform; install Syft using https://oss.anchore.com/docs/installation/syft/')
    extension = 'zip' if system == 'windows' else 'tar.gz'
    asset = f'syft_{version}_{system}_{arch}.{extension}'
    base = f'https://github.com/anchore/syft/releases/download/v{version}'
    print(f'Downloading official Syft {version} for {system}/{arch} ...', flush=True)
    checksums = download(f'{base}/syft_{version}_checksums.txt').decode('utf-8')
    expected = next((line.split()[0] for line in checksums.splitlines()
                     if line.split()[-1].lstrip('*') == asset), None)
    if not expected:
        raise RuntimeError(f'No checksum found for {asset}')
    archive = download(f'{base}/{asset}')
    actual = hashlib.sha256(archive).hexdigest()
    if actual != expected:
        raise RuntimeError('Syft download checksum mismatch; executable was not installed')
    filename = 'syft.exe' if system == 'windows' else 'syft'
    if extension == 'zip':
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            binary = source.read(filename)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
            stream = source.extractfile(filename)
            if stream is None:
                raise RuntimeError('Syft binary missing from release archive')
            binary = stream.read()
    destination = Path(destination) if destination else ROOT / '.tools' / 'syft' / version
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / filename
    target.write_bytes(binary)
    target.chmod(0o755)
    (destination / 'release.txt').write_text(f'{base}/{asset}\nSHA256 {actual}\n', encoding='utf-8')
    print(f'Installed: {target}\nVerified archive SHA256: {actual}')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default=VERSION)
    args = parser.parse_args()
    install(args.version)
