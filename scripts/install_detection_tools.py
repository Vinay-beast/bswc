"""Install pinned, checksum-verified Windows Trivy and OSV-Scanner executables.

zizmor, Bandit and CVSS helpers are Python dependencies in requirements.txt.
Application-control blocks are reported during a scan; this script never bypasses them.
"""
import hashlib
import io
from pathlib import Path
import platform
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def download(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Guardian-Detect/1'}), timeout=120) as response:
        return response.read()


def install(repo, version, asset, checksum, name):
    base = f'https://github.com/{repo}/releases/download/v{version}'
    print(f'Installing {name} {version} ...', flush=True)
    sums = download(base + '/' + checksum).decode()
    expected = next((line.split()[0] for line in sums.splitlines() if len(line.split()) >= 2 and line.split()[-1].lstrip('*') == asset), None)
    if not expected:
        raise RuntimeError('Checksum missing for ' + asset)
    data = download(base + '/' + asset)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Checksum mismatch for ' + asset)
    if asset.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            data = archive.read(name + '.exe')
    destination = ROOT / 'tools' / 'bin'
    destination.mkdir(parents=True, exist_ok=True)
    (destination / (name + '.exe')).write_bytes(data)


if __name__ == '__main__':
    if platform.system() != 'Windows' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('Install Trivy and OSV-Scanner using their official platform instructions; existing PATH tools are supported.')
    install('aquasecurity/trivy', '0.76.2', 'trivy_0.76.2_windows-64bit.zip', 'trivy_0.76.2_checksums.txt', 'trivy')
    install('google/osv-scanner', '2.7.1', 'osv-scanner_windows_amd64.exe', 'osv-scanner_SHA256SUMS', 'osv-scanner')
