"""Fetch the real Juice Shop source archive at an explicit commit, recording provenance."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
PINNED_COMMIT = 'c9f99228d9d56afb5f5ca7925376292f7fa44b13'


def fetch(commit=PINNED_COMMIT, destination=None):
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('An explicit 40-character Git commit SHA is required')
    root = Path(destination or Path.home() / 'Downloads' / 'guardian-juice-shop').resolve()
    marker = root / 'GUARDIAN_SOURCE.json'
    if marker.exists() and json.loads(marker.read_text(encoding='utf-8'))['commit'] == commit:
        (ROOT / '.guardian-target.json').write_text(json.dumps({'repositoryPath': str(root), 'commit': commit}, indent=2) + '\n', encoding='utf-8')
        return root
    if root.exists() and any(root.iterdir()):
        raise RuntimeError('Destination is not empty; source was not overwritten: ' + str(root))
    url = f'https://codeload.github.com/juice-shop/juice-shop/tar.gz/{commit}'
    print('Downloading Juice Shop source at ' + commit, flush=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Guardian/3'}), timeout=120) as response:
        data = response.read()
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for entry in archive.getmembers():
            if not entry.isfile():
                continue
            relative = Path(*Path(entry.name).parts[1:])
            target = (root / relative).resolve()
            if not target.is_relative_to(root):
                raise RuntimeError('Unsafe source archive entry')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(entry).read())
    marker.write_text(json.dumps({'repository': 'https://github.com/juice-shop/juice-shop', 'commit': commit,
                                 'archiveUrl': url, 'archiveSha256': hashlib.sha256(data).hexdigest(),
                                 'note': 'Original source archive. Guardian may add npm lockfiles with lifecycle scripts disabled.'}, indent=2) + '\n', encoding='utf-8')
    (ROOT / '.guardian-target.json').write_text(json.dumps({'repositoryPath': str(root), 'commit': commit}, indent=2) + '\n', encoding='utf-8')
    print('Source ready: ' + str(root), flush=True)
    return root


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', default=PINNED_COMMIT)
    parser.add_argument('--dest', type=Path)
    args = parser.parse_args()
    fetch(args.commit, args.dest)
