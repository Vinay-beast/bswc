# Discovery Agent

First stage of the Software Supply Chain Guardian. Given a Git repository URL it:

1. Shallow-clones the repo into `workspace/<repo-name>/` (reused on later runs).
2. Finds package manifests and lockfiles (npm, PyPI, Maven/Gradle, Go, Cargo, Gem, Composer, NuGet), skipping `node_modules`.
3. Generates a `package-lock.json` for any `package.json` that has no lockfile next to it.
4. Runs Syft to produce a CycloneDX JSON SBOM.
5. Writes a flat component list and a metadata file.

## Setup

| Tool    | Version used | Notes |
|---------|--------------|-------|
| Python  | 3.11+        | standard library only (`requirements.txt` has no packages) |
| git     | any recent   | |
| Node/npm| Node 18+ / npm 9+ | used only for `--package-lock-only` |
| Syft    | v1.18.1 (pinned) | `scripts/install_syft.sh` installs it to `~/.local/bin` |

```sh
scripts/install_syft.sh          # or: scripts/install_syft.sh v1.x.y
```

The agent also looks in `~/.local/bin` when a tool isn't on `PATH`.

## Usage

```sh
python -m agents.discovery.cli --repo https://github.com/juice-shop/juice-shop
python -m agents.discovery.cli --repo <url> --ref v17.0.0   # branch, tag or commit SHA
python -m agents.discovery.cli --repo <url> --refresh       # delete the clone and re-clone
```

Outputs, in `outputs/<app-name>/`:

| File | Contents |
|------|----------|
| `sbom.cdx.json` | CycloneDX JSON SBOM from Syft |
| `components.json` | `name`, `version`, `purl`, `ecosystem`, `licenses`, `locations` (source manifest/lockfile), `type`, `found_by` |
| `discovery_meta.json` | repo URL, commit SHA, timestamps, tool versions, manifests found (each marked `original` or `generated`), npm lockfile status, component counts |

`workspace/` and `outputs/` are git-ignored.

## Safety

Target repositories are untrusted. The agent never runs `npm install` without `--ignore-scripts`.
Lockfiles are generated with:

```
npm install --package-lock-only --ignore-scripts --no-audit --no-fund --package-lock=true
```

`--package-lock-only` resolves the dependency tree without downloading packages into `node_modules`.
`--package-lock=true` overrides a repo `.npmrc` that turns lockfiles off (Juice Shop has one).
If npm fails with an `ERESOLVE` peer-dependency conflict, the agent retries once with `--legacy-peer-deps` and records the exact command in the metadata.
npm still reads the target repo's `.npmrc`, so a hostile repo could point it at a different registry. That only affects version resolution, not code execution.

## Using the stages from an orchestrator

```python
from pathlib import Path
from agents.discovery import (
    fetch_repo, get_repo_info, discover_manifests,
    ensure_npm_lockfiles, generate_sbom, normalize_components, run_discovery,
)

path = fetch_repo("https://github.com/juice-shop/juice-shop")
manifests = discover_manifests(path)
locks = ensure_npm_lockfiles(path, manifests)
sbom = generate_sbom(path, Path("outputs/juice-shop/sbom.cdx.json"))
components = normalize_components(sbom)
```

A missing or failing tool raises `agents.discovery.ToolError` with a readable message.
