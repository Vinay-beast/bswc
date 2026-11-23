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
| Python  | 3.11+        | the agent uses only the standard library (`requirements.txt` lists the dashboard's packages) |
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

Outputs follow the [output contract](../../docs/output-contract.md):

| File | Contents |
|------|----------|
| `outputs/<app>/run.json` | App name, repo URL, commit SHA, run started and updated times |
| `outputs/<app>/discovery/status.json` | `running` while the agent works, then `done` or `failed`, with summary counts and the artifact list |
| `outputs/<app>/discovery/sbom.cdx.json` | CycloneDX JSON SBOM from Syft (dev dependencies included) |
| `outputs/<app>/discovery/components.json` | `name`, `version`, `purl`, `ecosystem`, `licenses`, `locations` (source lockfile), `relationship` (direct/transitive), `scope` (prod/dev), `type`, `found_by` |
| `outputs/<app>/discovery/discovery_meta.json` | Repo URL, commit SHA, timestamps, tool versions, manifests found (each marked `original` or `generated`), npm lockfile status, component counts |

`workspace/` and `outputs/` are git-ignored. To browse the results, start the dashboard
(see [dashboard/README.md](../../dashboard/README.md)).

**Direct vs transitive.** An npm component is `direct` when it is declared in the `package.json`
next to its lockfile and is the top-level install (`node_modules/<name>`). Everything else in the
lockfile is `transitive`. `scope` is `dev` when npm marks the lockfile entry `dev`, which means it
is reachable only through `devDependencies`; for direct dependencies, the `package.json` section
decides. Both fields are null for non-npm components such as GitHub Actions.

**Original vs generated lockfiles.** A lockfile is `original` only if git tracks it in the target
repo. A lockfile left over from an earlier run on a reused clone is still reported as `generated`.

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
    ensure_npm_lockfiles, generate_sbom, normalize_components, classify_components,
    run_discovery,
)

path = fetch_repo("https://github.com/juice-shop/juice-shop")
manifests = discover_manifests(path)
locks = ensure_npm_lockfiles(path, manifests)
sbom = generate_sbom(path, Path("outputs/juice-shop/discovery/sbom.cdx.json"))
components = classify_components(path, normalize_components(sbom))

# or everything, including run.json and status.json:
meta = run_discovery("https://github.com/juice-shop/juice-shop")
```

A missing or failing tool raises `agents.discovery.ToolError` with a readable message.
