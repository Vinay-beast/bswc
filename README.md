# Software Supply Chain Guardian

Hackathon project: find, explain and fix software supply chain risk in an open-source application.
The pipeline has five stages: **Discover → Detect → Analyze → Remediate → Validate**.
This repository currently implements **Discover**, plus a local dashboard for its outputs.
The reference target is OWASP Juice Shop, but the Discover stage works for any public git repository.

Discover is deterministic and uses no LLM. Every fact comes from a file in the repository or
from a named tool, and the tool's command line and version are recorded next to it.

## Architecture

```
                         python -m agents.discover --repo <url>
                                        │  (one run_id for all three agents)
          ┌─────────────────────────────┼──────────────────────────────┐
          ▼                             ▼                              │
  ┌───────────────┐            ┌────────────────────┐                  │
  │  source-deps  │            │ artifact-inspector │                  │
  │───────────────│            │────────────────────│                  │
  │ clone/update  │            │ Dockerfiles,       │                  │
  │ manifests     │            │ compose files      │                  │
  │ lockfiles     │            │ container image    │                  │
  │  (--before)   │            │  (Syft + Trivy)    │                  │
  │ npm ls, go    │            │ GitHub workflows,  │                  │
  │  mod graph,   │            │  actions, pins     │                  │
  │  pip report   │            └─────────┬──────────┘                  │
  │ Syft, cdxgen, │                      │                             │
  │  Trivy (fs)   │                      │                             │
  └──────┬────────┘                      │                             │
         │   source_graph.json           │  ci_inventory.json          │
         │   tool_results.json           │  container.json             │
         ▼                               ▼                             ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ inventory: one node per purl, edges from lockfiles (ground truth),      │
  │ roots project:<path> / ci:github-actions / container:<image>            │
  │ → components.json, graph.json, paths.json, sbom.cdx.json (CycloneDX 1.6),│
  │   sbom.spdx.json (SPDX 2.3), coverage.json                              │
  └─────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                         dashboard (FastAPI + vanilla JS, read-only)
```

| Agent | Package | Output folder | README |
|---|---|---|---|
| source-deps | `agents/source_deps` | `outputs/<app_id>/source_deps/` | [agents/source_deps/README.md](agents/source_deps/README.md) |
| artifact-inspector | `agents/artifact_inspector` | `outputs/<app_id>/artifacts/` | [agents/artifact_inspector/README.md](agents/artifact_inspector/README.md) |
| inventory | `agents/inventory` | `outputs/<app_id>/inventory/` | [agents/inventory/README.md](agents/inventory/README.md) |
| dashboard | `dashboard/` | reads `outputs/` | [dashboard/README.md](dashboard/README.md) |

The file layout, `run.json` and `status.json` are described in [docs/output-contract.md](docs/output-contract.md).

## Tools

| Tool | Pinned version | Installed by | Used for |
|---|---|---|---|
| Syft | 1.57.2 | `scripts/install_tools.sh` → `tools/bin` (checksum-verified release tarball) | CycloneDX + SPDX SBOMs of the repository and of the container image |
| Trivy | 0.76.2 | `scripts/install_tools.sh` → `tools/bin` (checksum-verified release tarball) | `trivy fs` and `trivy image` CycloneDX SBOMs with dependency relationships (package listing only, no vulnerability scan) |
| cdxgen (@cyclonedx/cdxgen) | 12.9.3 | `scripts/install_tools.sh` → `tools/node_modules` (`npm install --ignore-scripts`, never global) | Recursive CycloneDX SBOM with a dependency tree; edge source for ecosystems we do not parse ourselves |
| git | any | system | Shallow clones, `ls-remote` (default branch, action tag/branch resolution) |
| Node.js / npm | Node 18+, npm 9+ | system | `npm install --package-lock-only --ignore-scripts`, `npm ls --package-lock-only` |
| Docker | optional | system | Pull and inspect the image. Without a daemon, Syft and Trivy read the registry directly |
| go | optional | system | `go mod graph`, `go list -m all` |
| pip / uv | optional | system | `pip install --dry-run --report --only-binary=:all:` / `uv pip compile --no-build` |
| mvn / gradle | optional | system | `dependency:tree` / `dependencies` (only when installed; wrappers are never run) |

Python packages are pinned in `requirements.txt`. `requirements-dev.txt` adds pytest and httpx.
Vendored JavaScript (`dashboard/static/vendor/`): Cytoscape.js 3.35.0 and cytoscape-dagre 4.1.0, which bundles dagre.

```sh
scripts/install_tools.sh          # syft, trivy, cdxgen into ./tools (idempotent; --force to reinstall)
scripts/check_tools.sh            # version table of everything the Discover stage can use
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

## Run

```sh
# Whole Discover stage (source-deps -> artifact-inspector -> inventory)
.venv/bin/python -m agents.discover --repo https://github.com/juice-shop/juice-shop --refresh

#   --ref R            branch, tag or commit SHA
#   --refresh          delete the clone and clone again (otherwise: fetch + move to the latest default branch)
#   --image REF        inspect this image instead of the app's published one
#   --build-image      build the image from the repo's Dockerfile (runs its RUN steps inside Docker)
#   --skip-container   no image inspection
#   --include-all      also scan test/, tests/, __tests__/, fixtures/, examples/, docs/, vendor/, third_party/
#   -v                 debug logging and full tracebacks

# Each agent on its own (the later ones attach to run.json's run_id)
.venv/bin/python -m agents.source_deps --repo <url>
.venv/bin/python -m agents.artifact_inspector --repo <url> [--image REF]
.venv/bin/python -m agents.inventory --repo <url>

# Dashboard
.venv/bin/uvicorn dashboard.app:app --port 8000      # http://localhost:8000

# Tests
.venv/bin/python -m pytest
```

Any error exits with code 1 and a one-line message (`-v` shows the traceback). The failing
agent's `status.json` is set to `failed` with the error. `python -m agents.discovery.cli`
still works as a deprecated alias.

## Reading the coverage report (`inventory/coverage.json`)

| Section | Meaning |
|---|---|
| `per_tool` | For each source (lockfile parser, npm ls, Syft, cdxgen, Trivy, workflow parser, ...): unique purls found and how many only that source found |
| `tool_agreement` | How many source components every SBOM tool found, and which components each tool missed |
| `lockfiles` | For every lockfile: unique packages in it vs. present in the inventory. This must be 100%; misses are listed |
| `npm_ls` | The same check against `npm ls --all --package-lock-only` |
| `unreachable_nodes` | Nodes with no path from any root (should be 0) |
| `unresolved_edges` | Declared dependencies with no installed target, usually optional or peer dependencies, with the reason |
| `ecosystems` | Per ecosystem: `full` (transitive tree from a lockfile or native resolver), `partial`, or `declared-only`, with the reason |
| `container` | Image packages missing from the source inventory and vice versa, including same-name/other-version drift |
| `sbom_validation` | CycloneDX 1.6 and SPDX 2.3 schema validation results |

## Known limitations per ecosystem

| Ecosystem | Resolution | Limitation |
|---|---|---|
| npm (package-lock v1–v3) | full, our own parser + `npm ls` cross-check | A lockfile we generate pins versions as of the commit date (`--before`), not what the authors actually installed |
| npm (yarn v1/berry, pnpm v6–v9) | full, our own parser | Less battle-tested than the npm parser. If parsing fails, edges fall back to cdxgen/Trivy and this is reported |
| Python | full only with poetry/uv/Pipfile/pdm locks, or a pip/uv dry-run | The dry-run resolves for this machine's Python and platform, wheels only (no sdist builds). Without pip/uv: declared-only |
| Go | full with `go mod graph` (MVS-selected versions) | Needs the `go` toolchain and network access to the module proxy |
| Maven / Gradle | declared-only unless `mvn`/`gradle` is installed | Build wrappers (`mvnw`, `gradlew`) are never executed. Edges come from cdxgen/Trivy |
| Cargo, RubyGems, Composer, NuGet, Swift, Pub, Hex | lockfile parsed by Syft/cdxgen/Trivy | No native resolver. Edges come from the SBOM tools (`edge_source` says which) |
| GitHub Actions | full, from `.github/workflows` | Other CI systems (GitLab, Jenkins, Azure, ...) are detected and listed but not parsed |
| Container | the image published by the project (or `--image` / `--build-image`) | A published release image can differ from the cloned commit; the selection reason is recorded |

## Safety

- No dependency installs anywhere. npm only ever runs with `--package-lock-only --ignore-scripts`. pip runs `--dry-run --only-binary=:all:`, so no `setup.py` executes. cdxgen runs with `--no-install-deps` under Node's permission model.
- Tools come from version-tagged release URLs with SHA-256 verification, or from pinned npm versions. Nothing is installed globally.
- Clones go to `workspace/`, outputs to `outputs/` (both git-ignored). The dashboard binds to localhost, serves files from `outputs/` only, and is read-only.
- `--build-image` is opt-in, because a Docker build runs the target's `RUN` steps (inside the build sandbox).
- The agents never push or open pull requests, and never write to the target repository's remote.

## Standalone Juice Shop scanner and graph viewer

The [`guardian_scanner/`](guardian_scanner/README.md) module provides a portable
Juice Shop scan that combines Syft, native npm SBOMs, cdxgen and read-only workflow
metadata resolution. Its self-contained light-theme dashboard includes a full
dependency graph, workspace filters, component inventory, workflow BOM and
source evidence. It complements the existing agents and FastAPI dashboard.

```bash
cd guardian_scanner
python -m pip install -r requirements.txt
python install_syft.py
python install_scan_tools.py
python fetch_juice_shop.py
python guardian.py --full --open
```

The verified scan recorded 1,657 distinct npm package/version identities and 25
workflow action references across 16 workflows. All 532 distinct package/version
pairs in the supplied 571-record reference were present. These are recorded scan
results; dependency resolution can change over time. ABOM integration is included,
with an explicit diagnostic and workflow fallback when the operating system blocks
its executable.

- [One-page project summary (PDF)](docs/guardian-project-summary.pdf)
- [Dependency graph preview](docs/guardian-dependency-graph.png)
- [Recorded benchmark metadata](docs/guardian-benchmark.json)

Generated reports, downloaded tools, repository checkouts and local configuration
are not committed. To run this module's tests:

```bash
python -m unittest discover -s guardian_scanner -p "test_*.py" -v
```
