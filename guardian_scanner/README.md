# Guardian — Juice Shop supply chain scanner

This module is a standalone scanner and self-contained report viewer. It sits
alongside the repository's existing `agents/` and FastAPI `dashboard/` packages.
Start commands from this directory: `cd guardian_scanner`.

The active report scans **the real OWASP Juice Shop source**, not reconstructed
manifests, Requests, or the synthetic polyglot fixture. The source is acquired at
commit `c9f99228d9d56afb5f5ca7925376292f7fa44b13`; its archive URL and SHA-256 are
recorded in `GUARDIAN_SOURCE.json` inside the acquired source directory.

The scanner remains capable of basic Syft scans of other repositories when given
an explicit `--repo` and `--no-full`, but Juice Shop is the configured default.

## Run the complete scan

Requirements: Python 3.11+, internet for initial acquisition, package metadata and
workflow metadata, and the local scanning tools.

```powershell
python -m pip install -r requirements.txt
python install_syft.py
python install_scan_tools.py
python fetch_juice_shop.py
python guardian.py --full --reference "path/to/reference-bom.json" --open
```

After setup, `python guardian.py --open` defaults to the complete Juice Shop scan.
The configured target and optional comparison path are stored in the ignored
`.guardian-target.json`. Source acquisition defaults to a short
`Downloads/guardian-juice-shop` directory under the current user home to avoid
Windows path-length problems. `--reference` is comparison-only and never adds components
to scan results. The supplied reference file is not modified.

`fetch_juice_shop.py --commit <40-character SHA> --dest <empty directory>` can
acquire another Juice Shop revision. The source archive is checked for path
traversal. Acquisition refuses to overwrite an existing, different source tree.

## How coverage is expanded

1. **Resolve actual dependency metadata.** Both backend and frontend manifests
   receive npm lockfiles using `npm install --package-lock-only --package-lock=true
   --ignore-scripts --include=dev --include=optional --include=peer`. The upstream
   `package-lock=false` setting is explicitly overridden. Application scripts,
   builds and package lifecycle scripts do not run; `node_modules` is not installed.
2. **Syft 1.57.2** scans the complete source tree and generated lockfiles, including
   supported binary/archive and GitHub Actions catalogers. Original output is kept.
3. **npm 11.19.1** independently generates backend and frontend CycloneDX documents
   directly from lockfiles. A backend production-only view is also retained.
4. **cdxgen 12.9.3** independently scans JavaScript dependency evidence and GitHub
   workflows. Automatic dependency installation and Babel usage analysis are disabled.
5. **ABOM 0.2.1 adapter** attempts the requested Actions BOM collector with recursive
   resolution. On this Windows machine, Application Control blocks its executable.
   This failure is recorded in `abom.log` and tool diagnostics; policy is not bypassed.
6. **Guardian workflow metadata resolver** follows workflow `uses`, reusable
   workflows and composite-action `uses` recursively, reads local/remote YAML,
   and generates a standalone CycloneDX 1.6 workflow BOM. Source URLs and metadata
   SHA-256 hashes are retained. No action code or workflow step runs.
7. **Merge by identity.** Encoded PURLs and tool-specific qualifiers are normalized.
   Duplicate package/version identities are combined while discovery files,
   workspace scopes, licenses, hashes and tool provenance are retained. GitHub
   action subpaths remain distinct. Declared SHA pins take precedence over version
   labels appearing only in YAML comments.

The portable Node.js and ABOM installers verify official published archive
checksums. cdxgen is installed locally through npm with package scripts disabled;
its package lock/integrity metadata remains under `.tools/cdxgen/`.

## Current independently measured result

| Measure | Result |
| --- | ---: |
| Distinct npm package/version identities | 1,657 |
| Distinct workflow action references | 25 |
| Workflow files | 16 |
| Files inspected | 1,501 |
| Recognized source files | 855 |
| Static import references | 4,036 |
| Recorded dependency relationships in the merged graph | 4,699 |
| Supplied reference package/version identities matched | 532 / 532 |

The supplied SBOM has **571 package records representing 532 distinct name/version
pairs**. The earlier Guardian snapshot listed only **161 direct declarations**
from two manifests, with zero resolved versions or transitive package edges.
That explains the original large difference.

The new scan includes frontend, development, optional and peer dependencies as
well as backend packages, so its scope exceeds the supplied reference. All 532
reference identities were found independently: the reference is used only after
collection for comparison, never imported as scanner evidence. A larger count is
not by itself proof of completeness.

## Active report and artifacts

Open `output/dashboard.html`. The minimal light-theme dashboard includes Supply
chain, Dependency graph, Component inventory, Workflow BOM, Codebase analysis,
CycloneDX SBOM, and Scan details. It is self-contained and works directly from disk.

- `cyclonedx-sbom.json`: merged CycloneDX 1.7 supply chain BOM, including package,
  project, workflow and file evidence components. Package totals are reported
  separately from workflow/file entities.
- `dependency-graph.json`: typed containment, evidence, declaration and dependency
  edges with per-tool provenance. Evidence edges are not exported as dependencies.
- `source-analysis.json`: included file hashes, sizes, line counts, import and build
  references. Python imports use ASTs; other supported languages use patterns.
- `workflow-recursive.cdx.json`: standalone CycloneDX 1.6 workflow/action BOM.
- `workflow-resolution.json`: metadata source URLs/hashes, recursion results and gaps.
- `syft-sbom.json`, `syft-sbom.cdx.json`: original Syft results.
- `npm-backend.cdx.json`, `npm-frontend.cdx.json`: independent npm lockfile SBOMs.
- `npm-backend-production.cdx.json`: narrower backend production view.
- `cdxgen-packages.cdx.json`, `cdxgen-workflows.cdx.json`: original cdxgen output.
- `reference-comparison.json`: exact npm name/version comparison with the supplied file.
- `evidence-index.json`, `agent-trace.json`, `scan-config.json`, and tool logs:
  source revision, collection scope, execution details and diagnostics.

The network defaults to **All matching packages**. Optional 80- and 350-package
overviews reduce clutter; the graph reports how many matching packages are outside
the selected view. Isolated packages remain visible in the recorded-dependency
view. Selected neighborhood intentionally shows only nearby relationships. Exported
JSON always retains the full graph. Tables paginate at 100 rows. Search, workspace, ecosystem,
version evidence and development filters are supported. Recorded package arrows
and dashed declaration/evidence edges are visually distinct.

Generated scans, downloaded tool binaries, target source trees, machine-local
configuration and retired reports are excluded from version control. Test fixtures
and legacy inputs remain only for regression tests; they are not Juice Shop scan
input. The documented measurements describe the verified scan, not bundled artifacts.

## Limits of the evidence

- Lockfile versions are resolved at scan time from current registry metadata.
  They do not prove installation, shipping, runtime reachability or equality to
  the historical environment behind another SBOM.
- Workflow metadata discovery does not establish the contents of bundled action
  JavaScript, arbitrary shell downloads, actual CI execution or deployment provenance.
  Mutable refs remain mutable; content hashes of fetched metadata are recorded.
- Docker base images are recorded references. Container OS packages are not added
  without separately scanning those images. No application or container is executed.
- Source import extraction is not a call graph, semantic code analysis, vulnerability
  scan, secret scan or malicious-code verdict. Python 2 fixtures that cannot be
  parsed by Python 3 are reported explicitly.
- Source inventory skips symlinks/junctions and configured exclusions. Text analysis
  is capped at 2 MB per UTF-8 file; larger files are hashed and still available to
  Syft. Archive recursion is capped at four levels. Avoid source edits during a scan.
- ABOM is integrated but could not execute under this machine's application-control
  policy. cdxgen and the read-only resolver supplied workflow evidence instead.

## Verification

```powershell
python -m unittest -v test_guardian.py test_scanner.py test_full_scan.py
```

Regression tests cover actual Syft cataloging, lockfile associations, recursive
source discovery, scopes, exclusions, dependency direction, PURL normalization,
GitHub action subpaths, SHA pins versus comment tags, and local composite actions.
The merged BOM passed the official CycloneDX 1.7 JSON Schema and dependency-reference
integrity checks. Browser QA covered all seven sections, graph inspection, workspace
filters, pagination, workflow BOM export, reference coverage and mobile layouts.

## Other scan modes

```powershell
# Read existing evidence without external enrichment or new lockfile resolution.
python guardian.py --repo "C:\path\to\repository" --no-full --out ./output-other

# Original npm snapshot workflow, retained solely for compatibility/testing.
python guardian.py --engine legacy --repo ./snapshots --out ./output-legacy
```

## Tools consulted

- [Syft](https://github.com/anchore/syft)
- [ABOM](https://github.com/JulietSecurity/abom)
- [npm sbom](https://docs.npmjs.com/cli/v11/commands/npm-sbom/)
- [cdxgen](https://github.com/cdxgen/cdxgen)
