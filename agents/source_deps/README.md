# source-deps agent

Source dependencies of one repository: what is declared, what is locked, how it is connected, and
which tools agree. Output: `outputs/<app_id>/source_deps/`.

```sh
.venv/bin/python -m agents.source_deps --repo <url> [--ref R] [--refresh] [--include-all] [-v]
```

## Steps

1. **Clone or update** into `workspace/<app_id>/` (`app_id = <owner>__<repo>`, e.g. `juice-shop__juice-shop`).
   https, ssh (`git@host:o/r.git`, `ssh://`) and `git://` URLs are accepted; anything else is rejected.
   A reused clone is fetched (depth 1) and moved to the latest commit of the remote default branch.
   The previous and new SHAs are recorded. When the commit changes, untracked files (old generated
   lockfiles) are removed with `git clean -fdx`.
2. **Manifests and projects**. Test, example, doc and vendored folders are skipped unless `--include-all` is given;
   the skipped folders are recorded. npm/yarn/pnpm workspaces (`workspaces` in package.json,
   `pnpm-workspace.yaml`) form one project with members, so members get no lockfiles of their own.
3. **Resolvers** (`resolvers.py`, one class per ecosystem, add new ones to `RESOLVERS`):
   - npm: if no lockfile is committed, generate one reproducibly:
     `npm install --package-lock-only --ignore-scripts --no-audit --no-fund --package-lock=true --before=<HEAD commit date>`,
     retried with `--legacy-peer-deps` on `ERESOLVE`. The command, `--before` date, registry
     (`npm config get registry`) and commit are recorded. `npm ls --all --json --package-lock-only` is saved for cross-checking.
   - Python: `uv pip compile --no-build` or `python3 -m pip install --dry-run --ignore-installed --only-binary=:all: --report`
     (no installs, no builds). Without either, a coverage gap is recorded.
   - Go: `go mod graph` + `go list -m all` (MVS-selected versions only).
   - Maven/Gradle: `mvn dependency:tree` / `gradle dependencies` only if installed; otherwise a gap is recorded.
4. **Lockfile graph** (`lockfiles.py`): the authoritative edges. For npm package-lock v2/v3, every
   dependency is resolved with Node's algorithm: `P/node_modules/<name>`, then each ancestor's
   `node_modules`, then the root. Edge types are prod/dev/optional/peer, each with the declared range.
   Links, bundled dependencies and aliases are handled, and missing optional/peer dependencies
   are recorded as unresolved. v1 lockfiles, yarn v1/berry and pnpm v6–v9 are parsed too.
5. **SBOM tools in parallel** (each with a timeout; a failure only produces a warning):
   - `syft scan dir:<repo> -o cyclonedx-json@1.6=raw/syft.cdx.json -o spdx-json=raw/syft.spdx.json` (dev dependencies included)
   - `cdxgen -r --no-install-deps --spec-version 1.6 --no-babel` with `CDXGEN_SECURE_MODE=true`, Node `--permission`
     (read: repo + tools + temp; write: temp + output file), `NPM_INSTALL_ARGS=--ignore-scripts`, `FETCH_LICENSE=false`
   - `trivy fs --format cyclonedx --include-dev-deps --skip-db-update --offline-scan` (package listing only)
6. **Merge**: tool components are matched to lockfile nodes by canonical purl, and `found_by`,
   licenses, locations and hashes are added. Components only a tool found are kept and listed.
   Edges come from cdxgen/Trivy/Syft only where no authoritative parser covered the nodes;
   `edge_source` records which.

## Outputs

| File | Content |
|---|---|
| `source_meta.json` | Repo and fetch facts, tool versions, manifests (original/generated), skipped dirs, projects, lockfile generation records, native resolver results, every tool run (command, version, duration, status), warnings |
| `source_graph.json` | Roots (projects), nodes (purl, occurrences with install path / resolved URL / integrity, declared_in, found_by), edges, unresolved edges |
| `tool_results.json` | Each tool's normalised components and edges |
| `raw/` | `syft.cdx.json`, `syft.spdx.json`, `cdxgen.cdx.json`, `trivy-fs.cdx.json`, `native/npm-ls-*.json`, `native/go-mod-graph-*.txt`, `native/pip-report-*.json` |
