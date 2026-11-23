# Output contract

Every agent writes its results under `outputs/<app_id>/<agent-folder>/`. The dashboard and the
orchestrator read only these files, so an agent that follows this contract shows up in the
dashboard without dashboard changes.

`app_id` is `<owner>__<repo>` derived from the git URL (`https://github.com/juice-shop/juice-shop`
→ `juice-shop__juice-shop`; a GitLab subgroup `group/sub/proj` → `group-sub__proj`), so
`orgA/app` and `orgB/app` do not collide. The same id names the clone in `workspace/`.

## Layout

```
outputs/<app_id>/
├── run.json                    one per app; identifies the current run
├── source_deps/                agent "source-deps"          (stage discover)
│   ├── status.json
│   ├── source_meta.json  source_graph.json  tool_results.json
│   └── raw/  syft.cdx.json  syft.spdx.json  cdxgen.cdx.json  trivy-fs.cdx.json  native/...
├── artifacts/                  agent "artifact-inspector"   (stage discover)
│   ├── status.json
│   ├── dockerfile_analysis.json  ci_inventory.json  container.json
│   └── raw/  syft-image.cdx.json  syft-image.spdx.json  trivy-image.cdx.json
└── inventory/                  agent "inventory"            (stage discover)
    ├── status.json
    └── components.json  graph.json  paths.json  sbom.cdx.json  sbom.spdx.json  coverage.json
```

A folder is an agent only if it contains `status.json`. Agents are matched to pipeline stages by
the `stage` field. When an agent starts, it deletes its own folder, so no artifact from an older
run survives inside it. All JSON is written atomically (temp file + rename) with mode `0644`.

## `run.json`

Created by the first agent of a run (source-deps, or the orchestrator). Later agents merge into it;
they never replace it.

| Field | Meaning |
|---|---|
| `app_id`, `display_name` | `juice-shop__juice-shop`, `juice-shop` |
| `repo_url`, `owner`, `repo`, `host` | Parsed from the URL |
| `ref`, `default_branch` | Requested ref (if any) and the remote default branch |
| `run_id` | `<UTC yyyymmddThhmmssZ>-<short SHA>`, e.g. `20261123T110206Z-c9f9922`, shared by every agent of the run |
| `commit_sha`, `commit_date` | The checked-out commit |
| `started_at`, `finished_at`, `updated_at` | ISO 8601 UTC |
| `workspace` | Local clone path |

## `status.json` (every agent)

```json
{
  "agent": "inventory",
  "stage": "discover",
  "run_id": "20261123T110206Z-c9f9922",
  "state": "done",
  "started_at": "2026-11-23T11:05:01+00:00",
  "finished_at": "2026-11-23T11:06:12+00:00",
  "summary": { "components": 1655, "direct": 154, "max_depth": 10 },
  "coverage": { "lockfile_coverage_ok": true, "unreachable_nodes": 0 },
  "warnings": [],
  "artifacts": [
    { "name": "sbom.cdx.json", "path": "inventory/sbom.cdx.json", "type": "sbom", "bytes": 2952685 }
  ],
  "error": null
}
```

| Field | Meaning |
|---|---|
| `agent` | Agent name (`source-deps`, `artifact-inspector`, `inventory`, ...) |
| `stage` | `discover`, `detect`, `analyze`, `remediate` or `validate` |
| `run_id` | The run this status belongs to. If it differs from `run.json`'s `run_id`, the dashboard marks the agent **Stale** |
| `state` | `pending`, `running`, `done` or `failed`. Written as `running` at start, then `done` or `failed` |
| `started_at`, `finished_at` | ISO 8601; `finished_at` is null while running |
| `summary` | Flat key → number/string pairs shown as tiles |
| `coverage` | Agent-specific completeness facts (brief; the full report is an artifact) |
| `warnings` | Non-fatal problems: a tool failed, a resolver missing, no image found, ... |
| `artifacts` | Files the agent produced (see below) |
| `error` | Error message when `state` is `failed` |

Artifact entry: `name` (the file's basename, unique per agent, used in
`/api/runs/<app>/<agent>/artifact/<name>`), `path` (relative to `outputs/<app_id>/`), `type`
(`sbom`, `sbom-spdx`, `json`, `graph`, `inventory` or `report`) and `bytes`. The dashboard
serves only files listed here.

```python
from agents.common import AgentRun

with AgentRun(app_id, "detection", "detection", "detect", run_id) as status:   # state=running
    ...                                     # write files into status.dir
    status.warn("feed X unavailable")
    status.add_artifact("findings.json", "report")
    status.done({"vulnerabilities": 42}, coverage={...})
# an exception inside the block sets state=failed with the error and re-raises
```

## Key inventory formats

**`inventory/components.json`**: one entry per unique purl:

```json
{
  "purl": "pkg:npm/qs@6.16.2", "name": "qs", "version": "6.16.2", "ecosystem": "npm",
  "relationship": "transitive", "depth": 2, "scope": "prod",
  "dependents_count": 2, "dependencies_count": 2,
  "declared_in": [],
  "occurrences": [{ "project": "project:.", "lockfile": "package-lock.json",
                    "install_path": "node_modules/qs", "resolved": "https://registry.npmjs.org/qs/-/qs-6.16.2.tgz",
                    "integrity": "sha512-..." }],
  "origin": { "resolved_urls": ["https://registry.npmjs.org/qs/-/qs-6.16.2.tgz"],
              "registry_hosts": ["registry.npmjs.org"], "flags": [] },
  "integrity": { "present": true, "algorithms": ["sha512"], "source": "lockfile" },
  "licenses": ["BSD-3-Clause"], "license_sources": { "syft": ["BSD-3-Clause"] },
  "found_by": ["cdxgen", "lockfile-parser", "npm-ls", "syft", "trivy"],
  "sources": { "syft": ["package-lock.json"] },
  "in_container": true,
  "reachable_from": ["project:.", "project:frontend"]
}
```

`origin.flags` can be `non-default-registry`, `git`, `tarball-url`, `file`, `link` or `insecure-http`.
GitHub Actions nodes carry `ci: {pin_type, pin_source, publisher, ref_comment, uses}`; image-only
packages carry `container_only` and `container_kind` (`os` / `application`).

**`inventory/graph.json`**: `{roots, nodes, edges, stats}`. Edge:
`{from, to, type: prod|dev|optional|peer|uses|contains, range, edge_source}`. `edge_source` is one
of `lockfile-parser`, `go-mod-graph`, `pip-report`, `cdxgen`, `trivy`, `syft`, `workflow-parser`,
`syft-image`/`trivy-image` or `location-only`.

**`inventory/paths.json`**: `{cap: 1000, roots: [...], paths: {<node>: {<root>: {shortest: [ids], count: n | "1000+"}}}}`.

**`inventory/coverage.json`**: see "Reading the coverage report" in the root README.
