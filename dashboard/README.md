# Dashboard

A local, read-only view of `outputs/`. FastAPI backend; plain HTML, CSS and JavaScript frontend
with no build step. Cytoscape.js 3.35.0 and cytoscape-dagre 4.1.0 are vendored in `static/vendor/`,
so the dashboard works offline.

```sh
.venv/bin/python -m agents.discover --repo https://github.com/juice-shop/juice-shop   # produce outputs
.venv/bin/uvicorn dashboard.app:app --port 8000                                       # http://localhost:8000
```

`GUARDIAN_OUTPUTS=/path/to/outputs` reads another folder. The page polls every 5 seconds.

## Layout

- **Top bar**: app selector, repository, short commit, `run_id`, last run time.
- **Pipeline**: Discover, Detect, Analyze, Remediate, Validate. Each card lists its agents with a badge:
  Pending, Running, Done, Failed, or Stale (the agent's `run_id` differs from `run.json`).
- **Discover tabs**:
  1. **Overview**: tiles (unique components, direct, transitive, max depth, edges, ecosystems,
     container packages, workflows, actions not SHA-pinned), per-source coverage, lockfile
     coverage (the badge is green only at 100%), unresolved/unreachable counts, ecosystems, warnings.
  2. **SBOM**: metadata and validation result of the merged CycloneDX and the SPDX export,
     component counts by type and ecosystem, per-tool comparison, and downloads of every SBOM
     (merged and raw).
  3. **Components**: one row per purl, with search, filters (type, ecosystem, scope, in container),
     sorting and pagination. Clicking a row opens a drawer with occurrences, resolved URLs, tool
     locations and the dependency path from each root as a breadcrumb.
  4. **Dependency graph**:
     - The default view shows the roots and their direct dependencies, one band per root.
     - Clicking a node expands or collapses it (depth 1–3).
     - Search finds a package and shows its shortest paths from the roots.
     - Colour shows the relationship, size the number of dependents, and dashed/dotted lines dev/optional/peer edges.
     - There is a side panel for the selected node, a lazy tree view, and the top 20 most depended-on packages.
  5. **Container**: image reference and digest, why it was chosen, OS, base image pinning,
     OS vs application counts, a searchable package table, and Dockerfile/compose findings.
  6. **CI/CD**: workflows (triggers, permissions), deduplicated actions (ref, pin type, publisher,
     used in) and pattern facts with the job's `if:` condition.

## API (read-only)

| Endpoint | Returns |
|---|---|
| `GET /api/runs` | Apps: `run.json` + agent folder names |
| `GET /api/runs/{app}` | `{run, agents: {folder: status.json + stale}}` |
| `GET /api/runs/{app}/{agent}/status` | One `status.json` (+ `stale`) |
| `GET /api/runs/{app}/{agent}/artifact/{name}[?download=true]` | An artifact listed in `status.json` |
| `GET /api/runs/{app}/{agent}/sbom-summary/{name}` | Format, spec, serial, timestamp, tools, counts of a CycloneDX/SPDX artifact |
| `GET /api/runs/{app}/{agent}/components-table` | Compact rows of `components.json` |
| `GET /api/runs/{app}/{agent}/component?id=<purl>` | One full component record |
| `GET /api/runs/{app}/{agent}/graph/summary` | Roots + graph stats (no nodes) |
| `GET /api/runs/{app}/{agent}/graph/node?id=<id>&depth=0-3` (or `/graph/node/<purl>`) | Neighbourhood: node, parents, children up to `depth` (max 400 nodes) |
| `GET /api/runs/{app}/{agent}/graph/children?id=<id>` | Direct children (tree view) |
| `GET /api/runs/{app}/{agent}/graph/search?q=<text>` | Matching nodes |
| `GET /api/runs/{app}/{agent}/graph/path?to=<purl>` | Shortest path from every root + distinct path counts |

The graph endpoints work for any agent that lists `graph.json` (and `paths.json` /
`components.json`) in its status. The browser never loads the full graph.

**Safety**:
- App and agent names must match `[A-Za-z0-9][A-Za-z0-9._-]*`.
- Artifacts are looked up by name in `status.json`, never taken from the URL as a path.
- Every resolved path must stay inside `outputs/<app>/`.
- Node ids are only used as dictionary keys.
- `tests/test_dashboard_api.py` covers path-traversal rejection.
