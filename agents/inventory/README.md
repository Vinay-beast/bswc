# inventory agent

Merges the source-deps and artifact-inspector outputs into the single source of truth that later
stages use. Output: `outputs/<app_id>/inventory/`.

```sh
.venv/bin/python -m agents.inventory --repo <url> [--run-id ID]
```

## Graph model

- **Roots**: `project:<path>` (one per project and workspace member), `ci:github-actions`
  (deduplicated actions), and `container:<image>` (its OS packages, plus application packages that
  were not found in the source).
- **Nodes**: one per canonical purl (`pkg:npm/%40scope/name@1.2.3`). The same purl reached from
  several projects or install paths is one node with several occurrences.
- **Edges**: `{from, to, type: prod|dev|optional|peer|uses|contains, range, edge_source}`.
- **Relationship and depth**: `direct` (depth 1) or `transitive`, by minimum BFS depth from the
  project roots. Nodes reachable only from the CI or container roots get `ci` or `container`.
- **Scope**: `prod` if reachable through prod edges only, then `peer`, then `optional`; `dev` only
  if reachable exclusively through at least one dev edge.
- **Paths** (`paths.json`): for each node and each root that reaches it, one shortest path (BFS)
  and the number of distinct paths. Paths are counted on the cycle-condensed graph and capped at
  1000 (reported as `"1000+"`).

## Outputs

| File | Content |
|---|---|
| `components.json` | One entry per purl, with these fields:<br>• occurrences (project, lockfile, install path, resolved URL, integrity, alias)<br>• `declared_in`<br>• origin (registry hosts; flags for non-default registry, git, tarball, file, link, http)<br>• integrity (present + algorithm)<br>• licenses with their sources<br>• `found_by` / `sources`<br>• relationship, depth, scope, dependents/dependencies counts<br>• `in_container` |
| `graph.json` | `roots`, `nodes`, `edges`, `stats` (counts, edges by type, max depth, top 20 by dependents) |
| `paths.json` | `{paths: {node: {root: {shortest: [...], count}}}}` |
| `sbom.cdx.json` | Merged CycloneDX 1.6. Metadata covers the app, every tool with its version, the timestamp, and properties for the repo URL, commit SHA and run_id. Components use `bom-ref = purl`. The full `dependencies` section is built from graph.json. The container is a component with its OS packages nested inside. Validated with cyclonedx-python-lib's `JsonStrictValidator` |
| `sbom.spdx.json` | SPDX 2.3 with `DESCRIBES`, `DEPENDS_ON` (edge type in the comment) and `CONTAINS`. Validated against the official SPDX 2.3 JSON schema (vendored in `schemas/`), plus a check that every relationship points at a known element |
| `coverage.json` | Proof of completeness; see the root README |
