# Output contract

Every agent writes its results under `outputs/<app-name>/`. The dashboard and the
orchestrator read only these files, so an agent that follows this contract shows up
in the dashboard without any dashboard changes.

`<app-name>` is the repository name taken from the URL (`https://github.com/juice-shop/juice-shop` → `juice-shop`).

## Layout

```
outputs/<app-name>/
├── run.json                    # one per app, shared by all agents
├── discovery/                  # one folder per agent
│   ├── status.json             # required in every agent folder
│   ├── sbom.cdx.json
│   ├── components.json
│   └── discovery_meta.json
└── <next-agent>/
    ├── status.json
    └── ...
```

A folder counts as an agent only if it contains `status.json`. The dashboard finds agents
by scanning for those folders and matches each to a pipeline stage by its `stage` field.

## `run.json`

Written by the first agent of a run, and merged into (never replaced) by later agents.

| Field | Type | Meaning |
|-------|------|---------|
| `app_name` | string | Folder name under `outputs/` |
| `repo_url` | string | Repository URL that was analysed |
| `ref` | string? | Branch, tag or SHA requested (omitted when the default branch was used) |
| `commit_sha` | string | Full SHA of the checked-out commit |
| `commit_date` | ISO 8601 | Commit timestamp |
| `started_at` | ISO 8601 | When the current run started |
| `updated_at` | ISO 8601 | Last time any agent wrote a status update |

## `status.json`

The same schema for every agent.

```json
{
  "agent": "discovery",
  "stage": "discover",
  "state": "done",
  "started_at": "2026-11-23T10:00:01+00:00",
  "finished_at": "2026-11-23T10:00:40+00:00",
  "summary": { "components": 1975, "direct": 161, "transitive": 1761 },
  "artifacts": [
    { "name": "sbom.cdx.json", "path": "discovery/sbom.cdx.json", "type": "sbom" }
  ],
  "error": null
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `agent` | string | Agent name, the same as its folder name |
| `stage` | string | One of `discover`, `detect`, `analyze`, `remediate`, `validate` |
| `state` | string | `pending`, `running`, `done` or `failed` |
| `started_at` | ISO 8601 | Set when the agent starts |
| `finished_at` | ISO 8601 or null | Set on `done` or `failed`; null while running |
| `summary` | object | Flat key → number or string pairs that the dashboard shows as tiles |
| `artifacts` | array | Files the agent produced (see below) |
| `error` | string or null | Error message when `state` is `failed` |

Lifecycle: the agent writes `state: "running"` when it starts, then `done` or `failed` at the end.
Files are written atomically (temp file + rename), so a reader never sees a partial file.

### Artifacts

| Field | Meaning |
|-------|---------|
| `name` | File name, unique within the agent. Used in the API URL `/api/runs/<app>/<agent>/artifact/<name>` |
| `path` | Path relative to `outputs/<app-name>/` |
| `type` | `sbom`, `json`, `graph` or `report` |

The dashboard serves only files listed here.

### Writing status from Python

```python
from agents.common import AgentRun

status = AgentRun(app_name, agent="detection", stage="detect").start()   # state=running
try:
    ...  # write files into status.dir
    status.add_artifact("findings.json", "json")
    status.done({"vulnerabilities": 42, "critical": 3})
except Exception as exc:
    status.fail(str(exc))
    raise
```

## Discovery agent artifacts

### `components.json`

A list with one entry per component in the SBOM:

| Field | Type | Meaning |
|-------|------|---------|
| `name` | string | Package name (npm scope included, e.g. `@angular/core`) |
| `version` | string | Resolved version |
| `purl` | string | Package URL |
| `ecosystem` | string | purl type: `npm`, `pypi`, `maven`, `github` (GitHub Actions), ... |
| `licenses` | string[] | SPDX IDs or expressions, if known |
| `locations` | string[] | Manifest or lockfile the component was found in, relative to the repo root |
| `type` | string | CycloneDX component type |
| `found_by` | string | Syft cataloger |
| `relationship` | `"direct"`, `"transitive"` or null | Direct means declared in the `package.json` next to the lockfile and installed at the top level |
| `scope` | `"prod"`, `"dev"` or null | `dev` when only reachable through `devDependencies` |

`relationship` and `scope` are null when they cannot be determined yet: non-npm ecosystems, and
the root projects themselves. The dependency-graph step will fill these in.

### `discovery_meta.json`

Contains repo info (URL, SHA, commit date, ref), tool versions, every manifest and lockfile with
`origin: original | generated`, a per-`package.json` lockfile record (`status`, the npm command
used, and the error if generation failed), component counts by ecosystem, relationship and scope,
and run timestamps.

A lockfile is `original` only if git tracks it in the target repo.
