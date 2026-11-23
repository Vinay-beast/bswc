# Dashboard (v1)

A local, read-only view of agent outputs in `outputs/`. It uses FastAPI for the backend and plain
HTML, CSS and JavaScript for the frontend, with no build step.

## Run

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 1. Produce outputs (see agents/discovery/README.md)
python3 -m agents.discovery.cli --repo https://github.com/juice-shop/juice-shop

# 2. Start the dashboard
.venv/bin/uvicorn dashboard.app:app --port 8000
```

Open http://localhost:8000. The page polls every 5 seconds, so an agent that is running
updates its stage card while you watch. Set `GUARDIAN_OUTPUTS=/path/to/outputs` to read from
another folder.

## What it shows

- **Top bar**: app selector, repo URL, short commit SHA and last run time (from `run.json`).
- **Pipeline**: Discover → Detect → Analyze → Remediate → Validate. Each card shows the state
  from the matching agent's `status.json`, or Pending if there is no agent folder yet.
- **Discover panel**: summary tiles, manifests with each lockfile marked original or generated,
  tool versions, and a component table. The table supports search, filters for type, ecosystem
  and scope, sortable columns and pagination. Below it are artifact downloads and a placeholder
  for the dependency graph.
- **Other stages**: an empty state until their agents write output. A generic view (summary
  tiles and artifacts) appears once they do.

## API

Read-only. Files are served from `outputs/` only.

| Endpoint | Returns |
|----------|---------|
| `GET /api/runs` | List of apps: `run.json` plus the agent folder names |
| `GET /api/runs/{app}` | `{ "run": run.json, "agents": { "<agent>": status.json, ... } }` |
| `GET /api/runs/{app}/{agent}/status` | That agent's `status.json` |
| `GET /api/runs/{app}/{agent}/artifact/{name}` | An artifact listed in `status.json`. Add `?download=true` to download it as an attachment |

Interactive API docs are at `/api/docs`.

Path traversal is blocked in three ways: app and agent names must match `[A-Za-z0-9][A-Za-z0-9._-]*`,
artifacts are looked up by name in `status.json` (never taken from the URL as a path), and every
resolved path must stay inside `outputs/<app>/`.

Agents are discovered by scanning `outputs/<app>/*/status.json`. Nothing is hard-coded, so a
new agent appears as soon as it writes a `status.json` (see [docs/output-contract.md](../docs/output-contract.md)).
