"""Read-only local dashboard for Guardian agent outputs.

Run:  uvicorn dashboard.app:app --port 8000

Serves files from outputs/ only. App and agent names are validated, agents are
discovered by scanning outputs/<app>/*/status.json, and an artifact is served
only if it is listed in that agent's status.json and resolves inside the app folder.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = Path(os.environ.get("GUARDIAN_OUTPUTS", PROJECT_ROOT / "outputs")).resolve()
STATIC = Path(__file__).resolve().parent / "static"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

app = FastAPI(title="Software Supply Chain Guardian", docs_url="/api/docs", redoc_url=None)


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _safe_dir(*parts: str) -> Path:
    """Resolve outputs/<parts...> after validating every segment; 404 if missing."""
    for part in parts:
        if not _SAFE_NAME.match(part):
            raise HTTPException(status_code=400, detail=f"Invalid name: {part!r}")
    path = OUTPUTS.joinpath(*parts).resolve()
    if not path.is_relative_to(OUTPUTS) or not path.is_dir():
        raise HTTPException(status_code=404, detail="Not found")
    return path


def _agent_dirs(app_dir: Path) -> list[Path]:
    return sorted(d for d in app_dir.iterdir()
                  if d.is_dir() and _SAFE_NAME.match(d.name) and (d / "status.json").is_file())


def _run_info(app_dir: Path) -> dict:
    run = _read_json(app_dir / "run.json") or {}
    run.setdefault("app_name", app_dir.name)
    return run


@app.get("/api/runs")
def list_runs() -> list[dict]:
    if not OUTPUTS.is_dir():
        return []
    runs = []
    for d in sorted(OUTPUTS.iterdir()):
        if d.is_dir() and _SAFE_NAME.match(d.name) and (d / "run.json").is_file():
            run = _run_info(d)
            run["agents"] = [a.name for a in _agent_dirs(d)]
            runs.append(run)
    runs.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
    return runs


@app.get("/api/runs/{app_name}")
def get_run(app_name: str) -> dict:
    app_dir = _safe_dir(app_name)
    agents = {}
    for d in _agent_dirs(app_dir):
        status = _read_json(d / "status.json")
        if status is not None:
            agents[d.name] = status
    return {"run": _run_info(app_dir), "agents": agents}


@app.get("/api/runs/{app_name}/{agent}/status")
def get_status(app_name: str, agent: str) -> dict:
    status = _read_json(_safe_dir(app_name, agent) / "status.json")
    if status is None:
        raise HTTPException(status_code=404, detail="status.json not found")
    return status


@app.get("/api/runs/{app_name}/{agent}/artifact/{name}")
def get_artifact(app_name: str, agent: str, name: str,
                 download: bool = Query(False, description="Send as attachment")):
    app_dir = _safe_dir(app_name)
    status = get_status(app_name, agent)
    entry = next((a for a in status.get("artifacts") or [] if a.get("name") == name), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Artifact not listed in status.json")
    path = (app_dir / str(entry.get("path", ""))).resolve()
    if not path.is_relative_to(app_dir) or not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact file not found")
    media = "application/json" if path.suffix == ".json" else None
    return FileResponse(
        path,
        media_type=media,
        filename=path.name,
        content_disposition_type="attachment" if download else "inline",
    )


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
