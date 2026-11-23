"""Output contract shared by every agent (see docs/output-contract.md).

    outputs/<app-name>/run.json
    outputs/<app-name>/<agent>/status.json
    outputs/<app-name>/<agent>/<artifacts...>
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUTS = PROJECT_ROOT / "outputs"

STATES = ("pending", "running", "done", "failed")
ARTIFACT_TYPES = ("sbom", "json", "graph", "report")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json(path: Path, data: Any) -> None:
    """Write JSON atomically so a polling reader never sees a half-written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def app_dir(app_name: str, outputs: Path = DEFAULT_OUTPUTS) -> Path:
    return Path(outputs) / app_name


def agent_dir(app_name: str, agent: str, outputs: Path = DEFAULT_OUTPUTS) -> Path:
    return app_dir(app_name, outputs) / agent


def update_run_info(app_name: str, outputs: Path = DEFAULT_OUTPUTS, **fields: Any) -> dict:
    """Merge `fields` into outputs/<app>/run.json and bump updated_at."""
    path = app_dir(app_name, outputs) / "run.json"
    run = read_json(path, {}) or {}
    run.setdefault("app_name", app_name)
    run.setdefault("started_at", now_iso())
    run.update({k: v for k, v in fields.items() if v is not None})
    run["updated_at"] = now_iso()
    write_json(path, run)
    return run


class AgentRun:
    """Writes outputs/<app>/<agent>/status.json through an agent's lifecycle.

        status = AgentRun(app, "discovery", "discover").start()
        ...
        status.add_artifact("sbom.cdx.json", "sbom")
        status.done({"components": 1234})
        # or status.fail("message")
    """

    def __init__(self, app_name: str, agent: str, stage: str, outputs: Path = DEFAULT_OUTPUTS):
        self.app_name = app_name
        self.agent = agent
        self.stage = stage
        self.outputs = Path(outputs)
        self.dir = agent_dir(app_name, agent, outputs)
        self.path = self.dir / "status.json"
        self.status: dict[str, Any] = {}

    def _write(self) -> None:
        write_json(self.path, self.status)
        update_run_info(self.app_name, self.outputs)

    def start(self) -> "AgentRun":
        self.dir.mkdir(parents=True, exist_ok=True)
        self.status = {
            "agent": self.agent,
            "stage": self.stage,
            "state": "running",
            "started_at": now_iso(),
            "finished_at": None,
            "summary": {},
            "artifacts": [],
            "error": None,
        }
        self._write()
        return self

    def add_artifact(self, filename: str, type_: str) -> None:
        """Register a file in this agent's folder. `name` is the filename, used in API URLs."""
        if type_ not in ARTIFACT_TYPES:
            raise ValueError(f"artifact type must be one of {ARTIFACT_TYPES}")
        rel = (self.dir / filename).relative_to(self.outputs / self.app_name).as_posix()
        self.status["artifacts"].append({"name": Path(filename).name, "path": rel, "type": type_})

    def done(self, summary: dict[str, Any] | None = None) -> None:
        self.status.update(state="done", finished_at=now_iso(), summary=summary or {})
        self._write()

    def fail(self, error: str) -> None:
        self.status.update(state="failed", finished_at=now_iso(), error=error)
        self._write()
