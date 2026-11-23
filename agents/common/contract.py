"""Output contract shared by every agent (see docs/output-contract.md).

    outputs/<app_id>/run.json
    outputs/<app_id>/<agent>/status.json
    outputs/<app_id>/<agent>/<artifacts...>
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUTS = PROJECT_ROOT / "outputs"
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"

STATES = ("pending", "running", "done", "failed")
ARTIFACT_TYPES = ("sbom", "sbom-spdx", "json", "graph", "inventory", "report")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id(commit_sha: str | None = None) -> str:
    """UTC timestamp + short commit SHA, e.g. 20261123T101613Z-c9f9922."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{commit_sha[:7]}" if commit_sha else stamp


def write_json(path: Path, data: Any, *, indent: int | None = 2) -> None:
    """Write JSON atomically (temp file + rename) with mode 0644."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=indent, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError):
        return default


def app_dir(app_id: str, outputs: Path = DEFAULT_OUTPUTS) -> Path:
    return Path(outputs) / app_id


def agent_dir(app_id: str, agent_folder: str, outputs: Path = DEFAULT_OUTPUTS) -> Path:
    return app_dir(app_id, outputs) / agent_folder


def read_run_info(app_id: str, outputs: Path = DEFAULT_OUTPUTS) -> dict:
    return read_json(app_dir(app_id, outputs) / "run.json", {}) or {}


def update_run_info(app_id: str, outputs: Path = DEFAULT_OUTPUTS, **fields: Any) -> dict:
    """Merge `fields` into outputs/<app_id>/run.json and bump updated_at."""
    path = app_dir(app_id, outputs) / "run.json"
    run = read_json(path, {}) or {}
    run.setdefault("app_id", app_id)
    run.update({k: v for k, v in fields.items() if v is not None})
    run["updated_at"] = now_iso()
    write_json(path, run)
    return run


class AgentRun:
    """Writes outputs/<app_id>/<folder>/status.json through an agent's lifecycle.

        with AgentRun(app_id, "source-deps", "source_deps", "discover", run_id) as status:
            status.warn("cdxgen failed: ...")
            status.add_artifact("raw/syft.cdx.json", "sbom")
            status.done({"components": 1234}, coverage={...})

    Leaving the block with an exception marks the agent failed (the exception
    propagates). `start()` clears the folder so no artifact from an older run
    survives.
    """

    def __init__(self, app_id: str, agent: str, folder: str, stage: str, run_id: str,
                 outputs: Path = DEFAULT_OUTPUTS):
        self.app_id = app_id
        self.agent = agent
        self.stage = stage
        self.run_id = run_id
        self.outputs = Path(outputs)
        self.dir = agent_dir(app_id, folder, outputs)
        self.path = self.dir / "status.json"
        self.status: dict[str, Any] = {}

    # -- lifecycle -------------------------------------------------------
    def _write(self) -> None:
        write_json(self.path, self.status)
        update_run_info(self.app_id, self.outputs)

    def start(self, clear: bool = True) -> "AgentRun":
        if clear and self.dir.exists():
            shutil.rmtree(self.dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.status = {
            "agent": self.agent,
            "stage": self.stage,
            "run_id": self.run_id,
            "state": "running",
            "started_at": now_iso(),
            "finished_at": None,
            "summary": {},
            "coverage": {},
            "warnings": [],
            "artifacts": [],
            "error": None,
        }
        self._write()
        return self

    def __enter__(self) -> "AgentRun":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None and self.status.get("state") == "running":
            detail = "".join(traceback.format_exception_only(exc_type, exc)).strip()
            self.fail(detail)
        return False

    def warn(self, message: str) -> None:
        if message not in self.status["warnings"]:
            self.status["warnings"].append(message)

    def add_artifact(self, relpath: str, type_: str) -> None:
        """Register a file (relative to the agent folder). `name` is its basename and must be unique."""
        if type_ not in ARTIFACT_TYPES:
            raise ValueError(f"artifact type must be one of {ARTIFACT_TYPES}")
        file = self.dir / relpath
        if not file.is_file():
            return
        name = file.name
        if any(a["name"] == name for a in self.status["artifacts"]):
            raise ValueError(f"duplicate artifact name {name!r}")
        rel = file.relative_to(self.outputs / self.app_id).as_posix()
        self.status["artifacts"].append({"name": name, "path": rel, "type": type_,
                                         "bytes": file.stat().st_size})

    def done(self, summary: dict[str, Any] | None = None, coverage: dict | None = None) -> None:
        self.status.update(state="done", finished_at=now_iso(), summary=summary or {})
        if coverage is not None:
            self.status["coverage"] = coverage
        self._write()

    def fail(self, error: str) -> None:
        self.status.update(state="failed", finished_at=now_iso(), error=error)
        self._write()
