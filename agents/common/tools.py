"""Running external tools (git, npm, syft, trivy, cdxgen, ...) safely and recording them.

Pinned tools are looked up in ./tools first (installed by scripts/install_tools.sh),
then on PATH, then in ~/.local/bin.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from .contract import PROJECT_ROOT, now_iso

log = logging.getLogger(__name__)

TOOLS_DIR = PROJECT_ROOT / "tools"
SEARCH_DIRS = [TOOLS_DIR / "bin", TOOLS_DIR / "node_modules" / ".bin"]
FALLBACK_DIRS = [Path.home() / ".local" / "bin"]

PINNED = {"syft": "1.57.2", "trivy": "0.76.2", "cdxgen": "12.9.3"}

INSTALL_HINTS = {
    "git": "Install git: https://git-scm.com/downloads",
    "npm": "Install Node.js (includes npm): https://nodejs.org/",
    "node": "Install Node.js: https://nodejs.org/",
    "syft": "Run scripts/install_tools.sh",
    "trivy": "Run scripts/install_tools.sh",
    "cdxgen": "Run scripts/install_tools.sh",
}


class ToolError(RuntimeError):
    """An external tool is missing or failed. `output` holds its full stderr/stdout."""

    def __init__(self, message: str, output: str = ""):
        super().__init__(message)
        self.output = output


def find_tool(name: str) -> str | None:
    for d in SEARCH_DIRS:
        candidate = d / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    for d in FALLBACK_DIRS:
        candidate = d / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def require_tool(name: str) -> str:
    found = find_tool(name)
    if not found:
        raise ToolError(f"Required tool '{name}' not found. {INSTALL_HINTS.get(name, '')}".strip())
    return found


def run(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command with a timeout, capturing output. Raises ToolError on failure."""
    exe = require_tool(cmd[0])
    full_cmd = [exe, *cmd[1:]]
    merged_env = {**os.environ, **(env or {})}
    log.debug("run: %s (cwd=%s)", shlex.join(cmd), cwd)
    try:
        proc = subprocess.run(full_cmd, cwd=cwd, env=merged_env, capture_output=True,
                              text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out after {timeout}s: {shlex.join(cmd)}") from exc
    if check and proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        tail = "\n".join(out.splitlines()[-15:])
        raise ToolError(f"Command failed (exit {proc.returncode}): {shlex.join(cmd)}\n{tail}",
                        output=f"{proc.stderr}\n{proc.stdout}")
    return proc


def run_recorded(
    tool: str,
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 600,
    env: dict[str, str] | None = None,
    output_file: Path | None = None,
) -> dict:
    """Run a tool without raising and return a record of what happened.

    The record holds the exact command line, the tool version, timing, exit
    status and (if any) an error summary. Use it for every tool whose failure
    must not abort the agent.
    """
    record = {
        "tool": tool,
        "version": tool_version(tool),
        "command": shlex.join(cmd),
        "cwd": str(cwd) if cwd else None,
        "env": {k: v for k, v in (env or {}).items() if k != "NODE_OPTIONS"} or None,
        "started_at": now_iso(),
        "duration_s": None,
        "status": "ok",
        "exit_code": None,
        "output_file": str(output_file) if output_file else None,
        "error": None,
    }
    t0 = time.monotonic()
    try:
        proc = run(cmd, cwd=cwd, timeout=timeout, env=env, check=False)
        record["exit_code"] = proc.returncode
        record["stdout"] = proc.stdout
        record["stderr_tail"] = "\n".join((proc.stderr or "").strip().splitlines()[-20:])
        if proc.returncode != 0:
            record["status"] = "failed"
            record["error"] = _summarise_error(proc.stderr or proc.stdout)
        elif output_file and not Path(output_file).is_file():
            record["status"] = "failed"
            record["error"] = "tool exited 0 but wrote no output file"
    except ToolError as exc:
        record["status"] = "missing" if "not found" in str(exc) else "timeout" if "timed out" in str(exc) else "failed"
        record["error"] = str(exc).splitlines()[0]
    record["duration_s"] = round(time.monotonic() - t0, 2)
    return record


def public_record(record: dict) -> dict:
    """Tool record without the captured stdout (for metadata files)."""
    return {k: v for k, v in record.items() if k != "stdout"}


def _summarise_error(text: str) -> str:
    lines = [l.strip() for l in (text or "").splitlines() if l.strip()]
    keep = [l for l in lines if re.search(r"error|fatal|failed|ERR!", l, re.I)] or lines[-3:]
    return " | ".join(keep[:4])[:600]


_VERSION_CMDS: dict[str, list[str]] = {
    "syft": ["syft", "version", "-o", "json"],
    "trivy": ["trivy", "--version", "--format", "json"],
    "cdxgen": ["cdxgen", "--version"],
    "git": ["git", "--version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "go": ["go", "version"],
    "java": ["java", "-version"],
    "mvn": ["mvn", "--version"],
    "gradle": ["gradle", "--version"],
    "uv": ["uv", "--version"],
    "docker": ["docker", "version", "--format", "{{.Client.Version}}"],
}


@lru_cache(maxsize=None)
def tool_version(name: str) -> str | None:
    """Version string of a tool, or None if missing."""
    if name == "pip":
        return pip_version()
    if name == "python":
        import platform
        return platform.python_version()
    cmd = _VERSION_CMDS.get(name)
    if not cmd or not find_tool(cmd[0]):
        return None
    try:
        proc = run(cmd, timeout=30, check=False)
    except ToolError:
        return None
    out = f"{proc.stdout}\n{proc.stderr}"
    if name in ("syft", "trivy"):
        try:
            return json.loads(proc.stdout).get("version" if name == "syft" else "Version")
        except (json.JSONDecodeError, AttributeError):
            pass
    m = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.]+)?", out)
    return m.group(0) if m else None


@lru_cache(maxsize=None)
def pip_version() -> str | None:
    py = shutil.which("python3")
    if not py:
        return None
    try:
        proc = subprocess.run([py, "-m", "pip", "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.match(r"pip (\S+)", proc.stdout or "")
    return m.group(1) if proc.returncode == 0 and m else None


@lru_cache(maxsize=None)
def docker_status() -> dict:
    """{'cli': version|None, 'daemon': bool, 'server': version|None, 'error': str|None}"""
    status = {"cli": tool_version("docker"), "daemon": False, "server": None, "error": None}
    if not status["cli"]:
        status["error"] = "docker CLI not installed"
        return status
    try:
        proc = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            status.update(daemon=True, server=proc.stdout.strip())
        else:
            status["error"] = _summarise_error(proc.stderr) or "docker daemon not reachable"
    except ToolError as exc:
        status["error"] = str(exc).splitlines()[0]
    return status


def get_tool_versions() -> dict:
    """Versions of every tool the Discover stage can use (None = not installed)."""
    names = ["syft", "trivy", "cdxgen", "git", "node", "npm", "go", "java", "mvn",
             "gradle", "uv", "pip", "python"]
    versions = {n: tool_version(n) for n in names}
    d = docker_status()
    versions["docker"] = d["cli"]
    versions["docker_daemon"] = d["server"] if d["daemon"] else None
    return versions


def tool_path(name: str) -> str | None:
    p = find_tool(name)
    if p and p.startswith(str(PROJECT_ROOT)):
        return os.path.relpath(p, PROJECT_ROOT)
    return p
