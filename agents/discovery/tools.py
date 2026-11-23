"""Helpers for running external tools (git, npm, syft) safely."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

log = logging.getLogger(__name__)

INSTALL_HINTS = {
    "git": "Install git: https://git-scm.com/downloads",
    "npm": "Install Node.js (includes npm): https://nodejs.org/",
    "node": "Install Node.js: https://nodejs.org/",
    "syft": "Install Syft with scripts/install_syft.sh (installs a pinned version to ~/.local/bin)",
}

# Extra places to look for tools that may not be on PATH yet.
_EXTRA_BIN_DIRS = [Path.home() / ".local" / "bin"]


class ToolError(RuntimeError):
    """Raised when an external tool is missing or fails.

    `output` holds the command's full stderr/stdout (the message keeps only the tail).
    """

    def __init__(self, message: str, output: str = ""):
        super().__init__(message)
        self.output = output


def require_tool(name: str) -> str:
    """Return the absolute path of `name`, or raise ToolError with an install hint."""
    found = shutil.which(name)
    if not found:
        for d in _EXTRA_BIN_DIRS:
            candidate = d / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                found = str(candidate)
                break
    if not found:
        hint = INSTALL_HINTS.get(name, "")
        raise ToolError(f"Required tool '{name}' not found on PATH. {hint}".strip())
    return found


def run(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command with a timeout, capturing output.

    The first element of `cmd` is resolved through `require_tool`, so a missing
    tool produces a clear ToolError instead of a FileNotFoundError.
    """
    exe = require_tool(cmd[0])
    full_cmd = [exe, *cmd[1:]]
    merged_env = {**os.environ, **(env or {})}
    log.debug("run: %s (cwd=%s)", " ".join(cmd), cwd)
    try:
        proc = subprocess.run(
            full_cmd,
            cwd=cwd,
            env=merged_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out after {timeout}s: {' '.join(cmd)}") from exc
    if check and proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        tail = "\n".join(stderr.splitlines()[-15:])
        raise ToolError(
            f"Command failed (exit {proc.returncode}): {' '.join(cmd)}\n{tail}",
            output=f"{proc.stderr}\n{proc.stdout}",
        )
    return proc


def _version(cmd: Sequence[str]) -> str | None:
    try:
        return run(cmd, timeout=30).stdout.strip()
    except ToolError:
        return None


def syft_version() -> str | None:
    try:
        out = run(["syft", "version", "-o", "json"], timeout=30).stdout
        return json.loads(out).get("version")
    except (ToolError, json.JSONDecodeError):
        return None


def get_tool_versions() -> dict[str, str | None]:
    """Versions of the external tools used by the agent (None if missing)."""
    git = _version(["git", "--version"])
    return {
        "syft": syft_version(),
        "npm": _version(["npm", "--version"]),
        "node": _version(["node", "--version"]),
        "git": git.replace("git version ", "") if git else None,
    }
