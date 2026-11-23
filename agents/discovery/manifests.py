"""Manifest discovery and npm lockfile generation."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from .tools import ToolError, run

log = logging.getLogger(__name__)

SKIP_DIRS = {"node_modules", ".git", "bower_components", ".venv", "venv", "__pycache__"}

# filename -> (ecosystem, kind)
_EXACT = {
    # JavaScript / npm
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "bower.json": ("bower", "manifest"),
    # Python
    "pyproject.toml": ("pypi", "manifest"),
    "setup.py": ("pypi", "manifest"),
    "setup.cfg": ("pypi", "manifest"),
    "Pipfile": ("pypi", "manifest"),
    "Pipfile.lock": ("pypi", "lockfile"),
    "poetry.lock": ("pypi", "lockfile"),
    "uv.lock": ("pypi", "lockfile"),
    # Java / JVM
    "pom.xml": ("maven", "manifest"),
    "build.gradle": ("maven", "manifest"),
    "build.gradle.kts": ("maven", "manifest"),
    "gradle.lockfile": ("maven", "lockfile"),
    # Go
    "go.mod": ("golang", "manifest"),
    "go.sum": ("golang", "lockfile"),
    # Rust
    "Cargo.toml": ("cargo", "manifest"),
    "Cargo.lock": ("cargo", "lockfile"),
    # Ruby
    "Gemfile": ("gem", "manifest"),
    "Gemfile.lock": ("gem", "lockfile"),
    # PHP
    "composer.json": ("composer", "manifest"),
    "composer.lock": ("composer", "lockfile"),
    # .NET
    "packages.config": ("nuget", "manifest"),
    "packages.lock.json": ("nuget", "lockfile"),
}

_PATTERNS = [
    (re.compile(r"^requirements.*\.(txt|in)$"), ("pypi", "manifest")),
    (re.compile(r".*\.csproj$"), ("nuget", "manifest")),
]

NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

# Disable lifecycle scripts, audit/fund network calls, and force lockfile writing
# even if the target repo's .npmrc sets package-lock=false (Juice Shop does).
NPM_LOCK_CMD = [
    "npm", "install",
    "--package-lock-only",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--package-lock=true",
]
_NPM_TIMEOUT = 600


def _classify(filename: str) -> tuple[str, str] | None:
    if filename in _EXACT:
        return _EXACT[filename]
    for pattern, result in _PATTERNS:
        if pattern.match(filename):
            return result
    return None


def discover_manifests(repo_path: Path) -> list[dict]:
    """Find package manifests and lockfiles under `repo_path`, skipping node_modules etc.

    Returns a list of {"path", "ecosystem", "kind"} with paths relative to repo_path.
    """
    repo_path = Path(repo_path)
    found: list[dict] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            info = _classify(name)
            if info:
                rel = (Path(root) / name).relative_to(repo_path).as_posix()
                found.append({"path": rel, "ecosystem": info[0], "kind": info[1]})
    return found


def _has_npm_lockfile(directory: Path) -> str | None:
    for lock in NPM_LOCKFILES:
        if (directory / lock).is_file():
            return lock
    return None


def ensure_npm_lockfiles(repo_path: Path, manifests: list[dict]) -> list[dict]:
    """Make sure every package.json has a lockfile next to it.

    Missing lockfiles are generated with `npm install --package-lock-only
    --ignore-scripts` (no packages are installed, no scripts are run).
    Returns one record per package.json:
        {"manifest", "lockfile", "status": "original"|"generated"|"failed", ...}
    """
    repo_path = Path(repo_path)
    results: list[dict] = []
    for m in manifests:
        if Path(m["path"]).name != "package.json":
            continue
        pkg_dir = (repo_path / m["path"]).parent
        rel_dir = pkg_dir.relative_to(repo_path).as_posix()
        existing = _has_npm_lockfile(pkg_dir)
        if existing:
            results.append({
                "manifest": m["path"],
                "lockfile": _join(rel_dir, existing),
                "status": "original",
            })
            continue

        record = {"manifest": m["path"], "lockfile": _join(rel_dir, "package-lock.json")}
        cmd = list(NPM_LOCK_CMD)
        try:
            log.info("Generating package-lock.json in %s", rel_dir or ".")
            try:
                run(cmd, cwd=pkg_dir, timeout=_NPM_TIMEOUT)
            except ToolError as exc:
                if "ERESOLVE" not in str(exc):
                    raise
                # Peer-dependency conflicts are common in older Angular projects.
                cmd.append("--legacy-peer-deps")
                log.info("Retrying with --legacy-peer-deps in %s", rel_dir or ".")
                run(cmd, cwd=pkg_dir, timeout=_NPM_TIMEOUT)
            if not (pkg_dir / "package-lock.json").is_file():
                raise ToolError("npm exited successfully but no package-lock.json was written")
            record.update(status="generated", command=" ".join(cmd))
        except ToolError as exc:
            log.warning("Lockfile generation failed for %s: %s", m["path"], exc)
            record.update(status="failed", lockfile=None, command=" ".join(cmd),
                          error=str(exc).splitlines()[-1][:500])
        results.append(record)
    return results


def _join(rel_dir: str, name: str) -> str:
    return name if rel_dir in ("", ".") else f"{rel_dir}/{name}"
