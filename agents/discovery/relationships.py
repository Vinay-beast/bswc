"""Classify npm components as direct/transitive and prod/dev.

For every npm component we look at the lockfile Syft found it in, then at the
package.json next to that lockfile:

* relationship = "direct" if the package is declared in that package.json
  (dependencies / devDependencies / optionalDependencies / peerDependencies)
  and this exact version is the top-level install (node_modules/<name>);
  otherwise "transitive".
* scope = "dev" if it is only reachable through devDependencies (npm marks such
  lockfile entries with "dev": true), otherwise "prod". For direct
  dependencies the package.json section decides.

Components whose relationship cannot be determined (non-npm ecosystems, or no
lockfile entry) get null; the dependency-graph step fills those in later.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
_PROD_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")


@dataclass
class _LockEntry:
    top_level: bool
    dev: bool


@dataclass
class _Project:
    """package.json + lockfile of one npm project root (e.g. '.' or 'frontend')."""

    declared: dict[str, str] = field(default_factory=dict)  # name -> "prod" | "dev"
    lock: dict[tuple[str, str], list[_LockEntry]] | None = None


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _index_lock_v2(packages: dict) -> dict[tuple[str, str], list[_LockEntry]]:
    index: dict[tuple[str, str], list[_LockEntry]] = {}
    for key, entry in packages.items():
        if "node_modules/" not in key or entry.get("link"):
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
        version = entry.get("version")
        if not version:
            continue
        top_level = key == f"node_modules/{key.rsplit('node_modules/', 1)[1]}"
        dev = bool(entry.get("dev") or entry.get("devOptional"))
        index.setdefault((name, version), []).append(_LockEntry(top_level, dev))
    return index


def _index_lock_v1(deps: dict, top_level: bool = True, index=None):
    index = {} if index is None else index
    for name, entry in deps.items():
        version = entry.get("version")
        if version:
            index.setdefault((name, version), []).append(_LockEntry(top_level, bool(entry.get("dev"))))
        _index_lock_v1(entry.get("dependencies") or {}, False, index)
    return index


def _load_project(project_dir: Path) -> _Project:
    project = _Project()
    pkg = _load_json(project_dir / "package.json") or {}
    for section in _PROD_SECTIONS:
        for name in pkg.get(section) or {}:
            project.declared.setdefault(name, "prod")
    for name in pkg.get("devDependencies") or {}:
        project.declared.setdefault(name, "dev")

    for lock_name in _LOCKFILES:
        lock = _load_json(project_dir / lock_name)
        if lock is None:
            continue
        if "packages" in lock:
            project.lock = _index_lock_v2(lock["packages"])
        else:
            project.lock = _index_lock_v1(lock.get("dependencies") or {})
        break
    return project


def _classify_in_project(project: _Project, name: str, version: str | None):
    """(relationship, scope) for one component within one project, or (None, None)."""
    declared = project.declared.get(name)
    if project.lock is None:
        # Only a package.json: declared packages are direct, nothing else is known.
        return ("direct", declared) if declared else (None, None)
    entries = project.lock.get((name, version or ""))
    if not entries:
        return None, None
    if declared and any(e.top_level for e in entries):
        return "direct", declared
    scope = "dev" if all(e.dev for e in entries) else "prod"
    return "transitive", scope


def classify_components(repo_path: Path, components: list[dict]) -> list[dict]:
    """Add `relationship` (direct|transitive|null) and `scope` (prod|dev|null) in place."""
    repo_path = Path(repo_path)
    projects: dict[str, _Project] = {}

    for comp in components:
        relationships, scopes = set(), set()
        if comp.get("ecosystem") == "npm":
            for loc in comp.get("locations") or []:
                loc_path = PurePosixPath(loc)
                if loc_path.name not in (*_LOCKFILES, "package.json"):
                    continue
                key = str(loc_path.parent)
                if key not in projects:
                    projects[key] = _load_project(repo_path / key)
                rel, scope = _classify_in_project(projects[key], comp["name"], comp.get("version"))
                if rel:
                    relationships.add(rel)
                if scope:
                    scopes.add(scope)
        comp["relationship"] = ("direct" if "direct" in relationships
                                else "transitive" if relationships else None)
        comp["scope"] = "prod" if "prod" in scopes else "dev" if scopes else None
    return components
