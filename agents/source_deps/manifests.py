"""Manifest/lockfile discovery and project detection (including npm/yarn/pnpm workspaces)."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

import yaml

log = logging.getLogger(__name__)

ALWAYS_SKIP = {"node_modules", ".git", "bower_components", ".venv", "venv", "__pycache__",
               ".tox", ".mypy_cache", ".pytest_cache", "dist-newstyle"}
# Skipped unless --include-all: test data, examples and docs rarely ship.
DEFAULT_SKIP = {"test", "tests", "__tests__", "fixtures", "__fixtures__", "examples", "example",
                "docs", "vendor", "third_party"}

# filename -> (ecosystem, kind)
_EXACT = {
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "pnpm-workspace.yaml": ("npm", "workspace"),
    "bower.json": ("bower", "manifest"),
    "pyproject.toml": ("pypi", "manifest"),
    "setup.py": ("pypi", "manifest"),
    "setup.cfg": ("pypi", "manifest"),
    "Pipfile": ("pypi", "manifest"),
    "Pipfile.lock": ("pypi", "lockfile"),
    "poetry.lock": ("pypi", "lockfile"),
    "uv.lock": ("pypi", "lockfile"),
    "pdm.lock": ("pypi", "lockfile"),
    "pom.xml": ("maven", "manifest"),
    "build.gradle": ("maven", "manifest"),
    "build.gradle.kts": ("maven", "manifest"),
    "gradle.lockfile": ("maven", "lockfile"),
    "go.mod": ("golang", "manifest"),
    "go.sum": ("golang", "lockfile"),
    "Cargo.toml": ("cargo", "manifest"),
    "Cargo.lock": ("cargo", "lockfile"),
    "Gemfile": ("gem", "manifest"),
    "Gemfile.lock": ("gem", "lockfile"),
    "composer.json": ("composer", "manifest"),
    "composer.lock": ("composer", "lockfile"),
    "packages.config": ("nuget", "manifest"),
    "packages.lock.json": ("nuget", "lockfile"),
    "Package.swift": ("swift", "manifest"),
    "Package.resolved": ("swift", "lockfile"),
    "pubspec.yaml": ("pub", "manifest"),
    "pubspec.lock": ("pub", "lockfile"),
    "mix.exs": ("hex", "manifest"),
    "mix.lock": ("hex", "lockfile"),
}
_PATTERNS = [
    (re.compile(r"^requirements.*\.(txt|in)$"), ("pypi", "manifest")),
    (re.compile(r".*\.csproj$"), ("nuget", "manifest")),
]

# Lockfiles that pin a full tree for each ecosystem, in preference order.
LOCKFILES = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"),
    "pypi": ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"),
    "golang": ("go.sum",),
    "maven": ("gradle.lockfile",),
    "cargo": ("Cargo.lock",),
    "gem": ("Gemfile.lock",),
    "composer": ("composer.lock",),
    "nuget": ("packages.lock.json",),
    "swift": ("Package.resolved",),
    "pub": ("pubspec.lock",),
    "hex": ("mix.lock",),
}
# The manifest that defines a project for each ecosystem.
PROJECT_MANIFESTS = {
    "npm": ("package.json",),
    "pypi": ("pyproject.toml", "Pipfile", "setup.py", "requirements.txt", "requirements.in"),
    "golang": ("go.mod",),
    "maven": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "cargo": ("Cargo.toml",),
    "gem": ("Gemfile",),
    "composer": ("composer.json",),
    "nuget": ("packages.config",),
    "swift": ("Package.swift",),
    "pub": ("pubspec.yaml",),
    "hex": ("mix.exs",),
}


@dataclass
class Project:
    """One dependency root: an npm package (with its workspace members), a Go module, ..."""

    id: str                         # project:<path>  ('.' for the repo root)
    path: str                       # directory relative to the repo root
    ecosystem: str
    manifest: str                   # manifest file relative to the repo root
    lockfile: str | None = None     # lockfile relative to the repo root (committed or generated)
    lockfile_origin: str | None = None   # original | generated | None
    name: str | None = None
    version: str | None = None
    workspace_members: list[str] = field(default_factory=list)
    extra_manifests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def classify(filename: str) -> tuple[str, str] | None:
    if filename in _EXACT:
        return _EXACT[filename]
    for pattern, result in _PATTERNS:
        if pattern.match(filename):
            return result
    return None


def discover_manifests(repo_path: Path, include_all: bool = False) -> tuple[list[dict], list[str]]:
    """Walk the repo and return (manifests, skipped_dirs).

    manifests: [{path, ecosystem, kind}] (paths relative to the repo root).
    skipped_dirs: directories not scanned because of the default skip list.
    """
    repo_path = Path(repo_path)
    found: list[dict] = []
    skipped: list[str] = []
    for root, dirs, files in os.walk(repo_path):
        rel_root = Path(root).relative_to(repo_path)
        keep = []
        for d in sorted(dirs):
            if d in ALWAYS_SKIP:
                continue
            if not include_all and d.lower() in DEFAULT_SKIP:
                skipped.append((rel_root / d).as_posix())
                continue
            keep.append(d)
        dirs[:] = keep
        for name in sorted(files):
            info = classify(name)
            if info:
                found.append({"path": (rel_root / name).as_posix(), "ecosystem": info[0], "kind": info[1]})
    return found, skipped


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def npm_workspace_patterns(pkg_dir: Path) -> list[str]:
    """Workspace globs from package.json "workspaces" and pnpm-workspace.yaml."""
    patterns: list[str] = []
    ws = _load_json(pkg_dir / "package.json").get("workspaces")
    if isinstance(ws, list):
        patterns += ws
    elif isinstance(ws, dict):
        patterns += ws.get("packages") or []
    pnpm_ws = pkg_dir / "pnpm-workspace.yaml"
    if pnpm_ws.is_file():
        try:
            data = yaml.safe_load(pnpm_ws.read_text()) or {}
            patterns += data.get("packages") or []
        except yaml.YAMLError:
            pass
    return [p for p in patterns if isinstance(p, str)]


def _match_members(pkg_dir_rel: str, patterns: list[str], package_dirs: list[str]) -> list[str]:
    base = PurePosixPath(pkg_dir_rel)
    positives = [p for p in patterns if not p.startswith("!")]
    negatives = [p[1:] for p in patterns if p.startswith("!")]
    members = []
    for d in package_dirs:
        try:
            rel = PurePosixPath(d).relative_to(base).as_posix()
        except ValueError:
            continue
        if rel == ".":
            continue
        norm = lambda pat: pat.strip("./").rstrip("/")  # noqa: E731
        if any(fnmatch.fnmatch(rel, norm(p)) or fnmatch.fnmatch(rel, norm(p).replace("**", "*"))
               for p in positives) and not any(fnmatch.fnmatch(rel, norm(n)) for n in negatives):
            members.append(d)
    return members


def _dir(rel_file: str) -> str:
    parent = PurePosixPath(rel_file).parent.as_posix()
    return "." if parent in ("", ".") else parent


def _join(d: str, name: str) -> str:
    return name if d == "." else f"{d}/{name}"


def detect_projects(repo_path: Path, manifests: list[dict]) -> list[Project]:
    """Group manifests into projects. Workspace members belong to their workspace root."""
    repo_path = Path(repo_path)
    files = {m["path"] for m in manifests}
    projects: list[Project] = []

    # --- npm (workspace aware) ---
    pkg_dirs = sorted({_dir(p) for p in files if PurePosixPath(p).name == "package.json"},
                      key=lambda d: (d.count("/"), d))
    member_of: dict[str, str] = {}
    for d in pkg_dirs:
        if d in member_of:
            continue
        patterns = npm_workspace_patterns(repo_path / d)
        if patterns:
            for m in _match_members(d, patterns, pkg_dirs):
                member_of.setdefault(m, d)
    for d in pkg_dirs:
        if d in member_of:
            continue
        pkg = _load_json(repo_path / d / "package.json")
        lock = next((_join(d, l) for l in LOCKFILES["npm"] if _join(d, l) in files), None)
        members = sorted(m for m, root in member_of.items() if root == d)
        projects.append(Project(
            id=f"project:{d}", path=d, ecosystem="npm", manifest=_join(d, "package.json"),
            lockfile=lock, name=pkg.get("name") or (repo_path.name if d == "." else PurePosixPath(d).name),
            version=pkg.get("version"), workspace_members=members,
            extra_manifests=[_join(m, "package.json") for m in members]))

    # --- every other ecosystem: one project per directory holding a project manifest ---
    for eco, names in PROJECT_MANIFESTS.items():
        if eco == "npm":
            continue
        dirs: dict[str, list[str]] = {}
        for p in sorted(files):
            pp = PurePosixPath(p)
            is_req = eco == "pypi" and re.match(r"^requirements.*\.(txt|in)$", pp.name)
            if pp.name in names or is_req:
                dirs.setdefault(_dir(p), []).append(p)
        roots = sorted(dirs, key=lambda d: (d.count("/"), d))
        for d in roots:
            # Maven/Gradle multi-module: a module below another build file belongs to it.
            if eco == "maven" and any(d != r and (r == "." or d.startswith(r + "/")) for r in roots
                                      if r in dirs and r != d and _is_parent_build(repo_path, r)):
                continue
            mans = dirs[d]
            primary = next((m for n in names for m in mans if PurePosixPath(m).name == n), mans[0])
            lock = next((_join(d, l) for l in LOCKFILES.get(eco, ()) if _join(d, l) in files), None)
            name, version = _project_identity(repo_path, primary, eco)
            projects.append(Project(
                id=f"project:{d}", path=d, ecosystem=eco, manifest=primary, lockfile=lock,
                name=name or (repo_path.name if d == "." else PurePosixPath(d).name), version=version,
                extra_manifests=[m for m in mans if m != primary]))

    # Two ecosystems in the same directory would share an id: suffix the later ones.
    seen: dict[str, int] = {}
    for p in projects:
        if p.id in seen:
            p.id = f"{p.id}#{p.ecosystem}"
        seen[p.id] = 1
    return projects


def _is_parent_build(repo_path: Path, d: str) -> bool:
    pom = repo_path / d / "pom.xml"
    if pom.is_file() and "<modules>" in pom.read_text(errors="ignore"):
        return True
    return any((repo_path / d / n).is_file() for n in ("settings.gradle", "settings.gradle.kts"))


def _project_identity(repo_path: Path, manifest: str, eco: str) -> tuple[str | None, str | None]:
    path = repo_path / manifest
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None, None
    if eco == "golang":
        m = re.search(r"^module\s+(\S+)", text, re.M)
        return (m.group(1) if m else None), None
    if eco == "pypi" and path.name == "pyproject.toml":
        try:
            import tomllib
            data = tomllib.loads(text)
            proj = data.get("project") or data.get("tool", {}).get("poetry") or {}
            return proj.get("name"), proj.get("version")
        except Exception:  # noqa: BLE001 - best effort
            return None, None
    if eco == "maven" and path.name == "pom.xml":
        body = re.sub(r"<parent>.*?</parent>", "", text, flags=re.S)
        a = re.search(r"<artifactId>([^<]+)</artifactId>", body)
        v = re.search(r"<version>([^<]+)</version>", body)
        return (a.group(1).strip() if a else None), (v.group(1).strip() if v else None)
    if eco == "cargo":
        try:
            import tomllib
            pkg = tomllib.loads(text).get("package", {})
            return pkg.get("name"), pkg.get("version")
        except Exception:  # noqa: BLE001
            return None, None
    if eco == "composer":
        data = _load_json(path)
        return data.get("name"), data.get("version")
    return None, None
