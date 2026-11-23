"""Pluggable per-ecosystem resolvers.

A resolver can
  * prepare(project): make sure a full dependency tree exists without
    installing anything (e.g. generate a reproducible npm lockfile), and
  * native(project, builder): run the ecosystem's own resolver read-only
    (npm ls, go mod graph, pip --dry-run --report, mvn dependency:tree) and
    save its raw output, adding edges where it is the authoritative source.

Every outcome is recorded as a coverage entry: how this project's dependency
tree was resolved, or why it could not be.

Add an ecosystem: subclass Resolver and append it to RESOLVERS.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from agents.common.purl import build_purl, npm_purl
from agents.common.tools import ToolError, find_tool, public_record, run, run_recorded

from .graph_model import GraphBuilder
from .ingest import load_state, save_state
from .manifests import LOCKFILES, Project

log = logging.getLogger(__name__)

NPM_LOCK_CMD = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                "--no-fund", "--package-lock=true"]


@dataclass
class ResolverContext:
    repo_path: Path
    native_dir: Path                 # outputs/<app>/source_deps/raw/native
    commit_sha: str
    commit_date: str                 # ISO 8601, used for npm --before
    tracked_files: set[str]
    tool_runs: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        log.warning(msg)
        if msg not in self.warnings:
            self.warnings.append(msg)

    def record(self, rec: dict) -> dict:
        self.tool_runs.append(public_record(rec))
        return rec


def slug(path: str) -> str:
    return "root" if path in (".", "") else re.sub(r"[^A-Za-z0-9._-]+", "-", path).strip("-")


class Resolver:
    ecosystem = ""
    tool = ""

    def prepare(self, project: Project, ctx: ResolverContext) -> dict | None:
        return None

    def native(self, project: Project, ctx: ResolverContext, builder: GraphBuilder) -> dict:
        return {"project": project.id, "ecosystem": project.ecosystem, "native": None,
                "status": "n/a", "reason": "no native resolver for this ecosystem"}


# --------------------------------------------------------------------- npm
class NpmResolver(Resolver):
    ecosystem = "npm"
    tool = "npm"

    def prepare(self, project: Project, ctx: ResolverContext) -> dict:
        repo = ctx.repo_path
        pkg_dir = repo / project.path
        record = {"project": project.id, "manifest": project.manifest}
        if project.lockfile and project.lockfile in ctx.tracked_files:
            project.lockfile_origin = "original"
            return {**record, "lockfile": project.lockfile, "status": "original"}

        state = load_state(repo)
        generated = state.get("generated_lockfiles", {})
        target = project.lockfile or (f"{project.path}/package-lock.json" if project.path != "." else "package-lock.json")
        prev = generated.get(target)
        if (repo / target).is_file() and prev and prev.get("commit_sha") == ctx.commit_sha \
                and "--before" in prev.get("command", ""):
            project.lockfile, project.lockfile_origin = target, "generated"
            return {**record, **prev, "lockfile": target, "status": "generated", "reused": True}
        if project.lockfile and (repo / project.lockfile).is_file():
            # Untracked lockfile not produced by us for this commit: regenerate it.
            (repo / project.lockfile).unlink()
        if not find_tool("npm"):
            ctx.warn(f"npm not installed: cannot generate a lockfile for {project.manifest}")
            return {**record, "lockfile": None, "status": "failed", "error": "npm not installed"}

        registry = self.registry(pkg_dir)
        cmd = [*NPM_LOCK_CMD, f"--before={ctx.commit_date}"]
        rec = ctx.record(run_recorded("npm", cmd, cwd=pkg_dir, timeout=900))
        if rec["status"] != "ok" and "ERESOLVE" in (rec.get("stderr_tail", "") + (rec.get("error") or "")):
            cmd = [*cmd, "--legacy-peer-deps"]
            log.info("Peer-dependency conflict in %s; retrying with --legacy-peer-deps", project.path)
            rec = ctx.record(run_recorded("npm", cmd, cwd=pkg_dir, timeout=900))
        lock = pkg_dir / "package-lock.json"
        if rec["status"] != "ok" or not lock.is_file():
            err = rec.get("error") or "no package-lock.json written"
            ctx.warn(f"Lockfile generation failed for {project.manifest}: {err}")
            return {**record, "lockfile": None, "status": "failed", "command": shlex.join(cmd),
                    "error": err, "before": ctx.commit_date, "registry": registry}
        info = {"lockfile": target, "status": "generated", "command": shlex.join(cmd),
                "before": ctx.commit_date, "registry": registry, "commit_sha": ctx.commit_sha,
                "legacy_peer_deps": "--legacy-peer-deps" in cmd}
        generated[target] = info
        state["generated_lockfiles"] = generated
        save_state(repo, state)
        project.lockfile, project.lockfile_origin = target, "generated"
        return {**record, **info, "reused": False}

    @staticmethod
    def registry(pkg_dir: Path) -> str | None:
        try:
            return run(["npm", "config", "get", "registry"], cwd=pkg_dir, timeout=30).stdout.strip() or None
        except ToolError:
            return None

    def native(self, project: Project, ctx: ResolverContext, builder: GraphBuilder) -> dict:
        res = {"project": project.id, "ecosystem": "npm", "native": "npm ls"}
        if not project.lockfile or PurePosixPath(project.lockfile).name not in ("package-lock.json", "npm-shrinkwrap.json"):
            return {**res, "status": "skipped", "reason": "npm ls --package-lock-only needs a package-lock.json"}
        out = ctx.native_dir / f"npm-ls-{slug(project.path)}.json"
        cmd = ["npm", "ls", "--all", "--json", "--package-lock-only", "--include=dev",
               "--include=optional", "--include=peer"]
        rec = ctx.record(run_recorded("npm", cmd, cwd=ctx.repo_path / project.path, timeout=300))
        stdout = rec.get("stdout") or ""
        try:
            tree = json.loads(stdout)
        except json.JSONDecodeError:
            return {**res, "status": "failed", "reason": rec.get("error") or "npm ls produced no JSON"}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(stdout)
        out.chmod(0o644)
        purls: set[str] = set()

        def real_name(key: str, d: dict) -> str:
            # Aliases ("string-width-cjs": "npm:string-width@^4") are listed under the alias key;
            # the real package name is in the registry tarball URL: <registry>/<name>/-/<file>.tgz
            m = re.search(r"https?://[^/]+/((?:@[^/]+/)?[^/@]+)/-/", d.get("resolved") or "")
            return m.group(1).replace("%2f", "/").replace("%2F", "/") if m else key

        def walk(deps: dict) -> None:
            for name, d in (deps or {}).items():
                if d.get("version") and not d.get("missing"):
                    purls.add(npm_purl(real_name(name, d), d["version"]))
                walk(d.get("dependencies"))
        walk(tree.get("dependencies"))
        for p in purls:
            if p in builder.nodes and "npm-ls" not in builder.nodes[p]["found_by"]:
                builder.nodes[p]["found_by"].append("npm-ls")
        problems = tree.get("problems") or []
        return {**res, "status": "ok" if rec["exit_code"] == 0 else "ok-with-problems",
                "output": out.name, "purls": sorted(purls), "problems": problems[:50],
                "problem_count": len(problems)}


# ------------------------------------------------------------------ python
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class PythonResolver(Resolver):
    ecosystem = "pypi"
    tool = "pip"

    def native(self, project: Project, ctx: ResolverContext, builder: GraphBuilder) -> dict:
        res = {"project": project.id, "ecosystem": "pypi"}
        if project.lockfile:
            return {**res, "native": None, "status": "lockfile",
                    "reason": f"{project.lockfile} is parsed by the SBOM tools"}
        reqs = self._requirements(project, ctx)
        if not reqs:
            return {**res, "native": None, "status": "gap", "reason": "no installable requirements found"}
        req_file = Path(tempfile.mkstemp(prefix="guardian-req-", suffix=".txt")[1])
        req_file.write_text("\n".join(reqs) + "\n")
        try:
            if find_tool("uv"):
                out = ctx.native_dir / f"uv-compile-{slug(project.path)}.txt"
                out.parent.mkdir(parents=True, exist_ok=True)
                cmd = ["uv", "pip", "compile", str(req_file), "--no-build", "--no-header", "-o", str(out)]
                rec = ctx.record(run_recorded("uv", cmd, timeout=600, output_file=out))
                if rec["status"] == "ok":
                    return {**res, "native": "uv pip compile", "status": "generated", "output": out.name,
                            "reason": "resolved without installing (wheels only)"}
            python = shutil.which("python3")
            if python and self._pip_ok(python):
                out = ctx.native_dir / f"pip-report-{slug(project.path)}.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                # --only-binary=:all: means pip never builds an sdist, so no package code runs.
                cmd = ["python3", "-m", "pip", "install", "--dry-run", "--ignore-installed",
                       "--only-binary=:all:", "--quiet", "--report", str(out), "-r", str(req_file)]
                rec = ctx.record(run_recorded("pip", cmd, timeout=900, output_file=out))
                if rec["status"] == "ok":
                    stats = self._edges_from_report(out, project, reqs, builder)
                    return {**res, "native": "pip install --dry-run --report", "status": "generated",
                            "output": out.name, **stats,
                            "reason": "resolved for this machine's Python/platform; wheels only"}
                return {**res, "native": "pip", "status": "gap", "reason": rec.get("error")}
            return {**res, "native": None, "status": "gap",
                    "reason": "neither uv nor pip available: Python dependencies are declared-only"}
        finally:
            req_file.unlink(missing_ok=True)

    @staticmethod
    def _pip_ok(python: str) -> bool:
        import subprocess
        try:
            return subprocess.run([python, "-m", "pip", "--version"], capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _requirements(self, project: Project, ctx: ResolverContext) -> list[str]:
        lines: list[str] = []
        for man in [project.manifest, *project.extra_manifests]:
            path = ctx.repo_path / man
            name = PurePosixPath(man).name
            if re.match(r"^requirements.*\.(txt|in)$", name):
                for l in path.read_text(errors="ignore").splitlines():
                    l = l.split("#", 1)[0].strip()
                    if l and not l.startswith("-") and _REQ_NAME.match(l):
                        lines.append(l)
            elif name == "pyproject.toml":
                try:
                    import tomllib
                    data = tomllib.loads(path.read_text())
                    lines += data.get("project", {}).get("dependencies", []) or []
                    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
                    lines += [n for n in poetry if n.lower() != "python"]
                except Exception as exc:  # noqa: BLE001
                    ctx.warn(f"cannot read {man}: {exc}")
        return sorted(set(lines))

    def _edges_from_report(self, report: Path, project: Project, reqs: list[str], builder: GraphBuilder) -> dict:
        data = json.loads(report.read_text())
        installed = {}
        for item in data.get("install", []):
            meta = item.get("metadata", {})
            name, version = meta.get("name"), meta.get("version")
            if not name:
                continue
            purl = build_purl("pypi", name, version)
            installed[_norm_py(name)] = (purl, meta)
            builder.add_node(purl, name=name, version=version, ecosystem="pypi", source="pip-report",
                             license=meta.get("license_expression") or meta.get("license"),
                             occurrence={"project": project.id, "lockfile": None, "install_path": None,
                                         "resolved": (item.get("download_info") or {}).get("url"),
                                         "integrity": ((item.get("download_info") or {}).get("archive_info") or {}).get("hash")})
        edges = 0
        for req in reqs:
            m = _REQ_NAME.match(req)
            if m and _norm_py(m.group(1)) in installed:
                purl = installed[_norm_py(m.group(1))][0]
                builder.add_edge(project.id, purl, type_="prod", range_=req, edge_source="pip-report", project=project.id)
                builder.add_declared(purl, project.manifest, "requirements", req)
                edges += 1
        for purl, meta in installed.values():
            for dep in meta.get("requires_dist") or []:
                if "extra ==" in dep:
                    continue
                m = _REQ_NAME.match(dep)
                if m and _norm_py(m.group(1)) in installed:
                    builder.add_edge(purl, installed[_norm_py(m.group(1))][0], type_="prod", range_=dep,
                                     edge_source="pip-report", project=project.id)
                    edges += 1
        builder.mark_authoritative("pypi", project.id)
        return {"packages": len(installed), "edges": edges}


# ---------------------------------------------------------------------- go
class GoResolver(Resolver):
    ecosystem = "golang"
    tool = "go"
    ENV = {"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod", "GONOSUMDB": "", "GOWORK": "off"}

    def native(self, project: Project, ctx: ResolverContext, builder: GraphBuilder) -> dict:
        res = {"project": project.id, "ecosystem": "golang", "native": "go mod graph"}
        if not find_tool("go"):
            return {**res, "status": "gap", "reason": "go not installed: edges come from SBOM tools only"}
        cwd = ctx.repo_path / project.path
        out = ctx.native_dir / f"go-mod-graph-{slug(project.path)}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        rec = ctx.record(run_recorded("go", ["go", "mod", "graph"], cwd=cwd, timeout=600, env=self.ENV))
        if rec["status"] != "ok":
            return {**res, "status": "gap", "reason": rec.get("error")}
        out.write_text(rec.get("stdout") or "")
        sel = ctx.record(run_recorded("go", ["go", "list", "-m", "all"], cwd=cwd, timeout=600, env=self.ENV))
        selected = {}
        for line in (sel.get("stdout") or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                selected[parts[0]] = parts[1]
        root_mod = project.name
        edges = 0
        for line in (rec.get("stdout") or "").splitlines():
            a, _, b = line.partition(" ")
            if not b:
                continue
            am, _, av = a.partition("@")
            bm, _, bv = b.partition("@")
            if bm in ("go", "toolchain") or am in ("go", "toolchain"):
                continue                               # language/toolchain pseudo-modules
            if selected and selected.get(bm) != bv:
                continue                               # not the MVS-selected version
            if av and selected and selected.get(am) != av:
                continue
            src = project.id if not av else build_purl("golang", am, av)
            dst = build_purl("golang", bm, bv)
            for purl, mod, ver in ((dst, bm, bv),) + (((src, am, av),) if av else ()):
                builder.add_node(purl, name=mod, version=ver, ecosystem="golang", source="go-mod-graph",
                                 occurrence={"project": project.id, "lockfile": project.lockfile,
                                             "install_path": None, "resolved": None, "integrity": None})
            builder.add_edge(src, dst, type_="prod", range_=bv, edge_source="go-mod-graph", project=project.id)
            if src == project.id:
                builder.add_declared(dst, project.manifest, "require", bv)
            edges += 1
        builder.mark_authoritative("golang", project.id)
        return {**res, "status": "ok", "output": out.name, "edges": edges, "module": root_mod,
                "selected_modules": len(selected)}


# ------------------------------------------------------------- maven/gradle
class JvmResolver(Resolver):
    ecosystem = "maven"

    def native(self, project: Project, ctx: ResolverContext, builder: GraphBuilder) -> dict:
        name = PurePosixPath(project.manifest).name
        is_maven = name == "pom.xml"
        tool = "mvn" if is_maven else "gradle"
        res = {"project": project.id, "ecosystem": "maven", "native": f"{tool} dependency tree"}
        if not find_tool(tool):
            return {**res, "status": "gap",
                    "reason": f"{tool} not installed: only dependencies declared in {name} are known "
                              "(no transitive resolution); the Gradle/Maven wrapper is never executed"}
        out = ctx.native_dir / f"{tool}-tree-{slug(project.path)}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = (["mvn", "-B", "-q", "dependency:tree", f"-DoutputFile={out}"] if is_maven
               else ["gradle", "-q", "--offline", "dependencies"])
        rec = ctx.record(run_recorded(tool, cmd, cwd=ctx.repo_path / project.path, timeout=900))
        if rec["status"] != "ok":
            return {**res, "status": "gap", "reason": rec.get("error")}
        if not is_maven:
            out.write_text(rec.get("stdout") or "")
        return {**res, "status": "raw-only", "output": out.name,
                "reason": "tree saved; edges come from cdxgen/Trivy for this ecosystem"}


RESOLVERS: dict[str, Resolver] = {r.ecosystem: r for r in (NpmResolver(), PythonResolver(), GoResolver(), JvmResolver())}


def resolver_for(ecosystem: str) -> Resolver:
    return RESOLVERS.get(ecosystem, Resolver())


def has_lockfile_parser(project: Project) -> bool:
    return project.ecosystem == "npm" and bool(project.lockfile) and \
        PurePosixPath(project.lockfile).name in LOCKFILES["npm"]
