"""source-deps agent: clone -> manifests -> lockfiles -> native resolvers -> multi-tool SBOMs -> source graph.

Writes outputs/<app_id>/source_deps/:
    status.json
    source_meta.json        repo, tools, manifests, projects, lockfile generation, tool runs, coverage
    source_graph.json       roots / nodes / edges / unresolved, built from lockfiles + native resolvers
    tool_results.json       each tool's normalised component list and edges (for cross-checking)
    raw/syft.cdx.json raw/syft.spdx.json raw/cdxgen.cdx.json raw/trivy-fs.cdx.json raw/native/*
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from agents.common import (DEFAULT_OUTPUTS, DEFAULT_WORKSPACE, AgentRun, new_run_id, now_iso,
                           parse_repo_url, update_run_info, write_json)
from agents.common.purl import build_purl, canonical_purl, purl_ecosystem
from agents.common.sbomtools import (cdxgen_dir, normalize_cdx, syft_dir, tool_exclude_globs,
                                     trivy_fs)
from agents.common.tools import ToolError, get_tool_versions, public_record, require_tool, run

from .graph_model import GraphBuilder
from .ingest import fetch_repo, get_repo_info
from .lockfiles import LockfileError, parse_lockfile
from .manifests import detect_projects, discover_manifests
from .resolvers import ResolverContext, has_lockfile_parser, resolver_for

log = logging.getLogger(__name__)

AGENT, FOLDER, STAGE = "source-deps", "source_deps", "discover"
TOOL_PREFERENCE = ("cdxgen", "trivy", "syft")       # edge sources when no lockfile parser applies
CI_ECOSYSTEMS = {"github"}                         # owned by the artifact-inspector agent


def remote_sha(url: str, ref: str | None) -> str | None:
    """Commit the remote ref points to, without cloning (for an early run_id)."""
    try:
        out = run(["git", "ls-remote", url, ref or "HEAD"], timeout=60,
                  env={"GIT_TERMINAL_PROMPT": "0"}).stdout
    except ToolError:
        return None
    line = out.splitlines()[0] if out.strip() else ""
    sha = line.split()[0] if line else None
    if not sha and ref and len(ref) >= 7 and all(c in "0123456789abcdef" for c in ref.lower()):
        return ref
    return sha


def start_run(repo_url: str, ref: str | None, outputs: Path = DEFAULT_OUTPUTS) -> tuple[str, str]:
    """Create a run_id and write run.json for a new discovery run. Returns (app_id, run_id)."""
    repo = parse_repo_url(repo_url)
    run_id = new_run_id(remote_sha(repo.url, ref))
    update_run_info(repo.app_id, outputs, run_id=run_id, display_name=repo.display_name,
                    repo_url=repo.url, owner=repo.owner, repo=repo.repo, host=repo.host, ref=ref,
                    started_at=now_iso(), finished_at=None)
    return repo.app_id, run_id


def run_source_deps(repo_url: str, ref: str | None = None, *, refresh: bool = False,
                    include_all: bool = False, run_id: str | None = None,
                    workspace: Path = DEFAULT_WORKSPACE, outputs: Path = DEFAULT_OUTPUTS) -> dict:
    repo = parse_repo_url(repo_url)
    if run_id is None:
        _, run_id = start_run(repo_url, ref, outputs)
    with AgentRun(repo.app_id, AGENT, FOLDER, STAGE, run_id, outputs) as status:
        for tool in ("git", "npm"):
            require_tool(tool)
        meta = _run(repo, ref, refresh, include_all, workspace, status)
        update_run_info(repo.app_id, outputs, commit_sha=meta["repo"]["commit_sha"],
                        commit_date=meta["repo"]["commit_date"], default_branch=meta["repo"]["default_branch"],
                        workspace=meta["repo"]["local_path"])
        for rel, kind in (("source_meta.json", "json"), ("source_graph.json", "graph"),
                          ("tool_results.json", "json"), ("raw/syft.cdx.json", "sbom"),
                          ("raw/syft.spdx.json", "sbom-spdx"), ("raw/cdxgen.cdx.json", "sbom"),
                          ("raw/trivy-fs.cdx.json", "sbom")):
            status.add_artifact(rel, kind)
        for f in sorted((status.dir / "raw" / "native").glob("*")):
            status.add_artifact(f"raw/native/{f.name}", "report")
        status.done(meta["summary"], coverage=meta["coverage_summary"])
        return meta


def _tracked_files(repo_path: Path) -> set[str]:
    try:
        out = run(["git", "ls-files", "-z"], cwd=repo_path, timeout=60).stdout
    except ToolError:
        return set()
    return {p for p in out.split("\0") if p}


def _infer_project(location: str, projects: list) -> str | None:
    """Project whose directory is the deepest prefix of `location`."""
    best, best_len = None, -1
    loc = PurePosixPath(location)
    for p in projects:
        d = PurePosixPath(p.path)
        if p.path == "." or loc == d or d in loc.parents:
            depth = 0 if p.path == "." else len(d.parts)
            if depth > best_len:
                best, best_len = p.id, depth
    return best


def _run(repo, ref, refresh, include_all, workspace, status: AgentRun) -> dict:
    started = now_iso()
    fetch = fetch_repo(repo, ref, refresh=refresh, workspace=workspace)
    repo_path = fetch.path
    info = get_repo_info(repo, fetch)
    raw = status.dir / "raw"
    native_dir = raw / "native"
    native_dir.mkdir(parents=True, exist_ok=True)

    # 1. manifests and projects
    manifests, skipped = discover_manifests(repo_path, include_all)
    projects = detect_projects(repo_path, manifests)
    tracked = _tracked_files(repo_path)
    ctx = ResolverContext(repo_path, native_dir, fetch.sha, info["commit_date"], tracked)

    # 2. lockfiles (prepare) and the authoritative lockfile graph
    lock_records = []
    for p in projects:
        rec = resolver_for(p.ecosystem).prepare(p, ctx)
        if rec:
            lock_records.append(rec)
        elif p.lockfile:
            p.lockfile_origin = "original" if p.lockfile in tracked else "generated"
    builder = GraphBuilder()
    for p in projects:
        builder.add_root(p.id, name=p.name, version=p.version, ecosystem=p.ecosystem, manifest=p.manifest,
                         lockfile=p.lockfile, lockfile_origin=p.lockfile_origin, path=p.path,
                         workspace_members=p.workspace_members or None)
    lockfile_stats, project_coverage = [], []
    for p in projects:
        if has_lockfile_parser(p):
            try:
                stats = parse_lockfile(repo_path, p, builder)
                lockfile_stats.append({"project": p.id, **stats})
                project_coverage.append({"project": p.id, "ecosystem": p.ecosystem, "lockfile": p.lockfile,
                                         "lockfile_origin": p.lockfile_origin, "resolution": "lockfile-parser",
                                         "format": stats["format"], "status": "full"})
            except LockfileError as exc:
                ctx.warn(f"Lockfile parser failed ({exc}); edges for {p.id} fall back to cdxgen/Trivy")
                project_coverage.append({"project": p.id, "ecosystem": p.ecosystem, "lockfile": p.lockfile,
                                         "lockfile_origin": p.lockfile_origin, "resolution": "tool-edges",
                                         "status": "partial", "reason": str(exc)})

    # 3. native resolvers (read-only)
    natives = []
    for p in projects:
        res = resolver_for(p.ecosystem).native(p, ctx, builder)
        natives.append(res)
        if p.ecosystem == "npm":
            continue
        authoritative = p.id in builder.edge_sources.get(p.ecosystem, set())
        if authoritative:
            resolution, cov = res.get("native"), "full"
        elif p.lockfile:
            resolution, cov = "tool-edges", "lockfile-tools"
        else:
            resolution, cov = "declared-only", "gap"
        project_coverage.append({"project": p.id, "ecosystem": p.ecosystem, "lockfile": p.lockfile,
                                 "lockfile_origin": p.lockfile_origin, "resolution": resolution,
                                 "status": cov, "reason": res.get("reason")})
        if cov == "gap":
            ctx.warn(f"{p.id} ({p.ecosystem}): {res.get('reason') or 'no lockfile and no resolver'}")
    for p in projects:
        if p.ecosystem == "npm" and not p.lockfile:
            project_coverage.append({"project": p.id, "ecosystem": "npm", "lockfile": None,
                                     "resolution": "declared-only", "status": "gap",
                                     "reason": "no lockfile and generation failed"})

    # 4. SBOM tools, in parallel (each independent, non-fatal)
    globs = tool_exclude_globs(skipped)
    cache = Path(tempfile.mkdtemp(prefix="guardian-trivy-"))
    files = {"syft": raw / "syft.cdx.json", "cdxgen": raw / "cdxgen.cdx.json", "trivy": raw / "trivy-fs.cdx.json"}
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = {
                "syft": pool.submit(syft_dir, repo_path, files["syft"], raw / "syft.spdx.json", globs["syft"]),
                "cdxgen": pool.submit(cdxgen_dir, repo_path, files["cdxgen"], globs["cdxgen"]),
                "trivy": pool.submit(trivy_fs, repo_path, files["trivy"], globs["trivy"], cache),
            }
            tool_runs = {name: f.result() for name, f in futs.items()}
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    tool_results = {}
    for name, rec in tool_runs.items():
        ctx.record(rec)
        if rec["status"] != "ok":
            ctx.warn(f"{name} failed ({rec['status']}): {rec.get('error')}")
            continue
        try:
            tool_results[name] = normalize_cdx(files[name], name, repo_path)
        except (OSError, ValueError) as exc:
            ctx.warn(f"Could not parse {name} output: {exc}")

    # 5. merge tool findings into the graph
    tool_only = _merge_tools(builder, tool_results, projects)

    # 6. fallback edges and location-only attachment for non-authoritative parts
    edge_fallback = _fallback_edges(builder, tool_results, projects)

    graph = builder.to_dict()
    graph["projects"] = [p.to_dict() for p in projects]
    write_json(status.dir / "source_graph.json", graph)
    write_json(status.dir / "tool_results.json", {
        name: {"tool": name, "spec_version": r["spec_version"], "stats": r["stats"],
               "components": sorted(r["components"].values(), key=lambda c: c["purl"]),
               "edges": r["edges"], "root_edges": r["root_edges"]}
        for name, r in tool_results.items()})

    src_nodes = [n for n in builder.nodes.values() if n["ecosystem"] not in CI_ECOSYSTEMS]
    generated = [r for r in lock_records if r.get("status") == "generated"]
    summary = {
        "projects": len(projects),
        "manifests": sum(1 for m in manifests if m["kind"] == "manifest"),
        "lockfiles_generated": len(generated),
        "components": len(src_nodes),
        "edges": len(builder.edges),
        "unresolved_edges": len(builder.unresolved),
        "tools_ok": sum(1 for r in tool_runs.values() if r["status"] == "ok"),
        "tools_failed": sum(1 for r in tool_runs.values() if r["status"] != "ok"),
    }
    coverage_summary = {
        "projects": project_coverage,
        "tools": {n: r["stats"] for n, r in tool_results.items()},
        "tool_only_components": len(tool_only),
        "edges_by_source": edge_fallback["by_source"],
        "location_only_attachments": edge_fallback["location_only"],
        "skipped_dirs": skipped,
    }
    meta = {
        "app_id": repo.app_id,
        "repo": info,
        "tool_versions": get_tool_versions(),
        "include_all": include_all,
        "manifests": [{**m, "origin": "generated" if any(r.get("lockfile") == m["path"] and r.get("status") == "generated"
                                                         for r in lock_records) else "original"}
                      for m in discover_manifests(repo_path, include_all)[0]],
        "skipped_dirs": skipped,
        "projects": [p.to_dict() for p in projects],
        "lockfiles": lock_records,
        "lockfile_parse": [{k: v for k, v in s.items() if k != "purls"} for s in lockfile_stats],
        "lockfile_purls": {s["lockfile"]: s["purls"] for s in lockfile_stats},
        "native_resolvers": [{k: v for k, v in n.items() if k != "purls"} for n in natives],
        "npm_ls_purls": {n["project"]: n["purls"] for n in natives if n.get("purls")},
        "tool_runs": [public_record(r) for r in ctx.tool_runs],
        "tool_only_components": tool_only[:500],
        "warnings": ctx.warnings,
        "summary": summary,
        "coverage_summary": coverage_summary,
        "run": {"started_at": started, "finished_at": now_iso()},
    }
    write_json(status.dir / "source_meta.json", meta)
    for w in ctx.warnings:
        status.warn(w)
    return meta


def _merge_tools(builder: GraphBuilder, tool_results: dict, projects: list) -> list[dict]:
    lock_to_project = {p.lockfile: p.id for p in projects if p.lockfile}
    project_purls = {canonical_purl(build_purl(p.ecosystem, p.name, p.version)): p.id
                     for p in projects if p.name and p.version}
    for root in builder.roots.values():                 # workspace members found in lockfiles
        if root.get("name") and root.get("version") and root.get("ecosystem"):
            project_purls.setdefault(build_purl(root["ecosystem"], root["name"], root["version"]), root["id"])
    tool_only = []
    for name, res in tool_results.items():
        for purl, c in res["components"].items():
            if purl in project_purls:                   # the project itself, not a dependency
                builder.roots[project_purls[purl]].setdefault("found_by", [])
                if name not in builder.roots[project_purls[purl]]["found_by"]:
                    builder.roots[project_purls[purl]]["found_by"].append(name)
                continue
            node = builder.nodes.get(purl)
            if node is None:
                loc = next((l for l in c["locations"] if l in lock_to_project), c["locations"][0] if c["locations"] else "")
                project = lock_to_project.get(loc) or _infer_project(loc, projects) if loc else None
                node = builder.add_node(purl, name=c["name"], version=c["version"],
                                        ecosystem=c["ecosystem"] or purl_ecosystem(purl) or "unknown",
                                        occurrence={"project": project, "lockfile": loc or None,
                                                    "install_path": None, "resolved": c.get("resolved"),
                                                    "integrity": None, "via": name})
                node["tool_only"] = True
                if c["ecosystem"] not in CI_ECOSYSTEMS:
                    tool_only.append({"purl": purl, "tool": name, "locations": c["locations"][:5]})
            if name not in node["found_by"]:
                node["found_by"].append(name)
            node.setdefault("tool_licenses", {})[name] = c["licenses"]
            node.setdefault("tool_locations", {})[name] = c["locations"][:20]
            if c.get("hash_algs"):
                node.setdefault("tool_hash_algs", {})[name] = c["hash_algs"]
            if c.get("resolved") and not any(o.get("resolved") for o in node["occurrences"]):
                node["tool_resolved"] = c["resolved"]
    return tool_only


def _fallback_edges(builder: GraphBuilder, tool_results: dict, projects: list) -> dict:
    """Edges from cdxgen/Trivy/Syft for nodes no authoritative parser covered."""
    authoritative = set().union(*builder.edge_sources.values()) if builder.edge_sources else set()
    project_ids = {p.id for p in projects}

    def covered(purl: str) -> bool:
        node = builder.nodes.get(purl)
        return bool(node) and any(o.get("project") in authoritative and o.get("via") is None
                                  for o in node["occurrences"])

    by_source: dict[str, int] = {}
    for e in builder.edges.values():
        by_source[e["edge_source"]] = by_source.get(e["edge_source"], 0) + 1
    for name in TOOL_PREFERENCE:
        res = tool_results.get(name)
        if not res:
            continue
        for a, b in res["edges"]:
            if covered(a) and covered(b):
                continue
            if purl_ecosystem(a) in CI_ECOSYSTEMS or purl_ecosystem(b) in CI_ECOSYSTEMS:
                continue
            if (a, b) in builder.edges or a not in builder.nodes or b not in builder.nodes:
                continue
            builder.add_edge(a, b, type_="prod", range_=None, edge_source=name)
            by_source[name] = by_source.get(name, 0) + 1
    # Nodes nobody points to: attach to the project they were found in.
    has_incoming = {e["to"] for e in builder.edges.values()}
    location_only = 0
    for purl, node in builder.nodes.items():
        if purl in has_incoming or node["ecosystem"] in CI_ECOSYSTEMS:
            continue
        project = next((o.get("project") for o in node["occurrences"] if o.get("project") in project_ids), None)
        if project is None and projects:
            project = projects[0].id
        if project:
            builder.add_edge(project, purl, type_="prod", range_=None, edge_source="location-only", project=project)
            node["relationship_basis"] = "location-only"
            location_only += 1
    by_source["location-only"] = location_only
    return {"by_source": by_source, "location_only": location_only}
