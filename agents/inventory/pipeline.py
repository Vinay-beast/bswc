"""inventory agent: merge source-deps + artifact-inspector into the single source of truth.

Writes outputs/<app_id>/inventory/:
    status.json
    components.json     one entry per unique purl (origin, provenance, relationship, scope, tools, container)
    graph.json          roots / nodes / edges / stats
    paths.json          shortest path from each root + number of distinct paths (capped)
    sbom.cdx.json       merged CycloneDX 1.6 with a full dependencies section (schema-validated)
    sbom.spdx.json      SPDX 2.3 export with DEPENDS_ON / CONTAINS relationships (schema-validated)
    coverage.json       per-tool counts, lockfile coverage, unreachable nodes, unresolved edges, gaps, container diff
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from agents.common import DEFAULT_OUTPUTS, AgentRun, now_iso, parse_repo_url, read_json, read_run_info, write_json
from agents.common.tools import get_tool_versions

from .build import build_inventory, component_record, graph_record
from .coverage import build_coverage
from .sboms import build_cyclonedx, build_spdx, validate_cyclonedx, validate_spdx

log = logging.getLogger(__name__)

AGENT, FOLDER, STAGE = "inventory", "inventory", "discover"


def run_inventory(repo_url: str, *, run_id: str | None = None, outputs: Path = DEFAULT_OUTPUTS) -> dict:
    repo = parse_repo_url(repo_url)
    run = read_run_info(repo.app_id, outputs)
    run_id = run_id or run.get("run_id")
    if not run_id:
        raise RuntimeError("No run_id: run source-deps first (or use python -m agents.discover)")
    base = Path(outputs) / repo.app_id
    with AgentRun(repo.app_id, AGENT, FOLDER, STAGE, run_id, outputs) as status:
        sd = base / "source_deps"
        sd_status = read_json(sd / "status.json", {}) or {}
        if sd_status.get("state") != "done":
            raise RuntimeError("source-deps has not completed for this app; nothing to merge")
        if sd_status.get("run_id") != run_id:
            status.warn(f"source-deps output belongs to run {sd_status.get('run_id')}, not {run_id}")
        source_graph = read_json(sd / "source_graph.json")
        source_meta = read_json(sd / "source_meta.json")
        tool_results = read_json(sd / "tool_results.json", {}) or {}
        art = base / "artifacts"
        art_status = read_json(art / "status.json", {}) or {}
        ci = container = None
        if art_status.get("state") == "done":
            if art_status.get("run_id") != run_id:
                status.warn(f"artifact-inspector output belongs to run {art_status.get('run_id')}, not {run_id}")
            ci = read_json(art / "ci_inventory.json")
            container = read_json(art / "container.json")
        else:
            status.warn("artifact-inspector output missing or not done: no CI or container data merged")

        inv = build_inventory(source_graph, source_meta, tool_results, ci, container)
        components = [component_record(n) for n in sorted(inv["nodes"].values(), key=lambda n: n["id"])]
        graph = graph_record(inv)
        write_json(status.dir / "components.json", components)
        write_json(status.dir / "graph.json", graph, indent=None)
        write_json(status.dir / "paths.json", {"cap": 1000, "roots": sorted(inv["roots"]), "paths": inv["paths"]},
                   indent=None)

        versions = get_tool_versions()
        run = read_run_info(repo.app_id, outputs)
        cdx = build_cyclonedx(inv, run, versions, container)
        cdx_validation = validate_cyclonedx(cdx)
        write_json(status.dir / "sbom.cdx.json", cdx)
        spdx = build_spdx(inv, run, versions, container)
        spdx_validation = validate_spdx(spdx)
        write_json(status.dir / "sbom.spdx.json", spdx)
        for label, v in (("CycloneDX", cdx_validation), ("SPDX", spdx_validation)):
            if v["valid"] is False:
                status.warn(f"{label} SBOM failed validation ({v['error_count']} errors): {v['errors'][0]}")

        coverage = build_coverage(inv, source_graph, source_meta, tool_results, ci, container)
        coverage["sbom_validation"] = {"cyclonedx": cdx_validation, "spdx": spdx_validation}
        coverage["sbom_counts"] = {
            "cyclonedx_components_top_level": len(cdx["components"]),
            "cyclonedx_components_total": _count_components(cdx["components"]) + 1,
            "cyclonedx_dependencies_entries": len(cdx["dependencies"]),
            "cyclonedx_dependency_edges": sum(len(d["dependsOn"]) for d in cdx["dependencies"]),
            "spdx_packages": len(spdx["packages"]),
            "spdx_relationships": len(spdx["relationships"]),
        }
        coverage["generated_at"] = now_iso()
        write_json(status.dir / "coverage.json", coverage)
        if not coverage["lockfile_coverage_ok"]:
            status.warn("Lockfile coverage below 100%: see coverage.json")

        for rel, kind in (("components.json", "inventory"), ("graph.json", "graph"), ("paths.json", "graph"),
                          ("sbom.cdx.json", "sbom"), ("sbom.spdx.json", "sbom-spdx"), ("coverage.json", "report")):
            status.add_artifact(rel, kind)
        summary = _summary(inv, graph, coverage, ci, container, cdx_validation)
        status.done(summary, coverage=_coverage_brief(coverage))
        update_ok = {"finished_at": now_iso()}
        from agents.common import update_run_info
        update_run_info(repo.app_id, outputs, **update_ok)
        return {"summary": summary, "graph_stats": graph["stats"], "coverage": coverage,
                "sbom": {"cyclonedx": cdx_validation, "spdx": spdx_validation}}


def _count_components(comps: list[dict]) -> int:
    return sum(1 + _count_components(c.get("components") or []) for c in comps)


def _summary(inv, graph, coverage, ci, container, cdx_validation) -> dict:
    nodes = inv["nodes"].values()
    src = [n for n in nodes if n.get("relationship") in ("direct", "transitive")]
    by_eco = Counter(n["ecosystem"] for n in src)
    return {
        "components": len(src),
        "direct": sum(1 for n in src if n["relationship"] == "direct"),
        "transitive": sum(1 for n in src if n["relationship"] == "transitive"),
        "dev_only": sum(1 for n in src if n.get("scope") == "dev"),
        "ecosystems": len(by_eco),
        "edges": graph["stats"]["edges"],
        "roots": graph["stats"]["roots"],
        "max_depth": graph["stats"]["max_depth"],
        "container_packages": (container or {}).get("counts", {}).get("total", 0) if (container or {}).get("inspected") else 0,
        "workflows": (ci or {}).get("summary", {}).get("workflows", 0),
        "actions": (ci or {}).get("summary", {}).get("unique_actions", 0),
        "actions_not_sha_pinned": (ci or {}).get("summary", {}).get("not_sha_pinned", 0),
        "lockfile_coverage": "100%" if coverage["lockfile_coverage_ok"] else "<100%",
        "cyclonedx_valid": cdx_validation["valid"],
        "unreachable_nodes": coverage["unreachable_nodes"]["count"],
        "unresolved_edges": coverage["unresolved_edges"]["count"],
        "by_ecosystem": dict(sorted(by_eco.items())),
    }


def _coverage_brief(cov: dict) -> dict:
    return {
        "per_tool": {t: {k: v for k, v in d.items() if k in ("unique_purls", "only_this_tool")} for t, d in cov["per_tool"].items()},
        "lockfiles": [{k: l[k] for k in ("lockfile", "unique_packages", "in_inventory", "percent")} for l in cov["lockfiles"]],
        "lockfile_coverage_ok": cov["lockfile_coverage_ok"],
        "unreachable_nodes": cov["unreachable_nodes"]["count"],
        "unresolved_edges": cov["unresolved_edges"]["count"],
        "ecosystems": [{k: e[k] for k in ("ecosystem", "resolution", "reasons")} for e in cov["ecosystems"]],
    }
