"""coverage.json: the proof of completeness (or an honest list of what is missing)."""

from __future__ import annotations

from collections import Counter

from .build import SOURCE_TOOLS

TOOL_SET = ("lockfile-parser", "npm-ls", "go-mod-graph", "pip-report", "syft", "cdxgen", "trivy",
            "workflow-parser")


def build_coverage(inv: dict, source_graph: dict, source_meta: dict, tool_results: dict,
                   ci: dict | None, container: dict | None) -> dict:
    nodes = inv["nodes"]
    source_nodes = {k: n for k, n in nodes.items() if not n.get("container_only")}

    # 1. per tool
    per_tool = {}
    found = {t: {k for k, n in source_nodes.items() if t in n.get("found_by", [])} for t in TOOL_SET}
    for t in TOOL_SET:
        others = set().union(*(found[o] for o in TOOL_SET if o != t))
        entries = (tool_results.get(t) or {}).get("stats", {}).get("entries")
        per_tool[t] = {
            "entries": entries,
            "unique_purls": len(found[t]),
            "only_this_tool": len(found[t] - others),
            "only_this_tool_examples": sorted(found[t] - others)[:20],
            "by_ecosystem": dict(Counter(source_nodes[k]["ecosystem"] for k in found[t])),
        }
    sbom_tools = ("syft", "cdxgen", "trivy")
    non_ci = {k for k, n in source_nodes.items() if n["ecosystem"] != "github"}
    agreement = {
        "components_compared": len(non_ci),
        "found_by_all_sbom_tools": sum(1 for k in non_ci if all(k in found[t] for t in sbom_tools)),
        "found_by_lockfile_and_all_sbom_tools": sum(1 for k in non_ci if k in found["lockfile-parser"]
                                                     and all(k in found[t] for t in sbom_tools)),
        "missing_per_sbom_tool": {t: sorted(non_ci - found[t])[:50] for t in sbom_tools},
        "missing_count_per_sbom_tool": {t: len(non_ci - found[t]) for t in sbom_tools},
    }

    # 2. lockfile coverage: every package entry of every lockfile must be in the inventory
    lockfiles = []
    for lock, purls in (source_meta.get("lockfile_purls") or {}).items():
        missing = sorted(p for p in purls if p not in nodes)
        parse = next((p for p in source_meta.get("lockfile_parse", []) if p["lockfile"] == lock), {})
        lockfiles.append({"lockfile": lock, "format": parse.get("format"), "install_entries": parse.get("entries"),
                          "unique_packages": len(purls), "in_inventory": len(purls) - len(missing),
                          "percent": round(100.0 * (len(purls) - len(missing)) / len(purls), 2) if purls else 100.0,
                          "missing": missing[:100]})
    npm_ls = []
    for project, purls in (source_meta.get("npm_ls_purls") or {}).items():
        missing = sorted(p for p in purls if p not in nodes)
        npm_ls.append({"project": project, "packages": len(purls), "in_inventory": len(purls) - len(missing),
                       "percent": round(100.0 * (len(purls) - len(missing)) / len(purls), 2) if purls else 100.0,
                       "missing": missing[:50]})

    # 3. reachability
    unreachable = [{"id": k, "reason": "no edge from any root"} for k, n in nodes.items() if not n.get("reachable_from")]
    by_root_kind = Counter()
    for n in nodes.values():
        kinds = {inv["roots"][r]["kind"] for r in n.get("reachable_from", [])}
        by_root_kind["project" if "project" in kinds else (next(iter(kinds)) if kinds else "none")] += 1

    # 4. ecosystems
    detected = Counter(m["ecosystem"] for m in source_meta.get("manifests", []))
    eco_rows = {}
    for row in source_meta.get("coverage_summary", {}).get("projects", []):
        eco = row["ecosystem"]
        r = eco_rows.setdefault(eco, {"ecosystem": eco, "projects": 0, "full": 0, "partial": 0, "gap": 0, "reasons": []})
        r["projects"] += 1
        status = row.get("status")
        key = "full" if status == "full" else "gap" if status == "gap" else "partial"
        r[key] += 1
        if key != "full" and row.get("reason") and row["reason"] not in r["reasons"]:
            r["reasons"].append(row["reason"])
    for eco in detected:
        eco_rows.setdefault(eco, {"ecosystem": eco, "projects": 0, "full": 0, "partial": 0, "gap": 0,
                                  "reasons": ["manifest found but no project root (e.g. only a lockfile)"]})
    for eco_name, label in (("github", "GitHub Actions"), ):
        if ci and ci.get("actions"):
            eco_rows[eco_name] = {"ecosystem": eco_name, "projects": len(ci.get("workflows", [])), "full": 1, "partial": 0,
                                  "gap": 0, "reasons": [f"{label}: parsed from .github/workflows (all `uses:` references)"]}
    ecosystems = sorted(eco_rows.values(), key=lambda r: r["ecosystem"])
    for r in ecosystems:
        r["resolution"] = "full" if r["full"] and not r["gap"] and not r["partial"] else \
                          "declared-only" if r["gap"] and not r["full"] else "partial" if r["projects"] else "none"

    # 5. container vs source
    container_cov = None
    if container and container.get("inspected"):
        image = {p["purl"]: p for p in container.get("packages", [])}
        src = {k: n for k, n in source_nodes.items() if n["ecosystem"] not in ("github",)}
        src_names = {}
        for k, n in src.items():
            src_names.setdefault((n["ecosystem"], n["name"]), set()).add(n["version"])
        both = sorted(set(image) & set(src))
        image_only = sorted(set(image) - set(src))
        version_drift = [p for p in image_only if (image[p]["ecosystem"], image[p]["name"]) in src_names]
        source_only = sorted(set(src) - set(image))
        source_only_prod = [p for p in source_only if src[p].get("scope") in ("prod", "peer")]
        container_cov = {
            "image": container.get("ref"), "digest": container.get("digest"),
            "image_packages": len(image), "image_os_packages": sum(1 for p in image.values() if p["kind"] == "os"),
            "in_both": len(both),
            "image_only": len(image_only),
            "image_only_os": sum(1 for p in image_only if image[p]["kind"] == "os"),
            "image_only_application": sum(1 for p in image_only if image[p]["kind"] != "os"),
            "image_only_same_name_other_version": len(version_drift),
            "source_only": len(source_only),
            "source_only_prod_scope": len(source_only_prod),
            "source_only_dev_scope": sum(1 for p in source_only if src[p].get("scope") == "dev"),
            "image_only_examples": image_only[:50],
            "version_drift_examples": [{"image": p, "source_versions": sorted(src_names[(image[p]["ecosystem"], image[p]["name"])])}
                                       for p in version_drift[:30]],
            "source_only_prod_examples": source_only_prod[:50],
            "note": "The image is built from a released version and excludes devDependencies; "
                    "differences against the cloned commit are expected and listed here as facts.",
        }

    unresolved = source_graph.get("unresolved", [])
    return {
        "per_tool": per_tool,
        "tool_agreement": agreement,
        "lockfiles": lockfiles,
        "lockfile_coverage_ok": all(l["percent"] == 100.0 for l in lockfiles),
        "npm_ls": npm_ls,
        "unreachable_nodes": {"count": len(unreachable), "items": unreachable[:100]},
        "nodes_by_root_kind": dict(by_root_kind),
        "unresolved_edges": {"count": len(unresolved),
                             "by_reason": dict(Counter(u["reason"] for u in unresolved)),
                             "items": unresolved[:200]},
        "ecosystems": ecosystems,
        "projects": source_meta.get("coverage_summary", {}).get("projects", []),
        "edges_by_source": dict(Counter(e["edge_source"] for e in inv["edges"])),
        "tool_only_components": [k for k, n in source_nodes.items() if n.get("tool_only")][:100],
        "container": container_cov,
        "skipped_dirs": source_meta.get("skipped_dirs", []),
        "sources_considered": list(SOURCE_TOOLS) + ["workflow-parser", "syft-image", "trivy-image"],
    }
