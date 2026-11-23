"""Merge source-deps + artifact-inspector outputs into one inventory graph.

Roots:
    project:<path>          every project (app, frontend, workspace members, go module, ...)
    ci:github-actions       GitHub Actions used by the workflows
    container:<image ref>   the inspected image: its OS packages and app packages not seen in source
"""

from __future__ import annotations

from urllib.parse import urlparse

from agents.common.purl import purl_display_name

from . import graphalgo as ga

CI_ROOT = "ci:github-actions"
DEFAULT_REGISTRIES = {
    "npm": {"registry.npmjs.org", "registry.yarnpkg.com"},
    "pypi": {"files.pythonhosted.org", "pypi.org"},
    "golang": {"proxy.golang.org"},
    "maven": {"repo.maven.apache.org", "repo1.maven.org"},
}
SOURCE_TOOLS = ("lockfile-parser", "npm-ls", "go-mod-graph", "pip-report", "syft", "cdxgen", "trivy")


def origin_of(ecosystem: str, resolved_urls: list[str]) -> dict:
    hosts, flags = set(), set()
    for url in resolved_urls:
        if url.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:")) or url.endswith(".git"):
            flags.add("git")
        elif url.startswith("file:"):
            flags.add("file")
        elif url.startswith("link:") or url.startswith("workspace:"):
            flags.add("link")
        p = urlparse(url)
        if p.scheme in ("http", "https") and p.netloc:
            hosts.add(p.netloc)
            if p.scheme == "http":
                flags.add("insecure-http")
            defaults = DEFAULT_REGISTRIES.get(ecosystem)
            if defaults and p.netloc not in defaults:
                flags.add("non-default-registry")
            if ecosystem == "npm" and "/-/" not in p.path and "git" not in flags:
                flags.add("tarball-url")
    return {"resolved_urls": sorted(set(resolved_urls))[:10], "registry_hosts": sorted(hosts),
            "flags": sorted(flags)}


def integrity_of(occurrences: list[dict], tool_hash_algs: dict) -> dict:
    algs = set()
    for o in occurrences:
        integ = o.get("integrity") or ""
        for part in str(integ).split():
            if "-" in part:
                algs.add(part.split("-", 1)[0].lower())
            elif ":" in part:
                algs.add(part.split(":", 1)[0].lower())
    source = "lockfile" if algs else None
    if not algs:
        for tool_algs in (tool_hash_algs or {}).values():
            algs |= {a.lower().replace("-", "") for a in tool_algs}
        source = "sbom-tool" if algs else None
    return {"present": bool(algs), "algorithms": sorted(algs), "source": source}


def build_inventory(source_graph: dict, source_meta: dict, tool_results: dict,
                    ci: dict | None, container: dict | None) -> dict:
    roots: dict[str, dict] = {r["id"]: {**r, "kind": "project"} for r in source_graph["roots"]}
    nodes: dict[str, dict] = {n["id"]: dict(n) for n in source_graph["nodes"] if n["ecosystem"] != "github"}
    edges: list[dict] = [dict(e) for e in source_graph["edges"]
                         if e["from"] in nodes or e["from"] in roots]
    edges = [e for e in edges if e["to"] in nodes or e["to"] in roots]

    # --- CI root: deduplicated actions (and job images) -------------------------
    ci_actions = []
    if ci and ci.get("actions"):
        roots[CI_ROOT] = {"id": CI_ROOT, "kind": "ci", "name": "GitHub Actions", "ecosystem": "github",
                          "workflows": len(ci.get("workflows", []))}
        # Map tool-reported action purls onto the workflow parser's actions. Tools spell them
        # differently: Syft uses the `# vX.Y` comment after a SHA as the version, cdxgen keeps
        # the sub-path (github/codeql-action/init). Match on owner/repo + (ref or ref comment).
        by_key: dict[tuple, str] = {}
        for a in ci["actions"]:
            if a.get("purl") and a.get("action", "").count("/") >= 1:
                owner, repo = a["action"].split("/")[:2]
                for ver in filter(None, (a.get("ref"), a.get("ref_comment"))):
                    by_key.setdefault((owner.lower(), repo.lower(), ver), a["purl"])
        tool_gh: dict[str, set] = {}
        tool_alias: dict[str, set] = {}
        for name, res in tool_results.items():
            for c in res.get("components", []):
                if c["ecosystem"] != "github":
                    continue
                segs = c["purl"][len("pkg:github/"):].rsplit("@", 1)
                parts = segs[0].split("/")
                key = (parts[0].lower(), parts[1].lower() if len(parts) > 1 else "", segs[1] if len(segs) > 1 else None)
                target = by_key.get(key, c["purl"])
                tool_gh.setdefault(target, set()).add(name)
                if target != c["purl"]:
                    tool_alias.setdefault(target, set()).add(c["purl"])
        for a in ci["actions"]:
            if a["kind"] in ("local",) or not a.get("purl"):
                continue
            purl = a["purl"]
            node = nodes.setdefault(purl, {
                "id": purl, "purl": purl, "name": a["action"], "version": a["ref"], "ecosystem": "github",
                "occurrences": [], "declared_in": [], "found_by": ["workflow-parser"]})
            node["found_by"] = sorted(set(node["found_by"]) | tool_gh.get(purl, set()))
            node.setdefault("ci", {"pin_type": a["pin_type"], "pin_source": a["pin_source"],
                                   "publisher": a["publisher"], "kind": a["kind"], "uses": [],
                                   "ref_comment": a.get("ref_comment"),
                                   "tool_purls": sorted(tool_alias.get(purl, set()))})
            node["ci"]["uses"].append(a["uses"])
            for u in a["used_in"]:
                occ = {"project": CI_ROOT, "manifest": u["workflow"], "job": u["job"], "lockfile": None,
                       "install_path": None, "resolved": f"https://github.com/{a['action'].split('/')[0]}/{a['action'].split('/')[1]}"
                       if a["action"].count("/") >= 1 else None, "integrity": a["ref"] if a["pin_type"] == "sha" else None}
                if occ not in node["occurrences"]:
                    node["occurrences"].append(occ)
                decl = {"manifest": u["workflow"], "section": f"jobs.{u['job']}", "range": a["ref"]}
                if decl not in node["declared_in"]:
                    node["declared_in"].append(decl)
            edges.append({"from": CI_ROOT, "to": purl, "type": "uses", "range": a["ref"],
                          "edge_source": "workflow-parser", "projects": [CI_ROOT]})
            ci_actions.append(purl)
        # GitHub Actions purls reported by SBOM tools but not by the workflow parser
        for purl, tools in tool_gh.items():
            if purl not in nodes:
                nodes[purl] = {"id": purl, "purl": purl, "name": purl_display_name(purl),
                               "version": purl.rsplit("@", 1)[-1], "ecosystem": "github", "occurrences": [],
                               "declared_in": [], "found_by": sorted(tools), "tool_only": True}
                edges.append({"from": CI_ROOT, "to": purl, "type": "uses", "range": None,
                              "edge_source": "+".join(sorted(tools)), "projects": [CI_ROOT]})

    # --- container root --------------------------------------------------------
    container_root = None
    image_purls: set[str] = set()
    if container and container.get("inspected"):
        container_root = f"container:{container['ref']}"
        roots[container_root] = {"id": container_root, "kind": "container", "name": container["ref"],
                                 "version": (container.get("digest") or "")[:19] or None,
                                 "digest": container.get("digest"), "os": container.get("os"),
                                 "ecosystem": "oci"}
        for p in container.get("packages", []):
            image_purls.add(p["purl"])
            if p["purl"] in nodes:
                continue
            nodes[p["purl"]] = {"id": p["purl"], "purl": p["purl"], "name": p["name"], "version": p["version"],
                                "ecosystem": p["ecosystem"], "occurrences": [{
                                    "project": container_root, "lockfile": None, "install_path": (p["locations"] or [None])[0],
                                    "resolved": None, "integrity": None}],
                                "declared_in": [], "found_by": sorted(p["found_by"]),
                                "container_only": True, "container_kind": p["kind"],
                                "tool_licenses": {"image": p["licenses"]}}
            edges.append({"from": container_root, "to": p["purl"], "type": "contains", "range": None,
                          "edge_source": "+".join(sorted(p["found_by"])), "projects": [container_root]})

    # One edge per (from, to): several `uses:` strings (github/codeql-action/init@v3,
    # .../analyze@v3) map to the same action purl.
    edges = list({(e["from"], e["to"]): e for e in reversed(edges)}.values())[::-1]

    # --- graph metrics ----------------------------------------------------------
    adj = ga.adjacency(edges)
    project_roots = sorted(r for r, v in roots.items() if v["kind"] == "project")
    other_roots = sorted(r for r, v in roots.items() if v["kind"] != "project")
    min_depth: dict[str, int] = {}
    bfs_cache = {}
    for r in project_roots + other_roots:
        dist, parent = ga.bfs(adj, r)
        bfs_cache[r] = (dist, parent)
        for n, d in dist.items():
            if n == r or n in roots:
                continue
            if roots[r]["kind"] == "project":
                if d < min_depth.get(n, 10**9):
                    min_depth[n] = d
    scope = ga.scopes([e for e in edges if e["type"] in ("prod", "dev", "optional", "peer")], project_roots)
    indeg: dict[str, set] = {}
    outdeg: dict[str, set] = {}
    for e in edges:
        indeg.setdefault(e["to"], set()).add(e["from"])
        outdeg.setdefault(e["from"], set()).add(e["to"])

    for nid, n in nodes.items():
        reach_from = [r for r in project_roots + other_roots if nid in bfs_cache[r][0]]
        if nid in min_depth:
            n["depth"] = min_depth[nid]
            n["relationship"] = "direct" if min_depth[nid] == 1 else "transitive"
            n["scope"] = scope.get(nid)
        else:
            other = next((r for r in other_roots if nid in bfs_cache[r][0]), None)
            n["depth"] = bfs_cache[other][0][nid] if other else None
            n["relationship"] = roots[other]["kind"] if other else None
            n["scope"] = None
        n["reachable_from"] = reach_from
        n["dependents_count"] = len(indeg.get(nid, ()))
        n["dependencies_count"] = len(outdeg.get(nid, ()))
        n["in_container"] = nid in image_purls if container_root else None
        resolved = [o["resolved"] for o in n.get("occurrences", []) if o.get("resolved")]
        if not resolved and n.get("tool_resolved"):
            resolved = [n["tool_resolved"]]
        n["origin"] = origin_of(n["ecosystem"], resolved)
        n["integrity"] = integrity_of(n.get("occurrences", []), n.get("tool_hash_algs"))
        lic = set()
        lic_sources = {}
        if n.get("license"):
            lic.add(str(n["license"]))
            lic_sources["lockfile"] = [str(n["license"])]
        for tool, ls in (n.get("tool_licenses") or {}).items():
            lic |= set(ls)
            if ls:
                lic_sources[tool] = ls
        n["licenses"] = sorted(lic)
        n["license_sources"] = lic_sources
        if container_root and nid in image_purls and container_root not in n["reachable_from"]:
            n["also_in"] = [container_root]

    # --- paths ------------------------------------------------------------------
    comp = ga.strongly_connected(sorted(set(adj) | {v for vs in adj.values() for v in vs}), adj)
    paths: dict[str, dict] = {}
    for r in project_roots + other_roots:
        if r not in comp:
            continue
        counts = ga.path_counts(adj, comp, r)
        dist, parent = bfs_cache[r]
        for nid in dist:
            if nid == r or nid not in nodes:
                continue
            paths.setdefault(nid, {})[r] = {
                "shortest": ga.path_to(parent, r, nid),
                "count": ga.fmt_count(counts.get(comp[nid], 0)),
            }

    return {"roots": roots, "nodes": nodes, "edges": edges, "paths": paths,
            "project_roots": project_roots, "other_roots": other_roots,
            "container_root": container_root, "ci_actions": ci_actions, "image_purls": image_purls}


def component_record(n: dict) -> dict:
    """The public components.json entry (Part 5 fields)."""
    occ = []
    for o in n.get("occurrences", []):
        occ.append({k: o.get(k) for k in ("project", "manifest", "lockfile", "install_path", "resolved",
                                          "integrity", "job", "dev", "optional", "bundled", "alias") if o.get(k) not in (None, False)})
    return {
        "purl": n["purl"], "name": n["name"], "version": n["version"], "ecosystem": n["ecosystem"],
        "relationship": n.get("relationship"), "depth": n.get("depth"), "scope": n.get("scope"),
        "dependents_count": n.get("dependents_count", 0), "dependencies_count": n.get("dependencies_count", 0),
        "declared_in": n.get("declared_in", []),
        "occurrences": occ,
        "origin": n.get("origin"),
        "integrity": n.get("integrity"),
        "licenses": n.get("licenses", []),
        "license_sources": n.get("license_sources", {}),
        "found_by": sorted(n.get("found_by", [])),
        "sources": {t: (n.get("tool_locations") or {}).get(t, []) for t in sorted(n.get("found_by", []))},
        "in_container": n.get("in_container"),
        "reachable_from": n.get("reachable_from", []),
        **({"ci": n["ci"]} if n.get("ci") else {}),
        **({"container_only": True, "container_kind": n.get("container_kind")} if n.get("container_only") else {}),
        **({"tool_only": True} if n.get("tool_only") else {}),
        **({"relationship_basis": n["relationship_basis"]} if n.get("relationship_basis") else {}),
    }


def graph_record(inv: dict) -> dict:
    nodes = inv["nodes"]
    edges = inv["edges"]
    depths = [n["depth"] for n in nodes.values() if n.get("relationship") in ("direct", "transitive")]
    by_type: dict[str, int] = {}
    for e in edges:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    top = sorted(nodes.values(), key=lambda n: (-n["dependents_count"], n["id"]))[:20]
    return {
        "roots": [{**r, "dependencies_count": sum(1 for e in edges if e["from"] == r["id"])}
                  for r in sorted(inv["roots"].values(), key=lambda r: (r["kind"] != "project", r["id"]))],
        "nodes": [{
            "id": n["id"], "name": n["name"], "version": n["version"], "ecosystem": n["ecosystem"],
            "relationship": n.get("relationship"), "depth": n.get("depth"), "scope": n.get("scope"),
            "dependents_count": n["dependents_count"], "dependencies_count": n["dependencies_count"],
            "found_by": sorted(n.get("found_by", [])), "in_container": n.get("in_container"),
            "origin_flags": (n.get("origin") or {}).get("flags", []),
            "registry_hosts": (n.get("origin") or {}).get("registry_hosts", []),
            "licenses": n.get("licenses", []),
        } for n in sorted(nodes.values(), key=lambda n: n["id"])],
        "edges": [{k: e.get(k) for k in ("from", "to", "type", "range", "edge_source")} for e in edges],
        "stats": {
            "nodes": len(nodes), "edges": len(edges), "roots": len(inv["roots"]),
            "project_roots": len(inv["project_roots"]),
            "max_depth": max(depths) if depths else 0,
            "edges_by_type": dict(sorted(by_type.items())),
            "top_dependents": [{"id": n["id"], "name": n["name"], "version": n["version"],
                                "dependents_count": n["dependents_count"]} for n in top],
        },
    }


