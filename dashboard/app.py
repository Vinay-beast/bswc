"""Read-only local dashboard for Guardian agent outputs.

Run:  uvicorn dashboard.app:app --port 8000

Serves files from outputs/ only:
  * app and agent names are validated against a strict pattern,
  * agents are discovered by scanning outputs/<app>/*/status.json (nothing hard-coded),
  * an artifact is served only if it is listed in that agent's status.json and resolves
    inside outputs/<app>/,
  * graph queries read the agent's graph.json / paths.json / components.json artifacts and
    return small neighbourhoods, so the browser never loads a large graph at once.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = Path(os.environ.get("GUARDIAN_OUTPUTS", PROJECT_ROOT / "outputs")).resolve()
STATIC = Path(__file__).resolve().parent / "static"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_NEIGHBOURHOOD = 400

app = FastAPI(title="Software Supply Chain Guardian", docs_url="/api/docs", redoc_url=None)


# ------------------------------------------------------------------ helpers
def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _safe_dir(*parts: str) -> Path:
    for part in parts:
        if not _SAFE_NAME.match(part):
            raise HTTPException(status_code=400, detail=f"Invalid name: {part!r}")
    path = OUTPUTS.joinpath(*parts).resolve()
    if not path.is_relative_to(OUTPUTS) or not path.is_dir():
        raise HTTPException(status_code=404, detail="Not found")
    return path


def _agent_dirs(app_dir: Path) -> list[Path]:
    return sorted(d for d in app_dir.iterdir()
                  if d.is_dir() and _SAFE_NAME.match(d.name) and (d / "status.json").is_file())


def _run_info(app_dir: Path) -> dict:
    run = _read_json(app_dir / "run.json") or {}
    run.setdefault("app_id", app_dir.name)
    return run


def _with_staleness(status: dict, run: dict) -> dict:
    status = dict(status)
    status["stale"] = bool(run.get("run_id")) and status.get("run_id") != run.get("run_id")
    return status


def _artifact_path(app_name: str, agent: str, name: str) -> Path:
    app_dir = _safe_dir(app_name)
    status = _read_json(_safe_dir(app_name, agent) / "status.json") or {}
    entry = next((a for a in status.get("artifacts") or [] if a.get("name") == name), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Artifact not listed in status.json")
    path = (app_dir / str(entry.get("path", ""))).resolve()
    if not path.is_relative_to(app_dir) or not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact file not found")
    return path


# ------------------------------------------------------------------- runs
@app.get("/api/runs")
def list_runs() -> list[dict]:
    if not OUTPUTS.is_dir():
        return []
    runs = []
    for d in sorted(OUTPUTS.iterdir()):
        if d.is_dir() and _SAFE_NAME.match(d.name) and (d / "run.json").is_file():
            run = _run_info(d)
            run["agents"] = [a.name for a in _agent_dirs(d)]
            runs.append(run)
    runs.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
    return runs


@app.get("/api/runs/{app_name}")
def get_run(app_name: str) -> dict:
    app_dir = _safe_dir(app_name)
    run = _run_info(app_dir)
    agents = {}
    for d in _agent_dirs(app_dir):
        status = _read_json(d / "status.json")
        if status is not None:
            agents[d.name] = _with_staleness(status, run)
    return {"run": run, "agents": agents}


@app.get("/api/runs/{app_name}/{agent}/status")
def get_status(app_name: str, agent: str) -> dict:
    app_dir = _safe_dir(app_name)
    status = _read_json(_safe_dir(app_name, agent) / "status.json")
    if status is None:
        raise HTTPException(status_code=404, detail="status.json not found")
    return _with_staleness(status, _run_info(app_dir))


@app.get("/api/runs/{app_name}/{agent}/artifact/{name}")
def get_artifact(app_name: str, agent: str, name: str,
                 download: bool = Query(False, description="Send as attachment")):
    path = _artifact_path(app_name, agent, name)
    media = "application/json" if path.suffix == ".json" else "text/plain" if path.suffix == ".txt" else None
    return FileResponse(path, media_type=media, filename=path.name,
                        content_disposition_type="attachment" if download else "inline")


# ------------------------------------------------------- cached artifacts
_cache: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()


def _cached(path: Path, build):
    key = f"{path}|{getattr(build, '__qualname__', id(build))}"
    mtime = path.stat().st_mtime
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
    value = build(path)
    with _lock:
        _cache[key] = (mtime, value)
    return value


def _load_json_file(path: Path):
    return json.loads(path.read_text())


def _components_by_purl(path: Path) -> dict:
    return {c["purl"]: c for c in json.loads(path.read_text())}


def _graph_index(path: Path) -> dict:
    g = json.loads(path.read_text())
    nodes = {n["id"]: n for n in g["nodes"]}
    roots = {r["id"]: r for r in g["roots"]}
    out, inc = {}, {}
    for e in g["edges"]:
        out.setdefault(e["from"], []).append(e)
        inc.setdefault(e["to"], []).append(e)
    for lst in out.values():
        lst.sort(key=lambda e: (nodes.get(e["to"], {}).get("name") or e["to"]))
    return {"nodes": nodes, "roots": roots, "out": out, "in": inc, "stats": g.get("stats", {})}


def _graph(app_name: str, agent: str) -> dict:
    return _cached(_artifact_path(app_name, agent, "graph.json"), _graph_index)


def _node_view(idx: dict, nid: str) -> dict:
    if nid in idx["roots"]:
        r = idx["roots"][nid]
        return {"id": nid, "name": r.get("name") or nid, "version": r.get("version"), "kind": r.get("kind"),
                "relationship": "root", "dependencies_count": len(idx["out"].get(nid, [])), "dependents_count": 0}
    n = idx["nodes"].get(nid)
    if n is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    return {**n, "kind": "component"}


@app.get("/api/runs/{app_name}/{agent}/graph/summary")
def graph_summary(app_name: str, agent: str) -> dict:
    idx = _graph(app_name, agent)
    return {"roots": [_node_view(idx, r) for r in idx["roots"]], "stats": idx["stats"]}


@app.get("/api/runs/{app_name}/{agent}/graph/node")
def graph_node(app_name: str, agent: str, id: str = Query(..., max_length=2048),
               depth: int = Query(1, ge=0, le=3), limit: int = Query(MAX_NEIGHBOURHOOD, ge=1, le=2000)) -> dict:
    """The node, its parents (one level) and its children up to `depth` levels."""
    idx = _graph(app_name, agent)
    center = _node_view(idx, id)
    seen = {id}
    edges = []
    q = deque([(id, 0)])
    truncated = False
    while q:
        u, d = q.popleft()
        if d >= depth:
            continue
        for e in idx["out"].get(u, []):
            if e["to"] not in seen:
                if len(seen) >= limit:
                    truncated = True
                    break
                seen.add(e["to"])
                q.append((e["to"], d + 1))
            edges.append(e)
    parents = [e for e in idx["in"].get(id, [])][:50]
    for e in parents:
        seen.add(e["from"])
    edges += parents
    edges = [e for e in edges if e["from"] in seen and e["to"] in seen]
    return {"center": center, "nodes": [_node_view(idx, n) for n in sorted(seen)], "edges": edges,
            "parents_total": len(idx["in"].get(id, [])), "truncated": truncated}


@app.get("/api/runs/{app_name}/{agent}/graph/node/{node_id:path}")
def graph_node_path(app_name: str, agent: str, node_id: str, depth: int = Query(1, ge=0, le=3)) -> dict:
    return graph_node(app_name, agent, id=node_id, depth=depth, limit=MAX_NEIGHBOURHOOD)


@app.get("/api/runs/{app_name}/{agent}/graph/children")
def graph_children(app_name: str, agent: str, id: str = Query(..., max_length=2048)) -> dict:
    idx = _graph(app_name, agent)
    _node_view(idx, id)
    return {"id": id, "children": [{**_node_view(idx, e["to"]), "edge_type": e["type"], "range": e.get("range")}
                                   for e in idx["out"].get(id, [])]}


@app.get("/api/runs/{app_name}/{agent}/graph/search")
def graph_search(app_name: str, agent: str, q: str = Query(..., min_length=1, max_length=200),
                 limit: int = Query(30, ge=1, le=100)) -> list[dict]:
    idx = _graph(app_name, agent)
    ql = q.lower()
    hits = [n for n in idx["nodes"].values() if ql in (n.get("name") or "").lower() or ql in n["id"].lower()]
    hits.sort(key=lambda n: ((n.get("name") or "").lower() != ql, not (n.get("name") or "").lower().startswith(ql),
                             n.get("depth") or 99, n["id"]))
    return hits[:limit]


@app.get("/api/runs/{app_name}/{agent}/graph/path")
def graph_path(app_name: str, agent: str, to: str = Query(..., max_length=2048)) -> dict:
    """Shortest path from every root that reaches `to`, plus distinct path counts (paths.json)."""
    idx = _graph(app_name, agent)
    _node_view(idx, to)
    paths = _cached(_artifact_path(app_name, agent, "paths.json"), _load_json_file)
    entry = (paths.get("paths") or {}).get(to, {})
    ids = {i for v in entry.values() for i in v["shortest"]}
    edges = []
    for v in entry.values():
        s = v["shortest"]
        for a, b in zip(s, s[1:]):
            e = next((x for x in idx["out"].get(a, []) if x["to"] == b), None)
            if e and e not in edges:
                edges.append(e)
    return {"to": to, "paths": entry, "nodes": [_node_view(idx, i) for i in sorted(ids)], "edges": edges}


@app.get("/api/runs/{app_name}/{agent}/component")
def component(app_name: str, agent: str, id: str = Query(..., max_length=2048)) -> dict:
    comps = _cached(_artifact_path(app_name, agent, "components.json"), _components_by_purl)
    if id not in comps:
        raise HTTPException(status_code=404, detail="Unknown component")
    return comps[id]


def _compact_components(path: Path) -> list[dict]:
    rows = []
    for c in json.loads(path.read_text()):
        origin = c.get("origin") or {}
        rows.append({
            "purl": c["purl"], "name": c["name"], "version": c.get("version"), "ecosystem": c.get("ecosystem"),
            "relationship": c.get("relationship"), "depth": c.get("depth"), "scope": c.get("scope"),
            "dependents": c.get("dependents_count", 0), "dependencies": c.get("dependencies_count", 0),
            "found_by": c.get("found_by", []), "registry": (origin.get("registry_hosts") or [None])[0],
            "flags": origin.get("flags", []), "integrity": (c.get("integrity") or {}).get("present", False),
            "integrity_algs": (c.get("integrity") or {}).get("algorithms", []),
            "license": ", ".join(c.get("licenses") or []), "in_container": c.get("in_container"),
        })
    return rows


@app.get("/api/runs/{app_name}/{agent}/components-table")
def components_table(app_name: str, agent: str) -> list[dict]:
    """Compact rows of components.json for the dashboard table (full records via /component)."""
    return _cached(_artifact_path(app_name, agent, "components.json"), _compact_components)


def _sbom_summary(path: Path) -> dict:
    d = json.loads(path.read_text())
    if d.get("bomFormat") == "CycloneDX":
        comps, stack = [], list(d.get("components") or [])
        while stack:
            c = stack.pop()
            comps.append(c)
            stack += c.get("components") or []
        by_type, by_eco = {}, {}
        for c in comps:
            by_type[c.get("type")] = by_type.get(c.get("type"), 0) + 1
            eco = (c.get("purl") or "pkg:none/").split(":", 1)[1].split("/", 1)[0]
            by_eco[eco] = by_eco.get(eco, 0) + 1
        md = d.get("metadata") or {}
        tools = md.get("tools") or {}
        tools = tools.get("components", []) if isinstance(tools, dict) else tools
        return {"format": "CycloneDX", "spec_version": d.get("specVersion"), "serial_number": d.get("serialNumber"),
                "timestamp": md.get("timestamp"), "tools": [{"name": t.get("name"), "version": t.get("version")} for t in tools],
                "component": (md.get("component") or {}).get("name"), "properties": md.get("properties", []),
                "components": len(comps), "by_type": by_type, "by_ecosystem": by_eco,
                "dependencies": len(d.get("dependencies") or []),
                "dependency_edges": sum(len(x.get("dependsOn") or []) for x in d.get("dependencies") or [])}
    if d.get("spdxVersion"):
        rels = {}
        for r in d.get("relationships") or []:
            rels[r.get("relationshipType")] = rels.get(r.get("relationshipType"), 0) + 1
        ci = d.get("creationInfo") or {}
        return {"format": "SPDX", "spec_version": d.get("spdxVersion"), "serial_number": d.get("documentNamespace"),
                "timestamp": ci.get("created"), "tools": [{"name": c, "version": None} for c in ci.get("creators", [])],
                "components": len(d.get("packages") or []), "relationships": rels}
    raise HTTPException(status_code=415, detail="Not a CycloneDX or SPDX JSON document")


@app.get("/api/runs/{app_name}/{agent}/sbom-summary/{name}")
def sbom_summary(app_name: str, agent: str, name: str) -> dict:
    return _cached(_artifact_path(app_name, agent, name), _sbom_summary)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
