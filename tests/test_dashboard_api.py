"""Dashboard API: read-only access, staleness flag, path-traversal rejection."""

import json

import pytest
from fastapi.testclient import TestClient

import dashboard.app as dash


@pytest.fixture
def client(tmp_path, monkeypatch):
    out = tmp_path / "outputs"
    app_dir = out / "o__app"
    (app_dir / "inventory").mkdir(parents=True)
    (app_dir / "old_agent").mkdir()
    (app_dir / "run.json").write_text(json.dumps({"app_id": "o__app", "run_id": "R2"}))
    graph = {"roots": [{"id": "project:.", "kind": "project", "name": "app"}],
             "nodes": [{"id": "pkg:npm/a@1.0.0", "name": "a", "version": "1.0.0", "depth": 1},
                       {"id": "pkg:npm/b@1.0.0", "name": "b", "version": "1.0.0", "depth": 2}],
             "edges": [{"from": "project:.", "to": "pkg:npm/a@1.0.0", "type": "prod"},
                       {"from": "pkg:npm/a@1.0.0", "to": "pkg:npm/b@1.0.0", "type": "prod"}],
             "stats": {"nodes": 2}}
    (app_dir / "inventory" / "graph.json").write_text(json.dumps(graph))
    (app_dir / "inventory" / "paths.json").write_text(json.dumps({"paths": {"pkg:npm/b@1.0.0": {
        "project:.": {"shortest": ["project:.", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"], "count": 1}}}}))
    (app_dir / "inventory" / "status.json").write_text(json.dumps({
        "agent": "inventory", "stage": "discover", "run_id": "R2", "state": "done",
        "artifacts": [{"name": "graph.json", "path": "inventory/graph.json", "type": "graph"},
                      {"name": "paths.json", "path": "inventory/paths.json", "type": "graph"},
                      {"name": "evil.json", "path": "../../secret.json", "type": "json"}]}))
    (app_dir / "old_agent" / "status.json").write_text(json.dumps({
        "agent": "old", "stage": "detect", "run_id": "R1", "state": "done", "artifacts": []}))
    (tmp_path / "secret.json").write_text("{}")
    (app_dir / "inventory" / "unlisted.json").write_text("{}")
    monkeypatch.setattr(dash, "OUTPUTS", out.resolve())
    dash._cache.clear()
    return TestClient(dash.app)


def test_runs_and_staleness(client):
    assert client.get("/api/runs").json()[0]["agents"] == ["inventory", "old_agent"]
    agents = client.get("/api/runs/o__app").json()["agents"]
    assert agents["inventory"]["stale"] is False
    assert agents["old_agent"]["stale"] is True            # run_id differs from run.json


@pytest.mark.parametrize("url", [
    "/api/runs/..%2F..%2Fetc",
    "/api/runs/.git",
    "/api/runs/o__app/..%2F..%2F/status",
    "/api/runs/o__app/.hidden/status",
    "/api/runs/o__app/inventory/artifact/..%2Frun.json",
    "/api/runs/o__app/inventory/artifact/%2Fetc%2Fpasswd",
    "/api/runs/o__app/inventory/artifact/unlisted.json",   # exists, but not listed in status.json
    "/api/runs/o__app/inventory/artifact/evil.json",       # listed, but resolves outside the app folder
    "/api/runs/o__app/inventory/sbom-summary/..%2F..%2Fsecret.json",
    "/api/runs/nope/inventory/status",
])
def test_path_traversal_rejected(client, url):
    r = client.get(url)
    assert r.status_code in (400, 404), (url, r.status_code)
    assert r.content != b"{}"


def test_graph_endpoints(client):
    s = client.get("/api/runs/o__app/inventory/graph/summary").json()
    assert s["roots"][0]["id"] == "project:."
    n = client.get("/api/runs/o__app/inventory/graph/node", params={"id": "project:.", "depth": 2}).json()
    assert {x["id"] for x in n["nodes"]} == {"project:.", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"}
    p = client.get("/api/runs/o__app/inventory/graph/path", params={"to": "pkg:npm/b@1.0.0"}).json()
    assert p["paths"]["project:."]["count"] == 1 and len(p["edges"]) == 2
    assert client.get("/api/runs/o__app/inventory/graph/node", params={"id": "nope"}).status_code == 404
    assert client.get("/api/runs/o__app/inventory/graph/node", params={"id": "project:.", "depth": 9}).status_code == 422
    assert client.get("/api/runs/o__app/inventory/graph/search", params={"q": "b"}).json()[0]["name"] == "b"
