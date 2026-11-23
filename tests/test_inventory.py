"""Graph algorithms, path computation and the CycloneDX / SPDX builders."""

import json
from pathlib import Path

import pytest

from agents.common.contract import write_json
from agents.inventory import graphalgo as ga
from agents.inventory.build import build_inventory, component_record, graph_record, origin_of
from agents.inventory.sboms import (build_cyclonedx, build_spdx, sri_to_hashes, validate_cyclonedx,
                                    validate_spdx)
from agents.source_deps.graph_model import GraphBuilder
from agents.source_deps.lockfiles import parse_npm_lock

FIX = Path(__file__).parent / "fixtures"


def E(a, b, t="prod"):
    return {"from": a, "to": b, "type": t, "range": None, "edge_source": "test"}


def test_paths_and_counts_diamond_with_cycle():
    edges = [E("r", "a"), E("r", "b"), E("a", "c"), E("b", "c"), E("c", "d"), E("d", "c")]
    adj = ga.adjacency(edges)
    dist, parent = ga.bfs(adj, "r")
    assert dist == {"r": 0, "a": 1, "b": 1, "c": 2, "d": 3}
    assert ga.path_to(parent, "r", "d") == ["r", "a", "c", "d"]
    comp = ga.strongly_connected(sorted({"r", "a", "b", "c", "d"}), adj)
    assert comp["c"] == comp["d"] and comp["a"] != comp["b"]
    counts = ga.path_counts(adj, comp, "r")
    assert counts[comp["c"]] == 2                       # r-a-c and r-b-c; the c<->d cycle is condensed


def test_path_count_cap():
    # 12 layers of 2 parallel nodes -> 2**12 paths
    edges, prev = [], ["r"]
    for i in range(12):
        layer = [f"n{i}a", f"n{i}b"]
        edges += [E(p, n) for p in prev for n in layer]
        prev = layer
    edges += [E(p, "end") for p in prev]
    adj = ga.adjacency(edges)
    comp = ga.strongly_connected(sorted({e["from"] for e in edges} | {"end"}), adj)
    count = ga.path_counts(adj, comp, "r")[comp["end"]]
    assert ga.fmt_count(count) == "1000+"


def test_origin_flags():
    o = origin_of("npm", ["https://npm.example.com/c/-/c-1.0.0.tgz", "git+ssh://git@github.com/e/e.git#abc"])
    assert "non-default-registry" in o["flags"] and "git" in o["flags"]
    assert origin_of("npm", ["https://registry.npmjs.org/a/-/a-1.0.0.tgz"])["flags"] == []


def test_sri_to_hex():
    import base64, hashlib
    sri = "sha512-" + base64.b64encode(hashlib.sha512(b"a").digest()).decode()
    assert sri_to_hashes(sri) == [("sha512", hashlib.sha512(b"a").hexdigest())]


@pytest.fixture(scope="module")
def small_inventory():
    b = GraphBuilder()
    b.add_root("project:.", name="app", version="1.0.0", ecosystem="npm", path=".", kind="project")
    pkg = json.loads((FIX / "npm-v3" / "package.json").read_text())
    parse_npm_lock(FIX / "npm-v3" / "package-lock.json", "project:.", "package-lock.json", b, pkg, "package.json")
    g = b.to_dict()
    ci = {"workflows": [{}], "actions": [{
        "uses": "actions/checkout@v4", "action": "actions/checkout", "ref": "v4", "kind": "action",
        "pin_type": "tag", "pin_source": "test", "publisher": "github", "purl": "pkg:github/actions/checkout@v4",
        "used_in": [{"workflow": ".github/workflows/ci.yml", "job": "build"}]}]}
    container = {"inspected": True, "ref": "example/app:1.0", "digest": "sha256:" + "c" * 64, "os": {"name": "debian"},
                 "packages": [{"purl": "pkg:deb/debian/libc6@2.41", "name": "libc6", "version": "2.41",
                               "ecosystem": "deb", "kind": "os", "licenses": ["LGPL-2.1"], "locations": [],
                               "found_by": ["syft-image"]},
                              {"purl": "pkg:npm/a@1.0.0", "name": "a", "version": "1.0.0", "ecosystem": "npm",
                               "kind": "application", "licenses": [], "locations": [], "found_by": ["syft-image"]}]}
    inv = build_inventory(g, {}, {}, ci, container)
    run = {"app_id": "o__app", "run_id": "20260101T000000Z-abc1234", "repo_url": "https://github.com/o/app",
           "commit_sha": "abc1234" + "0" * 33, "display_name": "app"}
    return inv, run, container


def test_inventory_relationships_and_container(small_inventory):
    inv, _, _ = small_inventory
    n = inv["nodes"]
    assert n["pkg:npm/a@1.0.0"]["relationship"] == "direct" and n["pkg:npm/a@1.0.0"]["depth"] == 1
    assert n["pkg:npm/e@1.0.0"]["relationship"] == "transitive"
    assert n["pkg:npm/a@1.0.0"]["in_container"] is True
    assert n["pkg:npm/c@1.0.0"]["in_container"] is False
    assert n["pkg:deb/debian/libc6@2.41"]["relationship"] == "container"
    assert n["pkg:github/actions/checkout@v4"]["relationship"] == "ci"
    assert set(inv["roots"]) == {"project:.", "ci:github-actions", "container:example/app:1.0"}
    p = inv["paths"]["pkg:npm/e@1.0.0"]["project:."]
    assert p["shortest"][0] == "project:." and p["shortest"][-1] == "pkg:npm/e@1.0.0"
    rec = component_record(n["pkg:npm/c@1.0.0"])
    assert "non-default-registry" in rec["origin"]["flags"]
    stats = graph_record(inv)["stats"]
    assert stats["roots"] == 3 and stats["max_depth"] >= 2
    pairs = [(e["from"], e["to"]) for e in inv["edges"]]
    assert len(pairs) == len(set(pairs))                      # no duplicate edges


def test_cyclonedx_dependencies_section(small_inventory):
    inv, run, container = small_inventory
    bom = build_cyclonedx(inv, run, {"syft": "1.57.2", "trivy": "0.76.2", "cdxgen": "12.9.3"}, container)
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert deps["project:."] == sorted(["pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0", "pkg:npm/p@1.0.0"])
    assert "pkg:npm/b@2.0.0" in deps["pkg:npm/a@1.0.0"]
    assert deps["container:example/app:1.0"] == ["pkg:deb/debian/libc6@2.41"]
    assert "pkg:deb/debian/libc6@2.41" in deps                 # nested component has an entry too
    container_comp = next(c for c in bom["components"] if c["type"] == "container")
    assert container_comp["components"][0]["bom-ref"] == "pkg:deb/debian/libc6@2.41"
    a = next(c for c in bom["components"] if c["bom-ref"] == "pkg:npm/a@1.0.0")
    assert a["hashes"][0]["alg"] == "SHA-512"
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["guardian:run_id"] == run["run_id"]
    result = validate_cyclonedx(bom)
    assert result["valid"] is True, result["errors"]


def test_spdx_export(small_inventory, tmp_path):
    inv, run, container = small_inventory
    doc = build_spdx(inv, run, {"syft": "1.57.2"}, container)
    rel_types = {r["relationshipType"] for r in doc["relationships"]}
    assert {"DESCRIBES", "DEPENDS_ON", "CONTAINS"} <= rel_types
    result = validate_spdx(doc)
    assert result["valid"] is True, result["errors"]
    write_json(tmp_path / "x.json", doc)
    assert oct((tmp_path / "x.json").stat().st_mode & 0o777) == "0o644"   # write_json mode
