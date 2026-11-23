"""npm/yarn lockfile edge resolution, scopes, dedup across projects."""

from pathlib import Path

import pytest

from agents.common.purl import npm_purl
from agents.inventory import graphalgo as ga
from agents.source_deps.graph_model import GraphBuilder
from agents.source_deps.lockfiles import parse_npm_lock, parse_yarn_lock, resolve_npm

FIX = Path(__file__).parent / "fixtures"
P = npm_purl


def _parse(builder, folder, project_id, lock_rel):
    import json
    pkg = json.loads((FIX / folder / "package.json").read_text())
    return parse_npm_lock(FIX / folder / Path(lock_rel).name, project_id, lock_rel, builder, pkg,
                          lock_rel.replace(Path(lock_rel).name, "package.json"))


@pytest.fixture
def v3():
    b = GraphBuilder()
    b.add_root("project:.", name="app")
    stats = _parse(b, "npm-v3", "project:.", "package-lock.json")
    return b, stats


def edge(b, src, dst):
    return b.edges.get((src, dst))


def test_resolve_npm_walks_up_node_modules():
    packages = {"node_modules/a": {}, "node_modules/a/node_modules/b": {}, "node_modules/b": {}, "node_modules/c": {}}
    assert resolve_npm(packages, "node_modules/a", "b") == "node_modules/a/node_modules/b"   # nested wins
    assert resolve_npm(packages, "node_modules/c", "b") == "node_modules/b"                  # hoisted
    assert resolve_npm(packages, "node_modules/a/node_modules/b", "c") == "node_modules/c"   # walks up twice
    assert resolve_npm(packages, "", "missing") is None


def test_v3_nested_and_hoisted_edges(v3):
    b, stats = v3
    assert stats["format"] == "npm-lock-v3"
    assert edge(b, P("a", "1.0.0"), P("b", "2.0.0"))["type"] == "prod"        # nested copy under a
    assert edge(b, P("d", "1.0.0"), P("b", "1.0.0"))["type"] == "prod"        # hoisted copy
    assert edge(b, P("a", "1.0.0"), P("b", "1.0.0")) is None
    assert edge(b, "project:.", P("d", "1.0.0"))["type"] == "dev"
    assert edge(b, "project:.", P("a", "1.0.0"))["range"] == "^1.0.0"
    assert edge(b, P("p", "1.0.0"), P("a", "1.0.0"))["type"] == "peer"


def test_v3_unresolved_optional_and_peer(v3):
    b, _ = v3
    reasons = {(u["name"], u["type"]): u["reason"] for u in b.unresolved}
    assert reasons[("o", "optional")] == "optional dependency not installed"
    assert reasons[("q", "peer")] == "optional peer dependency not installed"


def test_v3_occurrence_metadata_and_declared_in(v3):
    b, stats = v3
    a = b.nodes[P("a", "1.0.0")]
    assert a["occurrences"][0]["install_path"] == "node_modules/a"
    assert a["occurrences"][0]["integrity"].startswith("sha512-")
    assert {"manifest": "package.json", "section": "dependencies", "range": "^1.0.0"} in a["declared_in"]
    assert b.nodes[P("@scope/s", "3.0.0")]["occurrences"][0]["bundled"] is True
    assert P("@scope/s", "3.0.0") == "pkg:npm/%40scope/s@3.0.0"
    assert stats["entries"] == 8                        # a, a/b, b, c, d, e, p, @scope/s


def test_scope_dev_only_when_reachable_only_through_dev(v3):
    b, _ = v3
    scopes = ga.scopes(list(b.edges.values()), ["project:."])
    assert scopes[P("a", "1.0.0")] == "prod"
    assert scopes[P("e", "1.0.0")] == "prod"          # via c (prod) and d (dev) -> prod wins
    assert scopes[P("b", "1.0.0")] == "dev"           # only via d
    assert scopes[P("d", "1.0.0")] == "dev"
    assert scopes[P("b", "2.0.0")] == "prod"


def test_v1_lockfile_nested_resolution():
    b = GraphBuilder()
    stats = _parse(b, "npm-v1", "project:.", "package-lock.json")
    assert stats["format"] == "npm-lock-v1"
    assert edge(b, P("a", "1.0.0"), P("b", "2.0.0")) is not None      # nested copy wins over hoisted b@1
    assert edge(b, "project:.", P("b", "1.0.0"))["type"] == "dev"
    assert b.nodes[P("b", "1.0.0")]["occurrences"][0]["dev"] is True


def test_same_purl_in_two_projects_is_one_node():
    b = GraphBuilder()
    _parse(b, "npm-v3", "project:.", "package-lock.json")
    _parse(b, "npm-v3-second", "project:frontend", "frontend/package-lock.json")
    e = b.nodes[P("e", "1.0.0")]
    assert sorted(o["project"] for o in e["occurrences"]) == ["project:.", "project:frontend"]
    assert len([n for n in b.nodes if n == P("e", "1.0.0")]) == 1
    assert edge(b, "project:frontend", P("e", "1.0.0"))["type"] == "prod"


def test_yarn_v1_lockfile():
    import json
    b = GraphBuilder()
    pkg = json.loads((FIX / "yarn-v1" / "package.json").read_text())
    stats = parse_yarn_lock(FIX / "yarn-v1" / "yarn.lock", "project:.", "yarn.lock", b, pkg, "package.json")
    assert stats["format"] == "yarn-v1"
    assert edge(b, "project:.", P("@scope/x", "1.2.0"))["type"] == "prod"
    assert edge(b, P("@scope/x", "1.2.0"), P("y", "2.1.3")) is not None
    assert stats["entries"] == 2                        # y@^2.0.0 and y@^2.1.0 are one entry
