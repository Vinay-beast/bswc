"""Workflow parser, Dockerfile parser, URL parsing / app_id, purls."""

import shutil
from pathlib import Path

import pytest

from agents.artifact_inspector.dockerfile import image_pinning, parse_dockerfile, split_image
from agents.artifact_inspector.workflows import (build_ci_inventory, classify_ref_heuristic, parse_uses,
                                                 parse_workflow)
from agents.common.purl import build_purl, canonical_purl, parse_purl
from agents.common.repo import parse_repo_url

FIX = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- workflows
def test_parse_uses_pin_types():
    assert parse_uses("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")["pin_type"] == "sha"
    assert parse_uses("actions/checkout@v4")["pin_type"] == "unresolved"
    assert parse_uses("./.github/actions/x")["pin_type"] == "local"
    d = parse_uses("docker://alpine:3.19")
    assert d["pin_type"] == "docker" and d["image_pinning"] == "tag"
    assert parse_uses("actions/checkout@v4")["publisher"] == "github"
    assert parse_uses("github/codeql-action/init@v3")["publisher"] == "github"
    assert parse_uses("some-org/x@v1")["publisher"] == "third-party"
    assert parse_uses("org/repo/.github/workflows/build.yml@main")["kind"] == "reusable-workflow"


def test_ref_heuristic():
    assert classify_ref_heuristic("v1.2.3") == "tag"
    assert classify_ref_heuristic("main") == "branch"
    assert classify_ref_heuristic("abc1234") == "short-sha"


def test_workflow_pull_request_target_permissions_secrets():
    wf = parse_workflow((FIX / "workflows" / "pr.yml").read_text(), ".github/workflows/pr.yml")
    assert wf["triggers"] == ["pull_request_target"]            # `on:` read correctly despite YAML 1.1
    assert wf["permissions_set"] is False
    types = {p["type"] for p in wf["patterns"]}
    assert {"pull-request-target-checkout-head", "pipe-to-shell", "secrets-in-pr-workflow",
            "default-token-permissions"} <= types
    sha_use = next(u for u in wf["uses"] if u["action"] == "actions/checkout")
    assert sha_use["ref_comment"] == "v6.0.0"
    assert any(i["image"] == "node:20" and i["pinning"] == "tag" for i in wf["images"])


def test_ci_inventory_dedup_and_offline_classification(tmp_path):
    wdir = tmp_path / ".github" / "workflows"
    wdir.mkdir(parents=True)
    for f in ("pr.yml", "push.yml"):
        shutil.copy(FIX / "workflows" / f, wdir / f)
    (tmp_path / "Jenkinsfile").write_text("pipeline {}")
    inv = build_ci_inventory(tmp_path, online=False)
    s = inv["summary"]
    assert s["workflows"] == 2
    checkout = [a for a in inv["actions"] if a["action"] == "actions/checkout"]
    assert len(checkout) == 1 and len(checkout[0]["used_in"]) == 2      # deduplicated across files
    pins = {a["uses"]: a["pin_type"] for a in inv["actions"]}
    assert pins["some-org/some-action@v1.2.3"] == "tag"
    assert pins["other/thing@main"] == "branch"
    assert pins["./.github/actions/local"] == "local"
    assert inv["other_ci"][0]["system"] == "jenkins"
    push = next(w for w in inv["workflows"] if w["path"].endswith("push.yml"))
    assert push["permissions_set"] is True
    assert any(i["pinning"] == "digest" for i in inv["images"])


# --------------------------------------------------------------- Dockerfile
def test_dockerfile_parser():
    d = parse_dockerfile((FIX / "docker" / "Dockerfile").read_text(), "Dockerfile")
    s0, s1 = d["stages"]
    assert s0["image"] == "node:20" and s0["name"] == "build" and s0["pinning"] == "tag"   # ARG substituted
    assert s1["pinning"] == "digest" and s1["registry"] == "gcr.io"
    assert d["final_user"] is None
    types = [f["type"] for f in d["findings"]]
    assert "pipe-to-shell" in types                    # across a line continuation
    assert "add-from-url" in types
    assert "final-stage-runs-as-root" in types
    assert "npm-install-runs-scripts" in types
    assert [f for f in d["findings"] if f["type"] == "base-image-not-digest-pinned"][0]["text"] == "node:20"


def test_image_reference_helpers():
    assert split_image("nginx")["repository"] == "library/nginx"
    assert split_image("ghcr.io/o/r:1.0@sha256:" + "a" * 64)["digest"].startswith("sha256:")
    assert image_pinning("nginx") == "latest-implicit"
    assert image_pinning("nginx:latest") == "latest"
    assert image_pinning("redis:7.4") == "tag"
    assert image_pinning("${IMG}") == "variable"


# -------------------------------------------------------------- URLs / ids
@pytest.mark.parametrize("url,owner,repo", [
    ("https://github.com/juice-shop/juice-shop", "juice-shop", "juice-shop"),
    ("https://github.com/juice-shop/juice-shop.git", "juice-shop", "juice-shop"),
    ("https://github.com/juice-shop/juice-shop/", "juice-shop", "juice-shop"),
    ("git@github.com:juice-shop/juice-shop.git", "juice-shop", "juice-shop"),
    ("ssh://git@gitlab.com:2222/group/sub/proj.git", "group/sub", "proj"),
    ("git://example.org/o/r", "o", "r"),
])
def test_parse_repo_url(url, owner, repo):
    ref = parse_repo_url(url)
    assert (ref.owner, ref.repo) == (owner, repo)


def test_app_id_avoids_collisions():
    assert parse_repo_url("https://github.com/juice-shop/juice-shop").app_id == "juice-shop__juice-shop"
    assert parse_repo_url("https://github.com/orgA/app").app_id != parse_repo_url("https://github.com/orgB/app").app_id
    assert parse_repo_url("ssh://git@gitlab.com/group/sub/proj.git").app_id == "group-sub__proj"


@pytest.mark.parametrize("bad", ["", "not-a-url", "/tmp/repo", "file:///tmp/repo", "https://github.com/only-owner",
                                 "https://github.com/../etc", "ftp://example.com/o/r", "https://github.com/o/r;rm"])
def test_parse_repo_url_rejects(bad):
    with pytest.raises(ValueError):
        parse_repo_url(bad)


def test_purl_canonicalisation():
    assert build_purl("npm", "@angular/core", "22.0.1") == "pkg:npm/%40angular/core@22.0.1"
    assert canonical_purl("pkg:npm/@angular/core@22.0.1") == "pkg:npm/%40angular/core@22.0.1"
    assert canonical_purl("pkg:npm/%40angular/core@22.0.1?package-id=abc") == "pkg:npm/%40angular/core@22.0.1"
    assert canonical_purl("pkg:pypi/Django_Rest@1.0") == "pkg:pypi/django-rest@1.0"
    assert parse_purl("pkg:golang/github.com/a/b@v1.2.3")["namespace"] == "github.com/a"
    assert canonical_purl("not a purl") is None
