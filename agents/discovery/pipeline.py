"""End-to-end discovery run: clone -> manifests -> lockfiles -> SBOM -> components.

Writes, per docs/output-contract.md:
    outputs/<app>/run.json
    outputs/<app>/discovery/{status.json, sbom.cdx.json, components.json, discovery_meta.json}
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from agents.common import DEFAULT_OUTPUTS, AgentRun, update_run_info, write_json
from agents.common.contract import now_iso

from .ingest import DEFAULT_WORKSPACE, fetch_repo, get_repo_info, repo_name_from_url
from .manifests import discover_manifests, ensure_npm_lockfiles
from .relationships import classify_components
from .sbom import generate_sbom, normalize_components
from .tools import get_tool_versions, require_tool

log = logging.getLogger(__name__)

AGENT = "discovery"
STAGE = "discover"
SBOM_FILE = "sbom.cdx.json"
COMPONENTS_FILE = "components.json"
META_FILE = "discovery_meta.json"


def run_discovery(
    repo_url: str,
    ref: str | None = None,
    *,
    refresh: bool = False,
    workspace: Path = DEFAULT_WORKSPACE,
    outputs: Path = DEFAULT_OUTPUTS,
) -> dict:
    """Run every discovery stage and write artifacts to outputs/<app>/discovery/.

    status.json is set to "running" first and to "done" or "failed" at the end.
    Returns the metadata dict (also written to discovery_meta.json).
    """
    app_name = repo_name_from_url(repo_url)
    update_run_info(app_name, outputs, repo_url=repo_url, ref=ref, started_at=now_iso())
    status = AgentRun(app_name, AGENT, STAGE, outputs).start()
    try:
        meta = _discover(repo_url, ref, refresh, workspace, status.dir)
    except Exception as exc:
        status.fail(f"{type(exc).__name__}: {exc}")
        raise

    update_run_info(app_name, outputs,
                    commit_sha=meta["repo"]["commit_sha"],
                    commit_date=meta["repo"]["commit_date"])
    status.add_artifact(SBOM_FILE, "sbom")
    status.add_artifact(COMPONENTS_FILE, "json")
    status.add_artifact(META_FILE, "json")
    status.done(meta["summary"])
    meta["outputs"]["status"] = str(status.path)
    return meta


def _discover(repo_url: str, ref: str | None, refresh: bool, workspace: Path, out_dir: Path) -> dict:
    for tool in ("git", "npm", "syft"):
        require_tool(tool)
    started = now_iso()
    sbom_path = out_dir / SBOM_FILE
    components_path = out_dir / COMPONENTS_FILE
    meta_path = out_dir / META_FILE

    repo_path = fetch_repo(repo_url, ref, refresh=refresh, workspace=workspace)
    repo_info = get_repo_info(repo_path, repo_url, ref)

    manifests = discover_manifests(repo_path)
    lockfiles = ensure_npm_lockfiles(repo_path, manifests)
    # Re-scan so generated lockfiles appear in the manifest list.
    manifests = discover_manifests(repo_path)
    generated = {l["lockfile"] for l in lockfiles if l["status"] == "generated"}
    for m in manifests:
        m["origin"] = "generated" if m["path"] in generated else "original"

    generate_sbom(repo_path, sbom_path)
    components = classify_components(repo_path, normalize_components(sbom_path))
    write_json(components_path, components)

    by_ecosystem = Counter(c["ecosystem"] or "unknown" for c in components)
    by_relationship = Counter(c["relationship"] or "unknown" for c in components)
    by_scope = Counter(c["scope"] or "unknown" for c in components)
    summary = {
        "components": len(components),
        "direct": by_relationship.get("direct", 0),
        "transitive": by_relationship.get("transitive", 0),
        "ecosystems": len(by_ecosystem),
        "manifests": sum(1 for m in manifests if m["kind"] == "manifest"),
        "lockfiles_generated": len(generated),
        "lockfiles_failed": sum(1 for l in lockfiles if l["status"] == "failed"),
    }

    meta = {
        "app_name": repo_info["name"],
        "repo": repo_info,
        "tool_versions": get_tool_versions(),
        "manifests": manifests,
        "npm_lockfiles": lockfiles,
        "generated_lockfiles": sorted(generated),
        "component_count": len(components),
        "components_by_ecosystem": dict(sorted(by_ecosystem.items())),
        "components_by_relationship": dict(sorted(by_relationship.items())),
        "components_by_scope": dict(sorted(by_scope.items())),
        "summary": summary,
        "outputs": {
            "sbom": str(sbom_path),
            "components": str(components_path),
            "metadata": str(meta_path),
        },
        "run": {"started_at": started, "finished_at": now_iso()},
    }
    write_json(meta_path, meta)
    return meta
