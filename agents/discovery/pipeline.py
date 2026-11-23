"""End-to-end discovery run: clone -> manifests -> lockfiles -> SBOM -> components."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .ingest import DEFAULT_WORKSPACE, PROJECT_ROOT, fetch_repo, get_repo_info, repo_name_from_url
from .manifests import discover_manifests, ensure_npm_lockfiles
from .sbom import generate_sbom, normalize_components
from .tools import get_tool_versions, require_tool

log = logging.getLogger(__name__)

DEFAULT_OUTPUTS = PROJECT_ROOT / "outputs"


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def run_discovery(
    repo_url: str,
    ref: str | None = None,
    *,
    refresh: bool = False,
    workspace: Path = DEFAULT_WORKSPACE,
    outputs: Path = DEFAULT_OUTPUTS,
) -> dict:
    """Run every discovery stage and write artifacts to outputs/<app-name>/.

    Returns the metadata dict (also written to discovery_meta.json).
    """
    for tool in ("git", "npm", "syft"):
        require_tool(tool)
    started = datetime.now(timezone.utc)

    app_name = repo_name_from_url(repo_url)
    out_dir = Path(outputs) / app_name
    sbom_path = out_dir / "sbom.cdx.json"
    components_path = out_dir / "components.json"
    meta_path = out_dir / "discovery_meta.json"

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
    components = normalize_components(sbom_path)
    _write_json(components_path, components)

    by_ecosystem: dict[str, int] = {}
    for c in components:
        key = c["ecosystem"] or "unknown"
        by_ecosystem[key] = by_ecosystem.get(key, 0) + 1

    meta = {
        "app_name": app_name,
        "repo": repo_info,
        "tool_versions": get_tool_versions(),
        "manifests": manifests,
        "npm_lockfiles": lockfiles,
        "generated_lockfiles": sorted(generated),
        "component_count": len(components),
        "components_by_ecosystem": dict(sorted(by_ecosystem.items())),
        "outputs": {
            "sbom": str(sbom_path),
            "components": str(components_path),
            "metadata": str(meta_path),
        },
        "run": {
            "started_at": started.isoformat(timespec="seconds"),
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }
    _write_json(meta_path, meta)
    return meta
