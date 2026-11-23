"""Discovery Agent: clone a target repository and generate its SBOM.

Each stage is a plain function so an orchestrator can call them as tools:

    fetch_repo          -> clone / reuse workspace/<repo-name>
    get_repo_info       -> repo URL, commit SHA, timestamp
    discover_manifests  -> package manifests and lockfiles
    ensure_npm_lockfiles-> generate missing package-lock.json (scripts disabled)
    generate_sbom       -> Syft CycloneDX JSON
    normalize_components-> flat component list
    classify_components -> direct/transitive and prod/dev for npm components
    run_discovery       -> all of the above, writes outputs/<app-name>/discovery/
"""

from .ingest import fetch_repo, get_repo_info, repo_name_from_url
from .manifests import discover_manifests, ensure_npm_lockfiles
from .pipeline import run_discovery
from .relationships import classify_components
from .sbom import generate_sbom, normalize_components
from .tools import ToolError, get_tool_versions, require_tool

__all__ = [
    "ToolError",
    "classify_components",
    "discover_manifests",
    "ensure_npm_lockfiles",
    "fetch_repo",
    "generate_sbom",
    "get_repo_info",
    "get_tool_versions",
    "normalize_components",
    "repo_name_from_url",
    "require_tool",
    "run_discovery",
]
