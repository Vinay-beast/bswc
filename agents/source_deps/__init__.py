"""source-deps agent: source dependencies of a repository.

Stages (each a plain function an orchestrator can call):
    fetch_repo / get_repo_info     clone or update workspace/<app_id>/
    discover_manifests / detect_projects
    resolvers.resolver_for(eco)    reproducible lockfiles, npm ls, go mod graph, pip report
    lockfiles.parse_lockfile       authoritative edges from npm/yarn/pnpm lockfiles
    run_source_deps                all of the above + Syft, cdxgen, Trivy
"""

from .ingest import FetchResult, fetch_repo, get_repo_info
from .lockfiles import parse_lockfile, resolve_npm
from .manifests import Project, detect_projects, discover_manifests
from .pipeline import run_source_deps, start_run

__all__ = ["FetchResult", "Project", "detect_projects", "discover_manifests", "fetch_repo",
           "get_repo_info", "parse_lockfile", "resolve_npm", "run_source_deps", "start_run"]
