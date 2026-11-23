"""Repository ingestion: shallow-clone a target repo into workspace/."""

from __future__ import annotations

import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .tools import ToolError, run

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"

# Never prompt for credentials; fail fast instead.
_GIT_ENV = {"GIT_TERMINAL_PROMPT": "0"}
_CLONE_TIMEOUT = 600


def repo_name_from_url(repo_url: str) -> str:
    """'https://github.com/juice-shop/juice-shop.git' -> 'juice-shop'."""
    name = repo_url.rstrip("/").split("/")[-1].split(":")[-1]
    name = re.sub(r"\.git$", "", name)
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
        raise ValueError(f"Cannot derive a safe repository name from URL: {repo_url!r}")
    return name


def _git(args: list[str], cwd: Path | None = None, timeout: int = _CLONE_TIMEOUT):
    return run(["git", *args], cwd=cwd, timeout=timeout, env=_GIT_ENV)


def _checkout_ref(dest: Path, ref: str) -> None:
    """Shallow-fetch `ref` (branch, tag or commit SHA) and check it out."""
    _git(["fetch", "--depth", "1", "origin", ref], cwd=dest)
    _git(["checkout", "--detach", "FETCH_HEAD"], cwd=dest)


def fetch_repo(
    repo_url: str,
    ref: str | None = None,
    *,
    refresh: bool = False,
    workspace: Path = DEFAULT_WORKSPACE,
) -> Path:
    """Shallow-clone `repo_url` into workspace/<repo-name>/ and return that path.

    An existing clone is reused unless `refresh` is True, in which case it is
    deleted and cloned again. If `ref` is given (branch, tag or commit SHA) it
    is checked out.
    """
    dest = Path(workspace) / repo_name_from_url(repo_url)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() and refresh:
        log.info("Refreshing: removing existing clone %s", dest)
        shutil.rmtree(dest)

    if dest.exists():
        if not (dest / ".git").exists():
            raise ToolError(f"{dest} exists but is not a git repository; rerun with --refresh")
        log.info("Reusing existing clone %s", dest)
        if ref:
            _checkout_ref(dest, ref)
        return dest

    log.info("Cloning %s into %s", repo_url, dest)
    clone = ["clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref:
        try:
            _git([*clone, "--branch", ref, repo_url, str(dest)])
            return dest
        except ToolError:
            # `--branch` only accepts branches/tags; fall back to fetching a commit SHA.
            shutil.rmtree(dest, ignore_errors=True)
            _git(["init", "--quiet", str(dest)])
            _git(["remote", "add", "origin", repo_url], cwd=dest)
            _checkout_ref(dest, ref)
            return dest
    _git([*clone, repo_url, str(dest)])
    return dest


def get_repo_info(repo_path: Path, repo_url: str, ref: str | None = None) -> dict:
    """Repo URL, checked-out commit SHA and timestamps for the metadata file."""
    sha = _git(["rev-parse", "HEAD"], cwd=repo_path, timeout=30).stdout.strip()
    commit_date = _git(["log", "-1", "--format=%cI"], cwd=repo_path, timeout=30).stdout.strip()
    return {
        "url": repo_url,
        "name": repo_name_from_url(repo_url),
        "ref": ref,
        "commit_sha": sha,
        "commit_date": commit_date,
        "local_path": str(repo_path),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
