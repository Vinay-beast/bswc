"""Repository ingestion: shallow clone into workspace/<app_id>/ and keep it current."""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from agents.common import DEFAULT_WORKSPACE, RepoRef, now_iso, parse_repo_url, read_json, write_json
from agents.common.tools import ToolError, run

log = logging.getLogger(__name__)

_GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
_TIMEOUT = 600
# Our own bookkeeping lives inside .git so scanners never see it.
_STATE_FILE = Path(".git") / "guardian-state.json"


@dataclass
class FetchResult:
    path: Path
    action: str                     # cloned | updated | unchanged | checked-out
    previous_sha: str | None
    sha: str
    default_branch: str | None
    ref: str | None
    cleaned: bool = False           # untracked files removed because the commit changed
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["path"] = str(self.path)
        return d


def _git(args: list[str], cwd: Path | None = None, timeout: int = _TIMEOUT):
    return run(["git", *args], cwd=cwd, timeout=timeout, env=_GIT_ENV)


def _head(path: Path) -> str | None:
    try:
        return _git(["rev-parse", "HEAD"], cwd=path, timeout=30).stdout.strip()
    except ToolError:
        return None


def remote_default_branch(url: str) -> str | None:
    """Default branch name from `git ls-remote --symref <url> HEAD`."""
    try:
        out = _git(["ls-remote", "--symref", url, "HEAD"], timeout=60).stdout
    except ToolError:
        return None
    m = re.search(r"^ref: refs/heads/(\S+)\s+HEAD", out, re.M)
    return m.group(1) if m else None


def _checkout_fetched(dest: Path, target: str) -> None:
    _git(["fetch", "--depth", "1", "--no-tags", "origin", target], cwd=dest)
    _git(["checkout", "--quiet", "--force", "--detach", "FETCH_HEAD"], cwd=dest)


def _clean(dest: Path) -> None:
    """Remove untracked and ignored files (e.g. lockfiles generated for an older commit)."""
    _git(["clean", "-fdxq"], cwd=dest, timeout=120)
    (dest / _STATE_FILE).unlink(missing_ok=True)


def fetch_repo(
    repo: RepoRef | str,
    ref: str | None = None,
    *,
    refresh: bool = False,
    workspace: Path = DEFAULT_WORKSPACE,
) -> FetchResult:
    """Shallow-clone into workspace/<app_id>/, or bring an existing clone up to date.

    * refresh=True: delete and clone again.
    * existing clone, no ref: fetch the remote default branch (depth 1) and move to it.
    * existing clone, ref given: fetch that branch/tag/SHA and check it out.
    When the commit changes, untracked files (our generated lockfiles) are removed.
    """
    repo = parse_repo_url(repo) if isinstance(repo, str) else repo
    dest = Path(workspace) / repo.app_id
    dest.parent.mkdir(parents=True, exist_ok=True)
    default_branch = remote_default_branch(repo.url)

    if dest.exists() and refresh:
        log.info("Refreshing: removing existing clone %s", dest)
        shutil.rmtree(dest)

    if dest.exists():
        if not (dest / ".git").exists():
            raise ToolError(f"{dest} exists but is not a git repository; rerun with --refresh")
        previous = _head(dest)
        target = ref or default_branch or "HEAD"
        log.info("Updating existing clone %s to %s", dest, target)
        _checkout_fetched(dest, target)
        sha = _head(dest) or ""
        cleaned = False
        if previous != sha:
            _clean(dest)
            cleaned = True
        action = "checked-out" if ref else ("updated" if previous != sha else "unchanged")
        return FetchResult(dest, action, previous, sha, default_branch, ref, cleaned)

    log.info("Cloning %s into %s", repo.url, dest)
    clone = ["clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref:
        try:
            _git([*clone, "--branch", ref, repo.url, str(dest)])
        except ToolError:
            # --branch accepts only branches/tags; fall back to fetching a commit SHA.
            shutil.rmtree(dest, ignore_errors=True)
            _git(["init", "--quiet", str(dest)])
            _git(["remote", "add", "origin", repo.url], cwd=dest)
            _checkout_fetched(dest, ref)
    else:
        _git([*clone, repo.url, str(dest)])
    return FetchResult(dest, "cloned", None, _head(dest) or "", default_branch, ref)


def get_repo_info(repo: RepoRef, fetch: FetchResult) -> dict:
    """Repo identity + commit facts for run.json and the metadata files."""
    path = fetch.path
    commit_date = _git(["log", "-1", "--format=%cI"], cwd=path, timeout=30).stdout.strip()
    subject = _git(["log", "-1", "--format=%s"], cwd=path, timeout=30).stdout.strip()
    return {
        **repo.to_dict(),
        "ref": fetch.ref,
        "default_branch": fetch.default_branch,
        "commit_sha": fetch.sha,
        "commit_date": commit_date,
        "commit_subject": subject,
        "local_path": str(path),
        "fetch": {k: v for k, v in fetch.to_dict().items() if k != "path"},
        "fetched_at": now_iso(),
    }


def load_state(repo_path: Path) -> dict:
    return read_json(repo_path / _STATE_FILE, {}) or {}


def save_state(repo_path: Path, state: dict) -> None:
    write_json(repo_path / _STATE_FILE, state)
