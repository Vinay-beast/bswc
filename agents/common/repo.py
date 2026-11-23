"""Git URL parsing and app identifiers.

    https://github.com/juice-shop/juice-shop(.git)   -> owner juice-shop, repo juice-shop
    git@github.com:juice-shop/juice-shop.git          -> same
    ssh://git@gitlab.com:2222/group/sub/repo.git      -> owner group/sub, repo repo

app_id = "<owner>__<repo>" (owner '/' replaced by '-'), used for workspace/ and outputs/.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SCP = re.compile(r"^(?P<user>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+):(?P<path>[^/].*)$")
_URL = re.compile(r"^(?P<scheme>https?|ssh|git)://(?:[^@/]+@)?(?P<host>[A-Za-z0-9.-]+)(?::\d+)?/(?P<path>.+)$")


@dataclass(frozen=True)
class RepoRef:
    url: str
    host: str
    owner: str
    repo: str

    @property
    def app_id(self) -> str:
        return f"{self.owner.replace('/', '-')}__{self.repo}"

    @property
    def display_name(self) -> str:
        return self.repo

    def to_dict(self) -> dict:
        return {**asdict(self), "app_id": self.app_id, "display_name": self.display_name}


def parse_repo_url(url: str) -> RepoRef:
    """Parse an https, ssh, scp-style or git:// URL. Raises ValueError for anything else."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Repository URL is empty")
    url = url.strip()
    m = _URL.match(url) or _SCP.match(url)
    if not m:
        raise ValueError(f"Not a git URL (expected https://, ssh://, git:// or user@host:owner/repo): {url!r}")
    host = m.group("host").lower()
    path = m.group("path").split("?", 1)[0].split("#", 1)[0].strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) < 2:
        raise ValueError(f"URL must contain an owner and a repository name: {url!r}")
    if any(not _SEGMENT.match(p) or p in (".", "..") for p in parts):
        raise ValueError(f"Unsafe characters in repository path: {url!r}")
    if "." not in host and host != "localhost":
        raise ValueError(f"Not a valid git host: {host!r}")
    return RepoRef(url=url, host=host, owner="/".join(parts[:-1]), repo=parts[-1])
