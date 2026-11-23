"""Package URL helpers. Every component is identified by its canonical purl:
type/namespace/name@version, without qualifiers or subpath, percent-encoded the
same way for every tool (e.g. pkg:npm/%40angular/core@22.0.1)."""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

_PURL = re.compile(r"^pkg:(?P<type>[A-Za-z0-9.+-]+)/(?P<rest>[^?#]+)")


def _enc(s: str) -> str:
    return quote(s, safe=".-_~+")


def build_purl(ptype: str, name: str, version: str | None, namespace: str | None = None) -> str:
    ptype = ptype.lower()
    if ptype == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if ptype == "npm" and name.startswith("@") and "/" in name and not namespace:
        namespace, name = name.split("/", 1)
    parts = [_enc(p) for p in (namespace or "").split("/") if p] + [_enc(name)]
    purl = f"pkg:{ptype}/{'/'.join(parts)}"
    if version:
        purl += "@" + _enc(version)
    return purl


def npm_purl(name: str, version: str | None) -> str:
    return build_purl("npm", name, version)


def parse_purl(purl: str) -> dict | None:
    """{type, namespace, name, version} or None if not a purl."""
    if not purl:
        return None
    m = _PURL.match(purl.strip())
    if not m:
        return None
    rest = m.group("rest")
    version = None
    # The version separator is the last '@' that is not percent-encoded and not
    # the leading '@' of an npm scope.
    at = rest.rfind("@")
    if at > 0 and rest[at - 1] != "/":
        rest, version = rest[:at], unquote(rest[at + 1:])
    segs = [unquote(s) for s in rest.strip("/").split("/") if s]
    if not segs:
        return None
    return {"type": m.group("type").lower(), "namespace": "/".join(segs[:-1]) or None,
            "name": segs[-1], "version": version}


def canonical_purl(purl: str | None) -> str | None:
    """Normalise a purl from any tool to the canonical identity form."""
    p = parse_purl(purl or "")
    if not p:
        return None
    return build_purl(p["type"], p["name"], p["version"], p["namespace"])


def purl_ecosystem(purl: str | None) -> str | None:
    p = parse_purl(purl or "")
    return p["type"] if p else None


def purl_display_name(purl: str) -> str:
    p = parse_purl(purl)
    if not p:
        return purl
    return f"{p['namespace']}/{p['name']}" if p["namespace"] else p["name"]
