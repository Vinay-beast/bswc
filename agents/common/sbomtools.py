"""Run Syft / cdxgen / Trivy and normalise their CycloneDX output.

Shared by the source-deps agent (directory scans) and the artifact-inspector
agent (image scans). Every run is non-fatal and recorded (command, version,
duration, status).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .purl import canonical_purl, parse_purl
from .tools import TOOLS_DIR, run_recorded

SYFT_ENV = {"SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}


def syft_dir(repo: Path, cdx_out: Path, spdx_out: Path, excludes: list[str]) -> dict:
    cmd = ["syft", "scan", f"dir:{repo}", "-q",
           "-o", f"cyclonedx-json@1.6={cdx_out}", "-o", f"spdx-json={spdx_out}"]
    for e in excludes:
        cmd += ["--exclude", e]
    return run_recorded("syft", cmd, timeout=900, env=SYFT_ENV, output_file=cdx_out)


def syft_image(source: str, cdx_out: Path, spdx_out: Path) -> dict:
    cmd = ["syft", "scan", source, "-q", "-o", f"cyclonedx-json@1.6={cdx_out}", "-o", f"spdx-json={spdx_out}"]
    return run_recorded("syft", cmd, timeout=1200, env=SYFT_ENV, output_file=cdx_out)


def trivy_fs(repo: Path, out: Path, skip_dirs: list[str], cache_dir: Path) -> dict:
    # No --scanners flag: with --format cyclonedx Trivy lists packages only
    # (vulnerability scanning stays off unless --scanners vuln is passed).
    cmd = ["trivy", "fs", "--format", "cyclonedx", "--include-dev-deps", "--disable-telemetry",
           "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--quiet",
           "--cache-dir", str(cache_dir), "-o", str(out)]
    for d in skip_dirs:
        cmd += ["--skip-dirs", d]
    cmd.append(str(repo))
    return run_recorded("trivy", cmd, timeout=900, output_file=out)


def trivy_image(ref: str, out: Path, cache_dir: Path, image_src: str) -> dict:
    cmd = ["trivy", "image", "--format", "cyclonedx", "--disable-telemetry", "--skip-db-update",
           "--skip-java-db-update", "--offline-scan", "--quiet", "--image-src", image_src,
           "--cache-dir", str(cache_dir), "-o", str(out), ref]
    return run_recorded("trivy", cmd, timeout=1800, output_file=out)


def cdxgen_dir(repo: Path, out: Path, excludes: list[str]) -> dict:
    """cdxgen in recurse mode with installs disabled and Node's permission model on."""
    tmp = Path(tempfile.mkdtemp(prefix="guardian-cdxgen-"))
    node_options = " ".join([
        "--permission",
        f"--allow-fs-read={TOOLS_DIR}/*", f"--allow-fs-read={repo}/*", f"--allow-fs-read={tmp}/*",
        f"--allow-fs-write={tmp}/*", f"--allow-fs-write={out}",
        "--allow-child-process",
    ])
    env = {
        "CDXGEN_SECURE_MODE": "true",       # cdxgen's hardened mode (needs the permission flags above)
        "NODE_OPTIONS": node_options,
        "NPM_INSTALL_ARGS": "--ignore-scripts",
        "FETCH_LICENSE": "false",
        "CDXGEN_FETCH_PKG_METADATA": "false",
        "GO_FETCH_VCS": "false",
        "TMPDIR": str(tmp),
        "CDXGEN_TEMP_DIR": str(tmp),
    }
    cmd = ["cdxgen", "-r", "--no-install-deps", "--spec-version", "1.6", "--no-babel",
           "--profile", "generic", "-o", str(out)]
    for e in excludes:
        cmd += ["--exclude", e]
    cmd.append(str(repo))
    rec = run_recorded("cdxgen", cmd, timeout=1200, env=env, output_file=out)
    return rec


def _flatten(components: list[dict]):
    for c in components or []:
        yield c
        yield from _flatten(c.get("components") or [])


def _licenses(c: dict) -> list[str]:
    out = []
    for entry in c.get("licenses") or []:
        if entry.get("expression"):
            out.append(entry["expression"])
        lic = entry.get("license") or {}
        if lic.get("id") or lic.get("name"):
            out.append(lic.get("id") or lic.get("name"))
    return sorted(set(out))


def _locations(c: dict, repo_prefix: str | None) -> list[str]:
    locs = []
    for p in c.get("properties") or []:
        n, v = p.get("name", ""), p.get("value", "")
        if (n.startswith("syft:location:") and n.endswith(":path")) or n in ("SrcFile", "aquasecurity:trivy:FilePath"):
            if repo_prefix and v.startswith(repo_prefix):
                v = v[len(repo_prefix):]
            locs.append(v.lstrip("/"))
    for ev in ((c.get("evidence") or {}).get("occurrences") or []):
        v = ev.get("location", "")
        if repo_prefix and v.startswith(repo_prefix):
            v = v[len(repo_prefix):]
        if v:
            locs.append(v.lstrip("/"))
    return sorted(set(locs))


def _hashes(c: dict) -> list[str]:
    return sorted({h.get("alg") for h in c.get("hashes") or [] if h.get("alg")})


def normalize_cdx(path: Path, tool: str, repo_root: Path | None = None) -> dict:
    """Parse a CycloneDX JSON into {components: {purl: info}, edges: [[a, b]], stats}.

    Components are keyed by canonical purl; duplicates (same purl at several
    locations) are merged. bom-refs are mapped to purls so the dependency
    section can be compared across tools.
    """
    data = json.loads(Path(path).read_text())
    prefix = str(repo_root) + "/" if repo_root else None
    meta_comp = (data.get("metadata") or {}).get("component") or {}
    ref_to_purl: dict[str, str] = {}
    root_refs = set()
    for c in _flatten([meta_comp]):
        if c.get("bom-ref"):
            root_refs.add(c["bom-ref"])
    comps: dict[str, dict] = {}
    entries = purl_less = 0
    types: dict[str, int] = {}
    for c in _flatten(data.get("components") or []):
        entries += 1
        types[c.get("type", "?")] = types.get(c.get("type", "?"), 0) + 1
        purl = canonical_purl(c.get("purl"))
        if not purl:
            purl_less += 1
            continue
        if c.get("bom-ref"):
            ref_to_purl[c["bom-ref"]] = purl
        p = parse_purl(purl)
        info = comps.setdefault(purl, {"purl": purl, "name": (f"{p['namespace']}/{p['name']}" if p["namespace"] and p["type"] in ("npm", "github", "golang") else p["name"]),
                                       "version": p["version"], "ecosystem": p["type"], "licenses": [],
                                       "locations": [], "hash_algs": [], "type": c.get("type"), "occurrences": 0})
        info["occurrences"] += 1
        info["licenses"] = sorted(set(info["licenses"]) | set(_licenses(c)))
        info["locations"] = sorted(set(info["locations"]) | set(_locations(c, prefix)))
        info["hash_algs"] = sorted(set(info["hash_algs"]) | set(_hashes(c)))
        for ext in c.get("externalReferences") or []:
            if ext.get("type") == "distribution" and ext.get("url"):
                info.setdefault("resolved", ext["url"])
    edges = set()
    root_edges = set()
    for d in data.get("dependencies") or []:
        src_ref = d.get("ref")
        src = ref_to_purl.get(src_ref)
        for t in d.get("dependsOn") or []:
            dst = ref_to_purl.get(t)
            if not dst:
                continue
            if src:
                if src != dst:
                    edges.add((src, dst))
            elif src_ref in root_refs:
                root_edges.add(dst)
    return {
        "tool": tool,
        "spec_version": data.get("specVersion"),
        "components": comps,
        "edges": sorted(edges),
        "root_edges": sorted(root_edges),
        "stats": {"entries": entries, "unique_purls": len(comps), "purl_less": purl_less,
                  "dependency_entries": len(data.get("dependencies") or []), "edges": len(edges),
                  "types": types},
        "metadata": data.get("metadata") or {},
    }


def tool_exclude_globs(skip_dirs: list[str]) -> dict[str, list[str]]:
    """The same skip list expressed in each tool's syntax."""
    names = sorted({Path(d).name for d in skip_dirs})
    return {
        "syft": ["./.git", "./**/node_modules"] + [f"./**/{n}/**" for n in names],
        "cdxgen": ["**/.git/**"] + [f"**/{n}/**" for n in names],
        "trivy": ["**/.git"] + [f"**/{n}" for n in names],
    }

