"""Container image selection and scanning (Syft + Trivy), with or without a Docker daemon."""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from agents.common.sbomtools import normalize_cdx, syft_image, trivy_image
from agents.common.tools import docker_status, public_record, run_recorded

from .dockerfile import split_image

log = logging.getLogger(__name__)

OS_PURL_TYPES = {"deb", "apk", "rpm", "alpm", "alpine", "ebuild"}
_DOCKER_CMD = re.compile(r"docker\s+(?:pull|run)\s+(?:-[-\w]+(?:[ =]\S+)?\s+)*([a-z0-9][\w./-]*[a-z0-9])(?::[\w.-]+)?", re.I)


def image_candidates_from_repo(repo_path: Path, display_name: str, compose: list[dict]) -> list[dict]:
    """Image names the project itself publishes/uses: README `docker pull/run` lines and compose `image:`."""
    names: dict[str, str] = {}
    for readme in sorted(Path(repo_path).glob("README*")):
        for m in _DOCKER_CMD.finditer(readme.read_text(errors="ignore")):
            names.setdefault(m.group(1), f"{readme.name}: docker pull/run")
    for c in compose:
        for s in c.get("services", []):
            if s.get("image") and "$" not in s["image"]:
                names.setdefault(s["image"].split("@")[0].rsplit(":", 1)[0] if ":" in s["image"].rsplit("/", 1)[-1]
                                 else s["image"].split("@")[0], f"{c['path']}: service {s['service']}")
    ranked = sorted(names.items(), key=lambda kv: (display_name.lower() not in kv[0].lower(), kv[0]))
    return [{"name": n, "source": src} for n, src in ranked]


def tag_candidates(version: str | None) -> list[str]:
    tags = []
    if version:
        tags += [f"v{version}", version]
        base = re.split(r"[-+]", version, 1)[0]
        if base != version:
            tags += [f"v{base}", base]
    tags.append("latest")
    return list(dict.fromkeys(tags))


def _docker_hub_tag_exists(repository: str, tag: str) -> bool | None:
    url = f"https://hub.docker.com/v2/repositories/{repository}/tags/{tag}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "guardian-discover"}), timeout=20) as r:
            return r.status == 200
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except (urllib.error.URLError, TimeoutError):
        return None


def image_exists(ref: str, docker_ok: bool) -> tuple[bool | None, str]:
    if shutil.which("docker"):
        rec = run_recorded("docker", ["docker", "manifest", "inspect", ref], timeout=60)
        if rec["status"] == "ok":
            return True, "docker manifest inspect"
        if "no such manifest" in (rec.get("stderr_tail") or "").lower() or "not found" in (rec.get("stderr_tail") or "").lower():
            return False, "docker manifest inspect"
    parts = split_image(ref)
    if parts["registry"] == "docker.io" and parts["tag"]:
        found = _docker_hub_tag_exists(parts["repository"], parts["tag"])
        return found, "Docker Hub API"
    return None, "unknown"


def select_image(repo_path: Path, app_id: str, display_name: str, version: str | None,
                 compose: list[dict], short_sha: str, *, image: str | None, build: bool,
                 dockerfile: str | None, docker_ok: bool) -> dict:
    """Decide which image to inspect. Returns {ref, method, reason, tried[]} or {ref: None, reason}."""
    if image:
        return {"ref": image, "method": "cli", "reason": "--image given", "tried": []}
    if build:
        return {"ref": f"guardian/{app_id}:{short_sha}", "method": "build", "dockerfile": dockerfile,
                "reason": "--build-image: built locally from the repo's Dockerfile", "tried": []}
    names = image_candidates_from_repo(repo_path, display_name, compose)
    tried = []
    for cand in names:
        for tag in tag_candidates(version):
            ref = f"{cand['name']}:{tag}"
            exists, how = image_exists(ref, docker_ok)
            tried.append({"ref": ref, "exists": exists, "checked_with": how})
            if exists:
                note = None if tag in (f"v{version}", version) else \
                    f"no image tagged with the exact version {version!r}; using {tag!r}, which may not match the cloned commit"
                return {"ref": ref, "method": "published", "name_source": cand["source"],
                        "reason": f"published image for version {version}" if note is None else note,
                        "tried": tried}
    return {"ref": None, "method": None, "tried": tried,
            "reason": "no published image found (no `docker pull` in README / compose image); "
                      "pass --image REF or --build-image"}


def _build(repo_path: Path, ref: str, dockerfile: str, records: list) -> str | None:
    # NOTE: a docker build executes the Dockerfile's RUN steps (inside the build sandbox).
    rec = run_recorded("docker", ["docker", "build", "-t", ref, "-f", str(repo_path / dockerfile), str(repo_path)],
                       timeout=3600)
    records.append(public_record(rec))
    return None if rec["status"] == "ok" else (rec.get("error") or "docker build failed")


def inspect_image(sel: dict, raw_dir: Path, repo_path: Path) -> dict:
    """Pull/resolve, then scan with Trivy and Syft. Never raises."""
    records: list[dict] = []
    warnings: list[str] = []
    ref = sel["ref"]
    d = docker_status()
    result = {"ref": ref, "selection": sel, "docker": d, "digest": None, "scanned_ref": None,
              "mode": None, "tool_runs": records, "warnings": warnings}

    if sel.get("method") == "build":
        if not d["daemon"]:
            warnings.append(f"--build-image needs a running Docker daemon ({d['error']})")
            return result
        err = _build(repo_path, ref, sel.get("dockerfile") or "Dockerfile", records)
        if err:
            warnings.append(f"docker build failed: {err}")
            return result

    if d["daemon"]:
        result["mode"] = "docker-daemon"
        if sel.get("method") != "build":
            rec = run_recorded("docker", ["docker", "pull", "--quiet", ref], timeout=1800)
            records.append(public_record(rec))
            if rec["status"] != "ok":
                warnings.append(f"docker pull failed ({rec.get('error')}); falling back to registry scanning")
                result["mode"] = "registry"
        if result["mode"] == "docker-daemon":
            rec = run_recorded("docker", ["docker", "image", "inspect", ref], timeout=60)
            records.append(public_record(rec))
            try:
                info = json.loads(rec.get("stdout") or "[]")[0]
                digests = info.get("RepoDigests") or []
                result["digest"] = digests[0].split("@", 1)[1] if digests else None
                result["image_id"] = info.get("Id")
                result["layers"] = len((info.get("RootFS") or {}).get("Layers") or [])
                result["os"] = info.get("Os")
                result["architecture"] = info.get("Architecture")
                result["created"] = info.get("Created")
                result["labels"] = (info.get("Config") or {}).get("Labels") or {}
                result["user"] = (info.get("Config") or {}).get("User") or None
            except (json.JSONDecodeError, IndexError):
                pass
    else:
        result["mode"] = "registry"
        warnings.append(f"Docker daemon unavailable ({d['error']}): scanning the image straight from the registry")

    cache = Path(tempfile.mkdtemp(prefix="guardian-trivy-img-"))
    try:
        trivy_out = raw_dir / "trivy-image.cdx.json"
        src = "docker" if result["mode"] == "docker-daemon" else "remote"
        rec = trivy_image(ref, trivy_out, cache, src)
        records.append(public_record(rec))
        if rec["status"] != "ok":
            warnings.append(f"trivy image failed: {rec.get('error')}")
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    if trivy_out.is_file():
        tmeta = _trivy_metadata(trivy_out)
        result.setdefault("layers", tmeta.get("layers"))
        if not result["digest"] and tmeta.get("digest"):
            result["digest"] = tmeta["digest"]
        result["trivy_metadata"] = tmeta

    scan_ref = ref
    if result["digest"] and result["mode"] == "registry":
        scan_ref = f"{split_image(ref)['registry']}/{split_image(ref)['repository']}@{result['digest']}"
    source = f"docker:{ref}" if result["mode"] == "docker-daemon" else f"registry:{scan_ref}"
    result["scanned_ref"] = source
    rec = syft_image(source, raw_dir / "syft-image.cdx.json", raw_dir / "syft-image.spdx.json")
    records.append(public_record(rec))
    if rec["status"] != "ok":
        warnings.append(f"syft image scan failed: {rec.get('error')}")
    return result


def _trivy_metadata(path: Path) -> dict:
    data = json.loads(path.read_text())
    comp = (data.get("metadata") or {}).get("component") or {}
    props = {}
    for p in comp.get("properties") or []:
        props.setdefault(p["name"], []).append(p["value"])
    digest = None
    for rd in props.get("aquasecurity:trivy:RepoDigest", []):
        digest = rd.split("@", 1)[1] if "@" in rd else digest
    return {"digest": digest, "layers": len(props.get("aquasecurity:trivy:DiffID", [])) or None,
            "image_id": (props.get("aquasecurity:trivy:ImageID") or [None])[0],
            "repo_tags": props.get("aquasecurity:trivy:RepoTag", [])}


def summarise_packages(raw_dir: Path) -> dict:
    """Merge the Syft and Trivy image SBOMs into one package list + OS facts."""
    per_tool = {}
    for tool, fname in (("syft", "syft-image.cdx.json"), ("trivy", "trivy-image.cdx.json")):
        f = raw_dir / fname
        if f.is_file():
            try:
                per_tool[tool] = normalize_cdx(f, f"{tool}-image")
            except (OSError, ValueError) as exc:
                log.warning("cannot parse %s: %s", f, exc)
    packages: dict[str, dict] = {}
    for tool, res in per_tool.items():
        for purl, c in res["components"].items():
            p = packages.setdefault(purl, {**{k: c[k] for k in ("purl", "name", "version", "ecosystem")},
                                           "licenses": [], "locations": [], "found_by": []})
            p["found_by"].append(f"{tool}-image")
            p["licenses"] = sorted(set(p["licenses"]) | set(c["licenses"]))
            p["locations"] = sorted(set(p["locations"]) | set(c["locations"]))[:10]
    for p in packages.values():
        p["kind"] = "os" if p["ecosystem"] in OS_PURL_TYPES else "application"
    distro = os_from_sbom(raw_dir / "syft-image.cdx.json") or os_from_sbom(raw_dir / "trivy-image.cdx.json")
    by_eco: dict[str, int] = {}
    for p in packages.values():
        by_eco[p["ecosystem"]] = by_eco.get(p["ecosystem"], 0) + 1
    return {
        "packages": sorted(packages.values(), key=lambda p: (p["kind"], p["ecosystem"], p["name"])),
        "os": distro,
        "counts": {"total": len(packages),
                   "os": sum(1 for p in packages.values() if p["kind"] == "os"),
                   "application": sum(1 for p in packages.values() if p["kind"] == "application"),
                   "by_ecosystem": dict(sorted(by_eco.items())),
                   "per_tool": {t: r["stats"]["unique_purls"] for t, r in per_tool.items()}},
    }


def os_from_sbom(path: Path) -> dict | None:
    """Find the operating-system component anywhere in a CycloneDX file."""
    if not path.is_file():
        return None
    data = json.loads(path.read_text())
    stack = list(data.get("components") or []) + [(data.get("metadata") or {}).get("component") or {}]
    while stack:
        c = stack.pop()
        if c.get("type") == "operating-system":
            return {"name": c.get("name"), "version": c.get("version"), "description": c.get("description")}
        stack += c.get("components") or []
    return None

