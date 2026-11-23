"""SBOM generation with Syft and normalization of CycloneDX components."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .tools import ToolError, run

log = logging.getLogger(__name__)

_SYFT_TIMEOUT = 900
_SYFT_ENV = {
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    # Syft skips devDependencies by default; we want them, tagged with a scope.
    "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true",
}
# Don't descend into the clone's git metadata or any vendored node_modules.
_SYFT_EXCLUDES = ["./.git", "./**/node_modules"]


def generate_sbom(repo_path: Path, output_file: Path) -> Path:
    """Run Syft on `repo_path` and write a CycloneDX JSON SBOM to `output_file`."""
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["syft", "scan", f"dir:{Path(repo_path).resolve()}",
           "-o", f"cyclonedx-json={output_file.resolve()}", "-q"]
    for pattern in _SYFT_EXCLUDES:
        cmd += ["--exclude", pattern]
    log.info("Running Syft on %s", repo_path)
    run(cmd, timeout=_SYFT_TIMEOUT, env=_SYFT_ENV)
    if not output_file.is_file():
        raise ToolError(f"Syft finished but did not write {output_file}")
    return output_file


def _licenses(component: dict) -> list[str]:
    out: list[str] = []
    for entry in component.get("licenses") or []:
        if "expression" in entry:
            out.append(entry["expression"])
        lic = entry.get("license") or {}
        value = lic.get("id") or lic.get("name")
        if value:
            out.append(value)
    return sorted(set(out))


def _ecosystem(purl: str | None, component: dict) -> str | None:
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].split("@", 1)[0]
    for prop in component.get("properties") or []:
        if prop.get("name") == "syft:package:type":
            return prop.get("value")
    return None


def _properties(component: dict) -> tuple[list[str], str | None]:
    locations, found_by = [], None
    for prop in component.get("properties") or []:
        name = prop.get("name", "")
        if name.startswith("syft:location:") and name.endswith(":path"):
            locations.append(prop["value"].lstrip("/"))
        elif name == "syft:package:foundBy":
            found_by = prop.get("value")
    return sorted(set(locations)), found_by


def normalize_components(sbom_file: Path) -> list[dict]:
    """Flatten a CycloneDX SBOM into a list of components.

    Each entry: name, version, purl, ecosystem, licenses, locations (source
    manifests/lockfiles relative to the scanned directory), type, found_by.
    """
    sbom = json.loads(Path(sbom_file).read_text())
    components: list[dict] = []
    for c in sbom.get("components") or []:
        purl = c.get("purl")
        name = c.get("name")
        if c.get("group"):
            name = f"{c['group']}/{name}"
        locations, found_by = _properties(c)
        components.append({
            "name": name,
            "version": c.get("version"),
            "purl": purl,
            "ecosystem": _ecosystem(purl, c),
            "licenses": _licenses(c),
            "locations": locations,
            "type": c.get("type"),
            "found_by": found_by,
        })
    components.sort(key=lambda x: (x["ecosystem"] or "", x["name"] or "", x["version"] or ""))
    return components
