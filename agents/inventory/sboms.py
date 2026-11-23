"""Merged CycloneDX 1.6 and SPDX 2.3 SBOMs built from the inventory graph, plus validation."""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agents.common.purl import parse_purl

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
GUARDIAN_TOOL = {"name": "guardian-discover", "version": "1.0.0"}
_HASH_ALGS = {"sha512": ("SHA-512", "SHA512", 128), "sha384": ("SHA-384", "SHA384", 96),
              "sha256": ("SHA-256", "SHA256", 64), "sha1": ("SHA-1", "SHA1", 40)}
CDX_SCOPE = {"prod": "required", "peer": "required", "optional": "optional", "dev": "excluded"}


# ----------------------------------------------------------------- helpers
def _spdx():
    import cyclonedx.spdx as spdx
    return spdx


def license_entry(value: str) -> dict:
    """CycloneDX license object: SPDX id, SPDX expression, or free-text name."""
    spdx = _spdx()
    if spdx.is_supported_id(value):
        return {"license": {"id": value}}
    fixed = spdx.fixup_id(value)
    if fixed:
        return {"license": {"id": fixed}}
    if " " in value.strip("() ") and spdx.is_expression(value):
        return {"expression": value}
    return {"license": {"name": value}}


def spdx_license(values: list[str]) -> str:
    spdx = _spdx()
    ids = []
    for v in values:
        fixed = v if spdx.is_supported_id(v) else spdx.fixup_id(v)
        if fixed:
            ids.append(fixed)
        elif " " in v.strip("() ") and spdx.is_expression(v):
            ids.append(f"({v})" if not v.startswith("(") else v)
        else:
            return "NOASSERTION"
    if not ids:
        return "NOASSERTION"
    return ids[0] if len(ids) == 1 else " AND ".join(sorted(set(ids)))


def sri_to_hashes(integrity: str | None) -> list[tuple[str, str]]:
    """'sha512-<base64>' (npm SRI) -> [(alg, hex)]."""
    out = []
    for part in str(integrity or "").split():
        alg, _, b64 = part.partition("-")
        alg = alg.lower()
        if alg not in _HASH_ALGS or not b64:
            continue
        try:
            hexval = base64.b64decode(b64, validate=True).hex()
        except (binascii.Error, ValueError):
            continue
        if len(hexval) == _HASH_ALGS[alg][2]:
            out.append((alg, hexval))
    return out


def _node_hashes(n: dict) -> list[tuple[str, str]]:
    seen = {}
    for o in n.get("occurrences", []):
        for alg, hx in sri_to_hashes(o.get("integrity")):
            seen.setdefault(alg, hx)
    return sorted(seen.items())


def _cdx_name(n: dict) -> tuple[str | None, str]:
    p = parse_purl(n["purl"]) if n.get("purl") else None
    if p and p["namespace"]:
        return p["namespace"], p["name"]
    return None, n["name"]


def _props(pairs: list[tuple[str, object]]) -> list[dict]:
    out = []
    for k, v in pairs:
        if v is None or v == [] or v == "":
            continue
        out.append({"name": f"guardian:{k}", "value": ",".join(map(str, v)) if isinstance(v, list) else str(v)})
    return out


# --------------------------------------------------------------- CycloneDX
def build_cyclonedx(inv: dict, run: dict, tool_versions: dict, container: dict | None) -> dict:
    nodes, roots = inv["nodes"], inv["roots"]
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"guardian:{run.get('app_id')}:{run.get('run_id')}")
    app_root = roots.get("project:.") or next((r for r in roots.values() if r["kind"] == "project"), None)
    app_ref = app_root["id"] if app_root else "project:."

    def comp_for(n: dict) -> dict:
        group, name = _cdx_name(n)
        c = {"type": "library", "bom-ref": n["id"], "name": name}
        if group:
            c["group"] = group
        if n.get("version"):
            c["version"] = str(n["version"])
        c["purl"] = n["purl"]
        if n.get("scope") in CDX_SCOPE:
            c["scope"] = CDX_SCOPE[n["scope"]]
        hashes = _node_hashes(n)
        if hashes:
            c["hashes"] = [{"alg": _HASH_ALGS[a][0], "content": h} for a, h in hashes]
        if n.get("licenses"):
            c["licenses"] = _licenses_block(n["licenses"])
        urls = (n.get("origin") or {}).get("resolved_urls") or []
        ext = [{"type": "distribution", "url": u} for u in urls[:3] if re.match(r"^[a-z][a-z0-9+.-]*:", u)]
        if ext:
            c["externalReferences"] = ext
        c["properties"] = _props([
            ("relationship", n.get("relationship")), ("depth", n.get("depth")), ("scope", n.get("scope")),
            ("dependents_count", n.get("dependents_count")), ("found_by", sorted(n.get("found_by", []))),
            ("in_container", n.get("in_container")), ("registry_hosts", (n.get("origin") or {}).get("registry_hosts")),
            ("origin_flags", (n.get("origin") or {}).get("flags")),
            ("declared_in", sorted({d["manifest"] for d in n.get("declared_in", [])})),
            ("lockfiles", sorted({o["lockfile"] for o in n.get("occurrences", []) if o.get("lockfile")})),
            ("ci_pin_type", (n.get("ci") or {}).get("pin_type")),
        ])
        return c

    components, nested_container = [], []
    container_root = inv.get("container_root")
    for nid in sorted(nodes):
        n = nodes[nid]
        c = comp_for(n)
        if n.get("container_only") and container_root:
            if n.get("container_kind") == "os":
                c["type"] = "library"
            nested_container.append(c)
        else:
            components.append(c)
    # Project roots other than the app, the CI root, the container root.
    for rid in sorted(roots):
        r = roots[rid]
        if rid == app_ref:
            continue
        if r["kind"] == "project":
            components.append({"type": "application", "bom-ref": rid, "name": r.get("name") or rid,
                               **({"version": str(r["version"])} if r.get("version") else {}),
                               "properties": _props([("project_path", r.get("path")), ("manifest", r.get("manifest")),
                                                     ("lockfile", r.get("lockfile")),
                                                     ("lockfile_origin", r.get("lockfile_origin"))])})
        elif r["kind"] == "ci":
            components.append({"type": "platform", "bom-ref": rid, "name": "github-actions",
                               "description": "GitHub Actions referenced by the repository's workflows",
                               "properties": _props([("workflows", r.get("workflows"))])})
        elif r["kind"] == "container" and container:
            name, _, tag = container["ref"].rpartition(":") if ":" in container["ref"].rsplit("/", 1)[-1] else (container["ref"], "", "")
            cc = {"type": "container", "bom-ref": rid, "name": name or container["ref"],
                  **({"version": tag} if tag else {}),
                  "description": f"Container image {container['ref']}",
                  "properties": _props([("image_digest", container.get("digest")), ("os", (container.get("os") or {}).get("name")),
                                        ("os_version", (container.get("os") or {}).get("version")),
                                        ("layers", container.get("layers")),
                                        ("image_sbom", "artifacts/raw/syft-image.cdx.json"),
                                        ("declared_base_image", container.get("declared_base_image"))])}
            dg = container.get("digest") or ""
            if dg.startswith("sha256:") and len(dg) == 71:
                cc["hashes"] = [{"alg": "SHA-256", "content": dg[7:]}]
                repo_name = (name or container["ref"]).rsplit("/", 1)[-1]
                cc["purl"] = f"pkg:oci/{repo_name}@sha256%3A{dg[7:]}?repository_url={(name or container['ref'])}"
            if nested_container:
                cc["components"] = nested_container
            components.append(cc)

    children: dict[str, list[str]] = {}
    for e in inv["edges"]:
        children.setdefault(e["from"], []).append(e["to"])
    refs = [app_ref] + [c["bom-ref"] for c in _walk(components)]
    dependencies = [{"ref": r, "dependsOn": sorted(set(children.get(r, [])))} for r in refs]

    tools = [{"type": "application", "name": t, "version": v}
             for t, v in sorted(tool_versions.items()) if v and t in ("syft", "trivy", "cdxgen", "npm", "node", "go", "pip", "docker")]
    tools.append({"type": "application", "name": GUARDIAN_TOOL["name"], "version": GUARDIAN_TOOL["version"]})
    app_component = {"type": "application", "bom-ref": app_ref,
                     "name": (app_root or {}).get("name") or run.get("display_name") or "app",
                     **({"version": str(app_root["version"])} if app_root and app_root.get("version") else {}),
                     "externalReferences": [{"type": "vcs", "url": run.get("repo_url")}] if run.get("repo_url") else [],
                     "properties": _props([("project_path", (app_root or {}).get("path")),
                                           ("lockfile", (app_root or {}).get("lockfile")),
                                           ("lockfile_origin", (app_root or {}).get("lockfile_origin"))])}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": tools},
            "component": app_component,
            "properties": _props([("repo_url", run.get("repo_url")), ("commit_sha", run.get("commit_sha")),
                                  ("commit_date", run.get("commit_date")), ("run_id", run.get("run_id")),
                                  ("app_id", run.get("app_id"))]),
        },
        "components": components,
        "dependencies": dependencies,
    }


def _licenses_block(values: list[str]) -> list[dict]:
    entries = [license_entry(v) for v in values]
    exprs = [e for e in entries if "expression" in e]
    if exprs:                                  # CycloneDX: one expression OR a list of licenses
        return [exprs[0]]
    return entries


def _walk(components: list[dict]):
    for c in components:
        yield c
        yield from _walk(c.get("components") or [])


def validate_cyclonedx(bom: dict) -> dict:
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as exc:
        return {"valid": None, "validator": None, "errors": [f"cyclonedx-python-lib not installed: {exc}"]}
    import importlib.metadata as md
    validator = f"cyclonedx-python-lib {md.version('cyclonedx-python-lib')} JsonStrictValidator (CycloneDX 1.6 JSON schema)"
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom), all_errors=True)
    errs = [str(e)[:500] for e in (errors or [])] if errors else []
    return {"valid": not errs, "validator": validator, "errors": errs[:20], "error_count": len(errs)}


# -------------------------------------------------------------------- SPDX
def _spdx_id(i: int) -> str:
    return f"SPDXRef-Package-{i}"


def build_spdx(inv: dict, run: dict, tool_versions: dict, container: dict | None) -> dict:
    nodes, roots = inv["nodes"], inv["roots"]
    ids: dict[str, str] = {}
    packages = []
    i = 0
    for rid in sorted(roots, key=lambda r: (r != "project:.", r)):
        r = roots[rid]
        i += 1
        ids[rid] = _spdx_id(i)
        purpose = {"project": "APPLICATION", "ci": "OTHER", "container": "CONTAINER"}[r["kind"]]
        packages.append({
            "SPDXID": ids[rid], "name": r.get("name") or rid, "versionInfo": str(r.get("version") or "NOASSERTION"),
            "downloadLocation": run.get("repo_url") if r["kind"] == "project" and run.get("repo_url") else "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION", "primaryPackagePurpose": purpose,
            "comment": f"guardian root {rid}",
            **({"checksums": [{"algorithm": "SHA256", "checksumValue": container["digest"][7:]}]}
               if r["kind"] == "container" and container and str(container.get("digest", "")).startswith("sha256:") else {}),
        })
    for nid in sorted(nodes):
        n = nodes[nid]
        i += 1
        ids[nid] = _spdx_id(i)
        urls = (n.get("origin") or {}).get("resolved_urls") or []
        dl = next((u for u in urls if re.match(r"^(https?|git\+\S+)://", u)), "NOASSERTION")
        pkg = {
            "SPDXID": ids[nid], "name": n["name"], "versionInfo": str(n.get("version") or "NOASSERTION"),
            "downloadLocation": dl, "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": spdx_license(n.get("licenses") or []),
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": n["purl"]}],
        }
        hashes = _node_hashes(n)
        if hashes:
            pkg["checksums"] = [{"algorithm": _HASH_ALGS[a][1], "checksumValue": h} for a, h in hashes]
        if pkg["licenseDeclared"] == "NOASSERTION" and n.get("licenses"):
            pkg["licenseComments"] = "Declared (not SPDX-normalisable): " + "; ".join(n["licenses"])[:500]
        packages.append(pkg)
    app = ids.get("project:.") or packages[0]["SPDXID"]
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": app}]
    for rid in sorted(roots):
        if ids[rid] != app:
            rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": ids[rid]})
    for e in inv["edges"]:
        if e["from"] not in ids or e["to"] not in ids:
            continue
        rel = {"spdxElementId": ids[e["from"]], "relatedSpdxElement": ids[e["to"]]}
        if e["type"] == "contains":
            rel["relationshipType"] = "CONTAINS"
        else:
            rel["relationshipType"] = "DEPENDS_ON"
            rel["comment"] = f"type={e['type']} source={e.get('edge_source')}"
        rels.append(rel)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    creators = [f"Tool: {t}-{v}" for t, v in sorted(tool_versions.items())
                if v and t in ("syft", "trivy", "cdxgen", "npm")] + [f"Tool: {GUARDIAN_TOOL['name']}-{GUARDIAN_TOOL['version']}"]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{run.get('display_name') or run.get('app_id')}-{(run.get('commit_sha') or '')[:7]}",
        "documentNamespace": f"https://guardian.local/spdx/{run.get('app_id')}/{run.get('run_id')}",
        "creationInfo": {"created": created, "creators": creators,
                         "comment": f"repo={run.get('repo_url')} commit={run.get('commit_sha')} run_id={run.get('run_id')}"},
        "documentDescribes": [app],
        "packages": packages,
        "relationships": rels,
    }


def validate_spdx(doc: dict) -> dict:
    try:
        import jsonschema
    except ImportError as exc:
        return {"valid": None, "validator": None, "errors": [f"jsonschema not installed: {exc}"]}
    schema = json.loads((SCHEMA_DIR / "spdx-2.3.schema.json").read_text())
    v = jsonschema.Draft7Validator(schema)
    errs = [f"{'/'.join(map(str, e.path))}: {e.message}"[:300] for e in v.iter_errors(doc)]
    # Referential integrity, which the JSON schema cannot express.
    known = {p["SPDXID"] for p in doc["packages"]} | {"SPDXRef-DOCUMENT"}
    dangling = [r for r in doc["relationships"] if r["spdxElementId"] not in known or r["relatedSpdxElement"] not in known]
    errs += [f"relationship references unknown element: {r}" for r in dangling[:5]]
    import importlib.metadata as md
    return {"valid": not errs, "validator": f"jsonschema {md.version('jsonschema')} + official SPDX 2.3 JSON schema "
                                            "(spdx-spec v2.3) + relationship reference check",
            "errors": errs[:20], "error_count": len(errs)}
