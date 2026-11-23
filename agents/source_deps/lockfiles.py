"""Authoritative dependency edges from lockfiles.

npm package-lock v2/v3 ("packages" map) and v1 (nested "dependencies"),
yarn.lock (classic v1 and berry), pnpm-lock.yaml (v6-v9).

npm resolution follows Node's algorithm: a dependency `name` required by the
package installed at path P resolves to the first existing entry among
    P/node_modules/name, <parent of P>/node_modules/name, ..., node_modules/name
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import yaml

from agents.common.purl import npm_purl

from .graph_model import GraphBuilder

DEP_SECTIONS = (("dependencies", "prod"), ("optionalDependencies", "optional"),
                ("peerDependencies", "peer"))
ROOT_SECTIONS = DEP_SECTIONS + (("devDependencies", "dev"),)


class LockfileError(ValueError):
    pass


def _parent_dir(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[1]


def resolve_npm(packages: dict, from_path: str, name: str) -> str | None:
    """Node's lookup: walk up from `from_path` looking for <dir>/node_modules/<name>."""
    cur = from_path
    while True:
        cand = f"{cur}/node_modules/{name}" if cur else f"node_modules/{name}"
        if cand in packages:
            return cand
        if not cur:
            return None
        cur = _parent_dir(cur)


def _v1_to_packages(lock: dict, root_pkg: dict) -> dict:
    """Convert a v1 nested lockfile into the v2 "packages" shape."""
    packages: dict[str, dict] = {"": {
        "name": lock.get("name") or root_pkg.get("name"),
        "version": lock.get("version") or root_pkg.get("version"),
        **{s: root_pkg.get(s) or {} for s, _ in ROOT_SECTIONS},
    }}

    def walk(deps: dict, prefix: str) -> None:
        for name, entry in (deps or {}).items():
            key = f"{prefix}node_modules/{name}"
            version = entry.get("version", "")
            real_name = name
            if version.startswith("npm:"):          # alias: "npm:real-name@1.2.3"
                real_name, _, version = version[4:].rpartition("@")
            packages[key] = {
                "name": real_name if real_name != name else None,
                "version": version, "resolved": entry.get("resolved"),
                "integrity": entry.get("integrity"), "dev": entry.get("dev"),
                "optional": entry.get("optional"), "inBundle": entry.get("bundled"),
                "dependencies": entry.get("requires") or {},
            }
            walk(entry.get("dependencies"), key + "/")

    walk(lock.get("dependencies"), "")
    return packages


def parse_npm_lock(lock_path: Path, project_id: str, lock_rel: str, builder: GraphBuilder,
                   root_pkg: dict | None = None, manifest_rel: str | None = None) -> dict:
    """Add nodes/edges for one package-lock.json / npm-shrinkwrap.json. Returns stats."""
    try:
        lock = json.loads(Path(lock_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise LockfileError(f"cannot read {lock_rel}: {exc}") from exc
    version = lock.get("lockfileVersion", 1)
    root_pkg = root_pkg or {}
    packages = lock.get("packages") if version >= 2 and "packages" in lock else _v1_to_packages(lock, root_pkg)
    base = _parent_dir(lock_rel) if "/" in lock_rel else "."

    # Map every install path to a node id (purl, or project id for the root / workspace members).
    ids: dict[str, str] = {}
    entries = 0
    for key, entry in packages.items():
        if key == "":
            ids[key] = project_id
            continue
        if entry.get("link"):
            continue                                   # resolved below via its target
        if "node_modules/" not in key:                 # workspace member folder
            member_id = f"project:{key if base == '.' else base + '/' + key}"
            ids[key] = member_id
            builder.add_root(member_id, name=entry.get("name") or PurePosixPath(key).name,
                             version=entry.get("version"), ecosystem="npm", lockfile=lock_rel,
                             manifest=f"{key}/package.json" if base == "." else f"{base}/{key}/package.json",
                             workspace_of=project_id)
            continue
        name = entry.get("name") or _name_from_key(key)
        ver = entry.get("version")
        if not ver:
            continue
        purl = npm_purl(name, ver)
        ids[key] = purl
        entries += 1
        builder.add_node(purl, name=name, version=ver, ecosystem="npm", source="lockfile-parser",
                         license=entry.get("license"), occurrence={
                             "project": project_id, "lockfile": lock_rel, "install_path": key,
                             "resolved": entry.get("resolved"), "integrity": entry.get("integrity"),
                             "dev": bool(entry.get("dev")), "optional": bool(entry.get("optional")),
                             "dev_optional": bool(entry.get("devOptional")), "bundled": bool(entry.get("inBundle")),
                             **({"alias": _name_from_key(key)} if entry.get("name") and entry["name"] != _name_from_key(key) else {}),
                         })

    def target_of(key: str | None) -> str | None:
        if key is None:
            return None
        entry = packages.get(key, {})
        if entry.get("link"):
            resolved = entry.get("resolved") or ""
            return ids.get(resolved) or ids.get(resolved.lstrip("./"))
        return ids.get(key)

    edges = unresolved = 0
    for key, entry in packages.items():
        src = ids.get(key)
        if src is None:
            continue
        is_root_like = key == "" or "node_modules/" not in key
        sections = ROOT_SECTIONS if is_root_like else DEP_SECTIONS
        peer_meta = entry.get("peerDependenciesMeta") or {}
        for section, etype in sections:
            for dep_name, rng in (entry.get(section) or {}).items():
                if etype == "peer" and dep_name in (entry.get("dependencies") or {}):
                    continue
                dst = target_of(resolve_npm(packages, key, dep_name))
                if dst is None:
                    optional_peer = etype == "peer" and (peer_meta.get(dep_name) or {}).get("optional")
                    builder.add_unresolved(project=project_id, lockfile=lock_rel, from_id=src,
                                           from_path=key or ".", name=dep_name, range=rng, type=etype,
                                           reason="optional dependency not installed" if etype == "optional"
                                           else "optional peer dependency not installed" if optional_peer
                                           else "peer dependency not installed" if etype == "peer"
                                           else "not found in lockfile")
                    unresolved += 1
                    continue
                builder.add_edge(src, dst, type_=etype, range_=rng, edge_source="lockfile-parser",
                                 project=project_id)
                edges += 1
                if is_root_like and dst.startswith("pkg:"):
                    man = manifest_rel if key == "" else (f"{key}/package.json" if base == "." else f"{base}/{key}/package.json")
                    builder.add_declared(dst, man, section, rng)
    builder.mark_authoritative("npm", project_id)
    return {"lockfile": lock_rel, "format": f"npm-lock-v{version}", "entries": entries,
            "edges": edges, "unresolved": unresolved,
            "purls": sorted({v for v in ids.values() if v.startswith("pkg:")})}


# ---------------------------------------------------------------- yarn.lock
_YARN_V1_KEY = re.compile(r'^(?P<keys>("[^"]+"|[^\s:][^:]*)(,\s*("[^"]+"|[^\s:,][^:,]*))*):\s*$')


def _split_spec(spec: str) -> tuple[str, str]:
    """'@scope/name@^1.0.0' -> ('@scope/name', '^1.0.0')."""
    spec = spec.strip().strip('"')
    at = spec.rfind("@")
    if at <= 0:
        return spec, ""
    return spec[:at], spec[at + 1:]


def _parse_yarn_v1(text: str) -> dict[str, dict]:
    """Return {"name@range": entry} for yarn classic lockfiles."""
    out: dict[str, dict] = {}
    current: dict | None = None
    section: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 0:
            m = _YARN_V1_KEY.match(line)
            if not m:
                current = None
                continue
            current = {"dependencies": {}, "optionalDependencies": {}}
            for k in re.split(r",\s*", m.group("keys")):
                out[k.strip().strip('"')] = current
            section = None
        elif current is not None and indent == 2:
            if line.endswith(":"):
                section = line[:-1]
                continue
            section = None
            key, _, val = line.partition(" ")
            current[key] = val.strip().strip('"')
        elif current is not None and indent >= 4 and section in ("dependencies", "optionalDependencies"):
            key, _, val = line.partition(" ")
            current[section][key.strip('"')] = val.strip().strip('"')
    return out


def parse_yarn_lock(lock_path: Path, project_id: str, lock_rel: str, builder: GraphBuilder,
                    root_pkg: dict, manifest_rel: str) -> dict:
    text = Path(lock_path).read_text()
    berry = "__metadata:" in text
    if berry:
        data = yaml.safe_load(text) or {}
        table: dict[str, dict] = {}
        for keys, entry in data.items():
            if keys == "__metadata" or not isinstance(entry, dict):
                continue
            for k in str(keys).split(","):
                table[k.strip()] = entry
        def lookup(name: str, rng: str):
            return table.get(f"{name}@{rng}") or table.get(f"{name}@npm:{rng}")
    else:
        table = _parse_yarn_v1(text)
        def lookup(name: str, rng: str):
            return table.get(f"{name}@{rng}")

    entry_ids: dict[int, str] = {}
    entries = 0
    for key, entry in table.items():
        name, rng = _split_spec(key)
        if berry and "@workspace:" in key:
            continue
        version = entry.get("version")
        if not version or id(entry) in entry_ids:
            continue
        purl = npm_purl(name, str(version))
        entry_ids[id(entry)] = purl
        entries += 1
        builder.add_node(purl, name=name, version=str(version), ecosystem="npm", source="lockfile-parser",
                         occurrence={"project": project_id, "lockfile": lock_rel, "install_path": None,
                                     "resolved": entry.get("resolved") or entry.get("resolution"),
                                     "integrity": entry.get("integrity") or entry.get("checksum")})

    edges = unresolved = 0
    def link(src: str, deps: dict, etype: str, declared: str | None = None):
        nonlocal edges, unresolved
        for dep, rng in (deps or {}).items():
            target = lookup(dep, str(rng))
            dst = entry_ids.get(id(target)) if target is not None else None
            if dst is None:
                builder.add_unresolved(project=project_id, lockfile=lock_rel, from_id=src, name=dep,
                                       range=rng, type=etype, reason="not found in yarn.lock")
                unresolved += 1
                continue
            builder.add_edge(src, dst, type_=etype, range_=str(rng), edge_source="lockfile-parser",
                             project=project_id)
            edges += 1
            if declared:
                builder.add_declared(dst, manifest_rel, declared, str(rng))

    for section, etype in ROOT_SECTIONS:
        link(project_id, root_pkg.get(section) or {}, etype, declared=section)
    seen = set()
    for entry in table.values():
        src = entry_ids.get(id(entry))
        if src is None or id(entry) in seen:
            continue
        seen.add(id(entry))
        link(src, entry.get("dependencies") or {}, "prod")
        link(src, entry.get("optionalDependencies") or {}, "optional")
    builder.mark_authoritative("npm", project_id)
    return {"lockfile": lock_rel, "format": "yarn-berry" if berry else "yarn-v1", "entries": entries,
            "edges": edges, "unresolved": unresolved, "purls": sorted(set(entry_ids.values()))}


# ----------------------------------------------------------- pnpm-lock.yaml
_PEER_SUFFIX = re.compile(r"\(.*\)$")


def _pnpm_key(key: str) -> tuple[str, str]:
    """'/@scope/name@1.2.3(peer@1)' or '@scope/name@1.2.3' -> (name, version)."""
    key = _PEER_SUFFIX.sub("", key.lstrip("/"))
    if "@" not in key[1:]:
        # v5 style: /name/1.2.3
        name, _, version = key.rpartition("/")
        return name, version
    return _split_spec(key)


def parse_pnpm_lock(lock_path: Path, project_id: str, lock_rel: str, builder: GraphBuilder,
                    root_pkg: dict, manifest_rel: str) -> dict:
    data = yaml.safe_load(Path(lock_path).read_text()) or {}
    packages = data.get("packages") or {}
    snapshots = data.get("snapshots") or {}
    base = _parent_dir(lock_rel) if "/" in lock_rel else "."
    ids: dict[str, str] = {}
    entries = 0
    for key, entry in {**packages, **snapshots}.items():
        name, version = _pnpm_key(str(key))
        if not version or version.startswith("link:"):
            continue
        purl = npm_purl(name, version)
        ids[_PEER_SUFFIX.sub("", str(key).lstrip("/"))] = purl
        if purl not in builder.nodes or not any(o.get("lockfile") == lock_rel for o in builder.nodes[purl]["occurrences"]):
            entries += 1
        meta = packages.get(key) or packages.get(_PEER_SUFFIX.sub("", str(key))) or entry or {}
        res = meta.get("resolution") or {}
        builder.add_node(purl, name=name, version=version, ecosystem="npm", source="lockfile-parser",
                         occurrence={"project": project_id, "lockfile": lock_rel, "install_path": None,
                                     "resolved": res.get("tarball"), "integrity": res.get("integrity"),
                                     "dev": bool(meta.get("dev"))})

    def dep_version(v) -> str:
        v = v.get("version") if isinstance(v, dict) else v
        return _PEER_SUFFIX.sub("", str(v))

    edges = unresolved = 0
    def link(src: str, deps: dict, etype: str, declared: str | None = None, man: str | None = None):
        nonlocal edges, unresolved
        for dep, spec in (deps or {}).items():
            ver = dep_version(spec)
            if ver.startswith("link:"):
                target_dir = ver[5:]
                continue_id = f"project:{target_dir if base == '.' else base + '/' + target_dir}"
                builder.add_edge(src, continue_id, type_=etype, range_=ver, edge_source="lockfile-parser",
                                 project=project_id)
                continue
            dst = ids.get(f"{dep}@{ver}") or ids.get(f"{dep}/{ver}")
            if dst is None:
                builder.add_unresolved(project=project_id, lockfile=lock_rel, from_id=src, name=dep,
                                       range=ver, type=etype, reason="not found in pnpm-lock.yaml")
                unresolved += 1
                continue
            builder.add_edge(src, dst, type_=etype, range_=(spec.get("specifier") if isinstance(spec, dict) else ver),
                             edge_source="lockfile-parser", project=project_id)
            edges += 1
            if declared:
                builder.add_declared(dst, man or manifest_rel, declared, spec.get("specifier") if isinstance(spec, dict) else ver)

    importers = data.get("importers") or {".": {s: data.get(s) for s, _ in ROOT_SECTIONS}}
    for imp_path, imp in importers.items():
        imp_id = project_id if imp_path in (".", "") else f"project:{imp_path if base == '.' else base + '/' + imp_path}"
        if imp_id != project_id:
            builder.add_root(imp_id, name=PurePosixPath(imp_path).name, ecosystem="npm",
                             lockfile=lock_rel, workspace_of=project_id)
        man = manifest_rel if imp_id == project_id else f"{imp_path}/package.json"
        for section, etype in ROOT_SECTIONS:
            link(imp_id, (imp or {}).get(section) or {}, etype, declared=section, man=man)
    for key, entry in (snapshots or packages).items():
        src = ids.get(_PEER_SUFFIX.sub("", str(key).lstrip("/")))
        if src is None:
            continue
        link(src, (entry or {}).get("dependencies") or {}, "prod")
        link(src, (entry or {}).get("optionalDependencies") or {}, "optional")
    builder.mark_authoritative("npm", project_id)
    return {"lockfile": lock_rel, "format": f"pnpm-lock-v{data.get('lockfileVersion')}", "entries": entries,
            "edges": edges, "unresolved": unresolved, "purls": sorted(set(ids.values()))}


def parse_lockfile(repo_path: Path, project, builder: GraphBuilder) -> dict:
    """Dispatch on the lockfile name. Raises LockfileError on unsupported/broken files."""
    lock_rel = project.lockfile
    lock_path = Path(repo_path) / lock_rel
    try:
        root_pkg = json.loads((Path(repo_path) / project.manifest).read_text())
    except (OSError, json.JSONDecodeError):
        root_pkg = {}
    name = PurePosixPath(lock_rel).name
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return parse_npm_lock(lock_path, project.id, lock_rel, builder, root_pkg, project.manifest)
        if name == "yarn.lock":
            return parse_yarn_lock(lock_path, project.id, lock_rel, builder, root_pkg, project.manifest)
        if name == "pnpm-lock.yaml":
            return parse_pnpm_lock(lock_path, project.id, lock_rel, builder, root_pkg, project.manifest)
    except LockfileError:
        raise
    except Exception as exc:  # noqa: BLE001 - any parser bug becomes a coverage gap, not a crash
        raise LockfileError(f"{lock_rel}: {type(exc).__name__}: {exc}") from exc
    raise LockfileError(f"no parser for {lock_rel}")
