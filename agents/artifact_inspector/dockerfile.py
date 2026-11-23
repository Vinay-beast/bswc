"""Dockerfile / Containerfile / docker-compose parsing (facts only, no scoring)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

DOCKERFILE_NAMES = re.compile(r"^(Dockerfile|Containerfile)(\..+)?$|.+\.(Dockerfile|dockerfile)$")
COMPOSE_NAMES = re.compile(r"^(docker-)?compose(\.[\w.-]+)?\.ya?ml$")
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(-?\w+\s+)*(ba|z|da|k)?sh\b")
SHA256 = re.compile(r"@sha256:[0-9a-f]{64}$")


def split_image(ref: str) -> dict:
    """'gcr.io/distroless/nodejs24-debian13:tag@sha256:..' -> registry/repository/tag/digest."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        registry, repository = ref.split("/", 1)
    else:
        registry, repository = "docker.io", ref if "/" in ref else f"library/{ref}"
    return {"registry": registry, "repository": repository, "tag": tag, "digest": digest}


def image_pinning(ref: str) -> str:
    """digest | tag | latest-implicit | variable."""
    if "$" in ref:
        return "variable"
    parts = split_image(ref)
    if parts["digest"]:
        return "digest"
    if parts["tag"] and parts["tag"] != "latest":
        return "tag"
    return "latest" if parts["tag"] == "latest" else "latest-implicit"


def _logical_lines(text: str):
    """Yield (line_no, instruction, args) joining backslash continuations."""
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.lstrip().startswith("#") and buf:
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.strip().split(None, 1)
        yield start, parts[0].upper(), parts[1] if len(parts) > 1 else ""
        buf = ""
    if buf.strip():
        parts = buf.strip().split(None, 1)
        yield start, parts[0].upper(), parts[1] if len(parts) > 1 else ""


def _subst(value: str, args: dict) -> str:
    def rep(m):
        name = m.group(1) or m.group(2)
        return args.get(name) or m.group(0)
    return re.sub(r"\$\{(\w+)(?::-[^}]*)?\}|\$(\w+)", rep, value)


def parse_dockerfile(text: str, path: str) -> dict:
    args: dict[str, str] = {}
    stages: list[dict] = []
    findings: list[dict] = []
    for line_no, instr, rest in _logical_lines(text):
        if instr == "ARG":
            name, _, default = rest.partition("=")
            args.setdefault(name.strip(), default.strip().strip("'\""))
        elif instr == "FROM":
            tokens = [t for t in rest.split() if not t.startswith("--")]
            platform = next((t.split("=", 1)[1] for t in rest.split() if t.startswith("--platform=")), None)
            image_raw = tokens[0] if tokens else ""
            alias = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else None
            image = _subst(image_raw, args)
            previous = {s["name"] for s in stages if s["name"]}
            from_stage = image in previous
            stages.append({
                "index": len(stages), "name": alias, "line": line_no, "image": image,
                "image_raw": image_raw, "platform": platform, "from_stage": from_stage,
                "pinning": "stage" if from_stage else ("scratch" if image == "scratch" else image_pinning(image)),
                **({} if from_stage or image == "scratch" else split_image(image)),
                "user": None, "run_count": 0,
            })
        elif not stages:
            continue
        elif instr == "USER":
            stages[-1]["user"] = rest.strip()
        elif instr == "RUN":
            stages[-1]["run_count"] += 1
            if PIPE_TO_SHELL.search(rest):
                findings.append({"type": "pipe-to-shell", "stage": stages[-1]["index"], "line": line_no,
                                 "text": rest[:300]})
            if re.search(r"\bnpm (i|install|ci)\b(?!.*--ignore-scripts)", rest):
                findings.append({"type": "npm-install-runs-scripts", "stage": stages[-1]["index"],
                                 "line": line_no, "text": rest[:300]})
        elif instr == "ADD":
            src = [t for t in rest.split() if not t.startswith("--")]
            if src and re.match(r"^https?://", src[0]):
                findings.append({"type": "add-from-url", "stage": stages[-1]["index"], "line": line_no,
                                 "text": rest[:300], "checksum": "--checksum=" in rest})
    final = stages[-1] if stages else None
    external = [s for s in stages if not s["from_stage"] and s["image"] != "scratch"]
    if final is not None and not final["user"]:
        findings.append({"type": "final-stage-runs-as-root", "stage": final["index"],
                         "line": final["line"], "text": "no USER directive in the final stage"})
    elif final is not None and final["user"] in ("root", "0", "0:0"):
        findings.append({"type": "final-stage-runs-as-root", "stage": final["index"],
                         "line": final["line"], "text": f"USER {final['user']}"})
    for s in external:
        if s["pinning"] != "digest":
            findings.append({"type": "base-image-not-digest-pinned", "stage": s["index"], "line": s["line"],
                             "text": s["image"], "pinning": s["pinning"]})
    return {
        "path": path,
        "stages": stages,
        "base_images": [s["image"] for s in external],
        "final_base_image": final["image"] if final and not final["from_stage"] else
                            next((s["image"] for s in reversed(external)), None),
        "final_user": final["user"] if final else None,
        "args": args,
        "findings": findings,
    }


def parse_compose(text: str, path: str) -> dict:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return {"path": path, "error": str(exc), "services": []}
    services = []
    for name, svc in (data.get("services") or {}).items():
        svc = svc or {}
        image = svc.get("image")
        build = svc.get("build")
        services.append({
            "service": name,
            "image": image,
            "pinning": image_pinning(image) if image else None,
            "build": build if isinstance(build, str) else (build or {}).get("context") if build else None,
            "privileged": bool(svc.get("privileged")),
            "user": svc.get("user"),
        })
    return {"path": path, "services": services}


def find_container_files(repo_path: Path, skip_dirs: set[str]) -> dict:
    dockerfiles, composes = [], []
    for p in sorted(Path(repo_path).rglob("*")):
        rel = p.relative_to(repo_path)
        if any(part in skip_dirs for part in rel.parts[:-1]) or not p.is_file():
            continue
        if DOCKERFILE_NAMES.match(p.name):
            dockerfiles.append(rel.as_posix())
        elif COMPOSE_NAMES.match(p.name):
            composes.append(rel.as_posix())
    return {"dockerfiles": dockerfiles, "compose": composes}


def analyse_repo(repo_path: Path, skip_dirs: set[str]) -> dict:
    files = find_container_files(repo_path, skip_dirs)
    return {
        "dockerfiles": [parse_dockerfile((Path(repo_path) / f).read_text(errors="ignore"), f)
                        for f in files["dockerfiles"]],
        "compose": [parse_compose((Path(repo_path) / f).read_text(errors="ignore"), f)
                    for f in files["compose"]],
    }
