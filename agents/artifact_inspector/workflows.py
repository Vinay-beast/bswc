"""CI/CD inventory: GitHub Actions workflows (parsed) + other CI systems (detected).

Facts only - nothing is scored here. Every `uses:` reference is classified by
how it is pinned (full commit SHA / tag / branch / local / docker) and by
publisher (GitHub-owned vs third-party). Tag-vs-branch is resolved with
`git ls-remote` when possible and otherwise marked as a heuristic.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from agents.common.purl import build_purl
from agents.common.tools import ToolError, run

from .dockerfile import image_pinning

log = logging.getLogger(__name__)

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHORT_SHA = re.compile(r"^[0-9a-f]{7,39}$")
SEMVER_TAG = re.compile(r"^v?\d+(\.\d+){0,2}([-+.][0-9A-Za-z.-]+)?$")
BRANCH_NAMES = {"main", "master", "develop", "dev", "trunk", "release", "stable", "latest", "next", "nightly"}
GITHUB_OWNED = {"actions", "github"}
PR_TRIGGERS = {"pull_request", "pull_request_target"}
OTHER_CI = {
    ".gitlab-ci.yml": "gitlab-ci", "Jenkinsfile": "jenkins", "azure-pipelines.yml": "azure-pipelines",
    ".circleci/config.yml": "circleci", "bitbucket-pipelines.yml": "bitbucket-pipelines",
    ".travis.yml": "travis-ci", ".drone.yml": "drone", "buildkite.yml": "buildkite",
    ".buildkite/pipeline.yml": "buildkite", "cloudbuild.yaml": "google-cloud-build",
}
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(-?\w+\s+)*(ba|z|da|k)?sh\b")
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
USES_COMMENT = re.compile(r"""uses:\s*['"]?([^\s'"#]+)['"]?\s*#\s*(\S+)""")
PR_HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref")


def parse_uses(uses: str) -> dict:
    """Classify one `uses:` value (pin type, publisher, owner/repo/path/ref)."""
    uses = uses.strip()
    if uses.startswith("./") or uses.startswith("../"):
        return {"uses": uses, "kind": "local", "pin_type": "local", "publisher": "local",
                "owner": None, "repo": None, "path": uses, "ref": None, "action": uses}
    if uses.startswith("docker://"):
        image = uses[len("docker://"):]
        return {"uses": uses, "kind": "docker", "pin_type": "docker", "image_pinning": image_pinning(image),
                "publisher": "docker", "owner": None, "repo": None, "path": None, "ref": None,
                "action": uses, "image": image}
    target, _, ref = uses.partition("@")
    parts = target.split("/")
    owner, repo = (parts + [None, None])[:2]
    path = "/".join(parts[2:]) or None
    kind = "reusable-workflow" if path and re.search(r"\.ya?ml$", path) else "action"
    if FULL_SHA.match(ref or ""):
        pin = "sha"
    elif not ref:
        pin = "none"
    else:
        pin = "unresolved"                 # tag or branch, decided later
    return {"uses": uses, "kind": kind, "pin_type": pin,
            "publisher": "github" if (owner or "").lower() in GITHUB_OWNED else "third-party",
            "owner": owner, "repo": repo, "path": path, "ref": ref or None,
            "action": f"{owner}/{repo}" + (f"/{path}" if path else "")}


def classify_ref_heuristic(ref: str) -> str:
    if SHORT_SHA.match(ref):
        return "short-sha"
    if ref in BRANCH_NAMES or ref.startswith(("release/", "releases/", "feature/")):
        return "branch"
    if SEMVER_TAG.match(ref):
        return "tag"
    return "tag"                           # most action refs are tags; marked as heuristic


def resolve_refs(refs: set[tuple[str, str, str]], online: bool = True) -> dict:
    """{(owner, repo, ref): (pin_type, source)} using `git ls-remote` (tags and heads)."""
    out = {}

    def one(key):
        owner, repo, ref = key
        if online:
            try:
                res = run(["git", "ls-remote", "--tags", "--heads", f"https://github.com/{owner}/{repo}",
                           f"refs/tags/{ref}", f"refs/heads/{ref}"], timeout=30,
                          env={"GIT_TERMINAL_PROMPT": "0"})
                names = {l.split("\t", 1)[1] for l in res.stdout.splitlines() if "\t" in l}
                if any(n.startswith(f"refs/tags/{ref}") for n in names):
                    return key, ("tag", "git ls-remote")
                if f"refs/heads/{ref}" in names:
                    return key, ("branch", "git ls-remote")
            except ToolError as exc:
                log.debug("ls-remote failed for %s/%s: %s", owner, repo, exc)
        return key, (classify_ref_heuristic(ref), "heuristic")

    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, val in pool.map(one, sorted(refs)):
            out[key] = val
    return out


def _triggers(on) -> list[str]:
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(t) for t in on]
    if isinstance(on, dict):
        return [str(k) for k in on]
    return []


def _container_images(job: dict) -> list[dict]:
    images = []
    c = job.get("container")
    if c:
        img = c if isinstance(c, str) else c.get("image")
        if img:
            images.append({"role": "container", "image": img, "pinning": image_pinning(img)})
    for name, svc in (job.get("services") or {}).items():
        img = svc if isinstance(svc, str) else (svc or {}).get("image")
        if img:
            images.append({"role": f"service:{name}", "image": img, "pinning": image_pinning(img)})
    return images


def parse_workflow(text: str, path: str) -> dict:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return {"path": path, "error": f"YAML error: {exc}", "jobs": [], "uses": [], "patterns": []}
    comments = {m.group(1): m.group(2) for m in USES_COMMENT.finditer(text)}
    on = data.get("on", data.get(True))           # PyYAML reads the key `on` as boolean True
    triggers = _triggers(on)
    pr_triggered = bool(PR_TRIGGERS & set(triggers))
    wf = {
        "path": path, "name": data.get("name"), "triggers": triggers,
        "permissions": data.get("permissions"),
        "permissions_set": "permissions" in data,
        "jobs": [], "uses": [], "images": [], "patterns": [],
    }
    for job_id, job in (data.get("jobs") or {}).items():
        job = job or {}
        cond = job.get("if")
        jinfo = {"id": job_id, "name": job.get("name"), "runs_on": job.get("runs-on"), "if": cond,
                 "permissions": job.get("permissions"), "permissions_set": "permissions" in job,
                 "uses": [], "images": _container_images(job), "secrets": []}
        if job.get("uses"):                       # reusable workflow call
            jinfo["uses"].append({**parse_uses(str(job["uses"])), "job": job_id, "step": None,
                                  "ref_comment": comments.get(str(job["uses"]))})
        checkout_pr_head = False
        for idx, step in enumerate(job.get("steps") or []):
            step = step or {}
            if step.get("uses"):
                u = parse_uses(str(step["uses"]))
                jinfo["uses"].append({**u, "job": job_id, "step": step.get("name") or idx,
                                      "ref_comment": comments.get(str(step["uses"]))})
                if u.get("action") == "actions/checkout" and PR_HEAD_REF.search(str(step.get("with") or "")):
                    checkout_pr_head = True
                if u["kind"] == "docker":
                    jinfo["images"].append({"role": "step", "image": u["image"], "pinning": u["image_pinning"]})
            run_text = str(step.get("run") or "")
            if run_text and PIPE_TO_SHELL.search(run_text):
                wf["patterns"].append({"type": "pipe-to-shell", "job": job_id, "job_if": cond,
                                       "step": step.get("name") or idx,
                                       "text": PIPE_TO_SHELL.search(run_text).group(0)[:200]})
            secrets = sorted(set(SECRET_REF.findall(str(step))))
            if secrets:
                jinfo["secrets"] += [s for s in secrets if s not in jinfo["secrets"]]
        secrets_job = sorted(set(SECRET_REF.findall(str({k: v for k, v in job.items() if k != "steps"}))))
        jinfo["secrets"] += [s for s in secrets_job if s not in jinfo["secrets"]]
        if "pull_request_target" in triggers and checkout_pr_head:
            wf["patterns"].append({"type": "pull-request-target-checkout-head", "job": job_id, "job_if": cond,
                                   "text": "pull_request_target with actions/checkout of the PR head"})
        if pr_triggered and jinfo["secrets"]:
            wf["patterns"].append({"type": "secrets-in-pr-workflow", "job": job_id, "job_if": cond,
                                   "text": f"secrets used on {', '.join(sorted(PR_TRIGGERS & set(triggers)))}: "
                                           + ", ".join(jinfo["secrets"])})
        wf["jobs"].append(jinfo)
        wf["uses"] += jinfo["uses"]
        wf["images"] += [{**i, "job": job_id} for i in jinfo["images"]]
    if not wf["permissions_set"]:
        unset = [j["id"] for j in wf["jobs"] if not j["permissions_set"]]
        if unset:
            wf["patterns"].append({"type": "default-token-permissions", "job": ", ".join(unset),
                                   "text": "no `permissions:` at workflow level or in these jobs"})
    return wf


def build_ci_inventory(repo_path: Path, online: bool = True) -> dict:
    repo_path = Path(repo_path)
    wf_dir = repo_path / ".github" / "workflows"
    workflows = [parse_workflow(p.read_text(errors="ignore"), p.relative_to(repo_path).as_posix())
                 for p in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))] if wf_dir.is_dir() else []
    other = [{"path": rel, "system": sysname, "parsed": False}
             for rel, sysname in OTHER_CI.items() if (repo_path / rel).is_file()]

    to_resolve = {(u["owner"], u["repo"], u["ref"]) for wf in workflows for u in wf["uses"]
                  if u["pin_type"] == "unresolved" and u["owner"] and u["repo"]}
    resolved = resolve_refs(to_resolve, online) if to_resolve else {}
    actions: dict[str, dict] = {}
    for wf in workflows:
        for u in wf["uses"]:
            if u["pin_type"] == "unresolved":
                u["pin_type"], u["pin_source"] = resolved.get((u["owner"], u["repo"], u["ref"]), ("tag", "heuristic"))
            else:
                u.setdefault("pin_source", "syntax")
            key = u["uses"]
            entry = actions.setdefault(key, {
                "uses": key, "action": u["action"], "ref": u["ref"], "kind": u["kind"],
                "pin_type": u["pin_type"], "pin_source": u["pin_source"], "publisher": u["publisher"],
                "ref_comment": u.get("ref_comment"),
                "purl": build_purl("github", u["repo"], u["ref"], u["owner"]) if u["owner"] and u["repo"] else None,
                "used_in": []})
            ref = {"workflow": wf["path"], "job": u["job"]}
            if ref not in entry["used_in"]:
                entry["used_in"].append(ref)
    action_list = sorted(actions.values(), key=lambda a: a["uses"])
    pins = {}
    for a in action_list:
        pins[a["pin_type"]] = pins.get(a["pin_type"], 0) + 1
    patterns = [{**p, "workflow": wf["path"]} for wf in workflows for p in wf["patterns"]]
    images = [{**i, "workflow": wf["path"]} for wf in workflows for i in wf["images"]]
    return {
        "workflows": [{k: v for k, v in wf.items() if k != "uses"} | {"uses_count": len(wf["uses"])}
                      for wf in workflows],
        "actions": action_list,
        "images": images,
        "other_ci": other,
        "patterns": patterns,
        "summary": {
            "workflows": len(workflows),
            "action_references": sum(len(wf["uses"]) for wf in workflows),
            "unique_actions": len(action_list),
            "pinned_sha": pins.get("sha", 0),
            "pinned_tag": pins.get("tag", 0),
            "pinned_branch": pins.get("branch", 0),
            "pinned_other": sum(v for k, v in pins.items() if k not in ("sha", "tag", "branch")),
            "not_sha_pinned": sum(1 for a in action_list if a["pin_type"] not in ("sha", "local")),
            "third_party_actions": sum(1 for a in action_list if a["publisher"] == "third-party"),
            "workflows_without_permissions": sum(1 for wf in workflows if not wf["permissions_set"]),
            "risky_patterns": len(patterns),
            "other_ci_systems": len(other),
        },
    }
