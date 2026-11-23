"""artifact-inspector agent: Dockerfiles, the container image and CI/CD workflows.

Writes outputs/<app_id>/artifacts/:
    status.json
    dockerfile_analysis.json   every Dockerfile/Containerfile/compose file: base images, pinning, USER, risky patterns
    ci_inventory.json          workflows, triggers, permissions, deduplicated actions with pin type, risky patterns
    container.json             image ref + digest, how it was chosen, OS, layers, OS vs application packages
    raw/syft-image.cdx.json raw/syft-image.spdx.json raw/trivy-image.cdx.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agents.common import (DEFAULT_OUTPUTS, DEFAULT_WORKSPACE, AgentRun, now_iso, parse_repo_url,
                           read_json, read_run_info, write_json)
from agents.common.tools import docker_status, get_tool_versions

from agents.source_deps.ingest import fetch_repo
from agents.source_deps.manifests import ALWAYS_SKIP, DEFAULT_SKIP

from .dockerfile import analyse_repo
from .image import inspect_image, select_image, summarise_packages
from .workflows import build_ci_inventory

log = logging.getLogger(__name__)

AGENT, FOLDER, STAGE = "artifact-inspector", "artifacts", "discover"


def run_artifact_inspector(repo_url: str, *, run_id: str | None = None, image: str | None = None,
                           build_image: bool = False, skip_container: bool = False,
                           include_all: bool = False, workspace: Path = DEFAULT_WORKSPACE,
                           outputs: Path = DEFAULT_OUTPUTS) -> dict:
    repo = parse_repo_url(repo_url)
    run_info = read_run_info(repo.app_id, outputs)
    run_id = run_id or run_info.get("run_id")
    if not run_id:
        raise RuntimeError("No run_id: run source-deps first (or use python -m agents.discover)")
    with AgentRun(repo.app_id, AGENT, FOLDER, STAGE, run_id, outputs) as status:
        repo_path = Path(workspace) / repo.app_id
        if not (repo_path / ".git").is_dir():
            repo_path = fetch_repo(repo, workspace=workspace).path
        result = _run(repo, repo_path, status, run_info, image=image, build_image=build_image,
                      skip_container=skip_container, include_all=include_all, outputs=outputs)
        for rel, kind in (("dockerfile_analysis.json", "json"), ("ci_inventory.json", "json"),
                          ("container.json", "json"), ("raw/syft-image.cdx.json", "sbom"),
                          ("raw/syft-image.spdx.json", "sbom-spdx"), ("raw/trivy-image.cdx.json", "sbom")):
            status.add_artifact(rel, kind)
        status.done(result["summary"], coverage=result["coverage"])
        return result


def _app_version(app_id: str, outputs: Path, repo_path: Path) -> str | None:
    meta = read_json(Path(outputs) / app_id / "source_deps" / "source_meta.json", {}) or {}
    for p in meta.get("projects", []):
        if p.get("path") == "." and p.get("version"):
            return p["version"]
    try:
        return json.loads((repo_path / "package.json").read_text()).get("version")
    except (OSError, json.JSONDecodeError):
        return None


def _run(repo, repo_path: Path, status: AgentRun, run_info: dict, *, image, build_image,
         skip_container, include_all, outputs) -> dict:
    started = now_iso()
    skip = set(ALWAYS_SKIP) | (set() if include_all else DEFAULT_SKIP)

    # A. Dockerfiles / compose
    docker_files = analyse_repo(repo_path, skip)
    write_json(status.dir / "dockerfile_analysis.json", {**docker_files, "generated_at": now_iso()})

    # B. CI/CD
    ci = build_ci_inventory(repo_path)
    write_json(status.dir / "ci_inventory.json", {**ci, "generated_at": now_iso()})

    # C. Container image
    container: dict = {"inspected": False}
    raw = status.dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    final_dockerfile = next((d for d in docker_files["dockerfiles"] if Path(d["path"]).name in ("Dockerfile", "Containerfile")),
                            docker_files["dockerfiles"][0] if docker_files["dockerfiles"] else None)
    if skip_container:
        container["reason"] = "--skip-container"
        status.warn("Container inspection skipped (--skip-container)")
    else:
        sha = (run_info.get("commit_sha") or "")[:7] or "local"
        sel = select_image(repo_path, repo.app_id, repo.display_name, _app_version(repo.app_id, outputs, repo_path),
                           docker_files["compose"], sha, image=image, build=build_image,
                           dockerfile=final_dockerfile["path"] if final_dockerfile else None,
                           docker_ok=docker_status()["daemon"])
        container["selection"] = sel
        if not sel["ref"]:
            container["reason"] = sel["reason"]
            status.warn(f"No container image inspected: {sel['reason']}")
        else:
            res = inspect_image(sel, raw, repo_path)
            for w in res["warnings"]:
                status.warn(w)
            pk = summarise_packages(raw)
            container.update({
                "inspected": pk["counts"]["total"] > 0,
                "ref": res["ref"], "digest": res["digest"], "scanned_ref": res["scanned_ref"],
                "mode": res["mode"], "layers": res.get("layers"), "image_os": res.get("os"),
                "architecture": res.get("architecture"), "created": res.get("created"),
                "user": res.get("user"), "labels": res.get("labels"),
                "os": pk["os"], "counts": pk["counts"],
                "declared_base_image": final_dockerfile["final_base_image"] if final_dockerfile else None,
                "declared_base_pinning": next((s["pinning"] for s in reversed(final_dockerfile["stages"])
                                               if not s["from_stage"]), None) if final_dockerfile else None,
                "base_image_note": "declared in the repo's Dockerfile; the published image is assumed to be built from it"
                                   if sel.get("method") == "published" else None,
                "tool_runs": res["tool_runs"],
                "packages": pk["packages"],
            })
            if not container["inspected"]:
                container["reason"] = "image scan produced no packages (see warnings)"
    write_json(status.dir / "container.json", {**container, "generated_at": now_iso()})

    cs = ci["summary"]
    summary = {
        "dockerfiles": len(docker_files["dockerfiles"]),
        "compose_files": len(docker_files["compose"]),
        "image": container.get("ref") or "not inspected",
        "image_packages": (container.get("counts") or {}).get("total", 0),
        "image_os_packages": (container.get("counts") or {}).get("os", 0),
        "workflows": cs["workflows"],
        "unique_actions": cs["unique_actions"],
        "actions_not_sha_pinned": cs["not_sha_pinned"],
        "ci_patterns": cs["risky_patterns"],
    }
    coverage = {
        "container": {"inspected": container.get("inspected", False), "reason": container.get("reason"),
                      "mode": container.get("mode"), "per_tool": (container.get("counts") or {}).get("per_tool")},
        "ci": {"workflows_parsed": cs["workflows"], "other_ci_detected_not_parsed": [o["path"] for o in ci["other_ci"]]},
        "tool_versions": {k: v for k, v in get_tool_versions().items() if k in ("syft", "trivy", "docker", "docker_daemon")},
        "started_at": started,
    }
    return {"summary": summary, "coverage": coverage, "container": container, "ci": ci,
            "dockerfiles": docker_files}
