"""Run the three Discover-stage agents in order with a shared run_id.

    python -m agents.discover --repo <url> [--ref R] [--refresh] [--image REF | --build-image]
                              [--include-all] [--skip-container] [-v]
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

from agents.artifact_inspector import run_artifact_inspector
from agents.common import DEFAULT_OUTPUTS, DEFAULT_WORKSPACE, parse_repo_url, read_json, update_run_info
from agents.common.cli import add_common_args, guarded_main
from agents.common.contract import now_iso
from agents.inventory import run_inventory
from agents.source_deps import run_source_deps, start_run

log = logging.getLogger(__name__)


def run_discover(repo_url: str, ref: str | None = None, *, refresh: bool = False, image: str | None = None,
                 build_image: bool = False, include_all: bool = False, skip_container: bool = False,
                 workspace: Path = DEFAULT_WORKSPACE, outputs: Path = DEFAULT_OUTPUTS) -> dict:
    """Returns {app_id, run_id, results: {agent: result | None}, errors: {agent: msg}}."""
    app_id, run_id = start_run(repo_url, ref, outputs)
    log.info("Discover run %s for %s", run_id, app_id)
    results, errors = {}, {}

    # source-deps is required by everything else: let its exception propagate.
    results["source-deps"] = run_source_deps(repo_url, ref, refresh=refresh, include_all=include_all,
                                             run_id=run_id, workspace=workspace, outputs=outputs)
    try:
        results["artifact-inspector"] = run_artifact_inspector(
            repo_url, run_id=run_id, image=image, build_image=build_image, skip_container=skip_container,
            include_all=include_all, workspace=workspace, outputs=outputs)
    except Exception as exc:  # noqa: BLE001 - inventory can still merge source data
        errors["artifact-inspector"] = f"{type(exc).__name__}: {exc}"
        log.error("artifact-inspector failed: %s", exc)
    results["inventory"] = run_inventory(repo_url, run_id=run_id, outputs=outputs)
    update_run_info(app_id, outputs, finished_at=now_iso())
    return {"app_id": app_id, "run_id": run_id, "results": results, "errors": errors}


# ------------------------------------------------------------------ summary
def _table(rows: list[list], headers: list[str]) -> str:
    cols = [headers] + [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cols) for i in range(len(headers))]
    line = lambda r: "  " + "  ".join(c.ljust(w) for c, w in zip(r, widths))  # noqa: E731
    return "\n".join([line(headers), "  " + "  ".join("-" * w for w in widths)] + [line(r) for r in cols[1:]])


def print_summary(res: dict, outputs: Path = DEFAULT_OUTPUTS) -> None:
    app_id = res["app_id"]
    base = Path(outputs) / app_id
    run = read_json(base / "run.json", {})
    inv = res["results"]["inventory"]
    s, cov, g = inv["summary"], inv["coverage"], inv["graph_stats"]
    comps = read_json(base / "inventory" / "components.json", [])
    src = [c for c in comps if c["relationship"] in ("direct", "transitive")]
    print()
    print(f"Discover complete: {run.get('display_name')} ({app_id})")
    print(f"  repo      {run.get('repo_url')} @ {(run.get('commit_sha') or '')[:12]} ({run.get('commit_date')})")
    print(f"  run_id    {res['run_id']}")
    tv = read_json(base / "source_deps" / "source_meta.json", {}).get("tool_versions", {})
    print("  tools     " + ", ".join(f"{k} {v}" for k, v in tv.items() if v and k in
                                    ("syft", "trivy", "cdxgen", "npm", "node", "go", "pip", "docker")))
    print("\nComponents (unique purls, reachable from project roots)")
    by_eco = Counter(c["ecosystem"] for c in src)
    print(_table([[eco, n, sum(1 for c in src if c["ecosystem"] == eco and c["relationship"] == "direct"),
                   sum(1 for c in src if c["ecosystem"] == eco and c["relationship"] == "transitive"),
                   sum(1 for c in src if c["ecosystem"] == eco and c["scope"] == "dev")]
                  for eco, n in sorted(by_eco.items())] +
                 [["TOTAL", len(src), s["direct"], s["transitive"], s["dev_only"]]],
                 ["ecosystem", "unique", "direct", "transitive", "dev-only"]))
    print(f"\nGraph     {g['nodes']} nodes, {g['edges']} edges, {g['roots']} roots, max depth {g['max_depth']}")
    art = res["results"].get("artifact-inspector")
    if art:
        c = art["container"]
        if c.get("inspected"):
            print(f"Container {c['ref']}  digest {c.get('digest')}")
            print(f"          OS {(c.get('os') or {}).get('name')} {(c.get('os') or {}).get('version')}, "
                  f"base (declared) {c.get('declared_base_image')}, {c.get('layers')} layers, "
                  f"{c['counts']['total']} packages ({c['counts']['os']} OS / {c['counts']['application']} application)")
        else:
            print(f"Container not inspected: {c.get('reason')}")
        cs = art["ci"]["summary"]
        print(f"CI/CD     {cs['workflows']} workflows, {cs['action_references']} action references, "
              f"{cs['unique_actions']} unique actions: {cs['pinned_sha']} SHA-pinned, {cs['pinned_tag']} tag, "
              f"{cs['pinned_branch']} branch; {cs['workflows_without_permissions']} workflows without `permissions:`; "
              f"{cs['risky_patterns']} pattern facts")
    print("\nCoverage")
    print(_table([[t, d["unique_purls"], d["only_this_tool"]] for t, d in cov["per_tool"].items() if d["unique_purls"]],
                 ["source", "unique purls", "only this source"]))
    for l in cov["lockfiles"]:
        print(f"  lockfile {l['lockfile']}: {l['in_inventory']}/{l['unique_packages']} packages in inventory ({l['percent']}%)")
    for l in cov["npm_ls"]:
        print(f"  npm ls {l['project']}: {l['in_inventory']}/{l['packages']} ({l['percent']}%)")
    print(f"  unreachable nodes: {cov['unreachable_nodes']['count']}   unresolved edges: {cov['unresolved_edges']['count']} "
          f"{cov['unresolved_edges']['by_reason']}")
    for e in cov["ecosystems"]:
        print(f"  ecosystem {e['ecosystem']:<8} {e['resolution']:<14} {'; '.join(e['reasons'])[:150]}")
    v = cov["sbom_validation"]
    print(f"  CycloneDX valid: {v['cyclonedx']['valid']} ({v['cyclonedx']['validator']})")
    print(f"  SPDX valid: {v['spdx']['valid']} ({v['spdx']['validator']})")
    warnings = []
    for agent, folder in (("source-deps", "source_deps"), ("artifact-inspector", "artifacts"), ("inventory", "inventory")):
        st = read_json(base / folder / "status.json", {}) or {}
        warnings += [f"[{agent}] {w}" for w in st.get("warnings", [])]
    for agent, err in res["errors"].items():
        warnings.append(f"[{agent}] FAILED: {err}")
    print(f"\nWarnings ({len(warnings)})")
    for w in warnings:
        print(f"  - {w}")
    print("\nOutputs")
    for folder in ("source_deps", "artifacts", "inventory"):
        st = read_json(base / folder / "status.json", {}) or {}
        print(f"  {folder}/  [{st.get('state')}] " + ", ".join(a["name"] for a in st.get("artifacts", [])))
    print(f"  (all under {base})")


# ---------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m agents.discover",
                                description="Discover stage: source-deps -> artifact-inspector -> inventory.")
    add_common_args(p)
    p.add_argument("--ref", help="Branch, tag or commit SHA")
    p.add_argument("--refresh", action="store_true", help="Delete the clone and clone again")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--image", help="Container image to inspect (default: the app's published image)")
    g.add_argument("--build-image", action="store_true", help="Build the image from the repo's Dockerfile")
    p.add_argument("--include-all", action="store_true", help="Also scan test/, examples/, docs/, vendor/ ...")
    p.add_argument("--skip-container", action="store_true", help="Skip container image inspection")
    return p


def _main(args: argparse.Namespace) -> int:
    parse_repo_url(args.repo)
    res = run_discover(args.repo, args.ref, refresh=args.refresh, image=args.image, build_image=args.build_image,
                       include_all=args.include_all, skip_container=args.skip_container)
    print_summary(res)
    return 1 if res["errors"] else 0


def main(argv: list[str] | None = None) -> int:
    return guarded_main(_main, build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
