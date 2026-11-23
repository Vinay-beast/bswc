"""CLI: python -m agents.discovery.cli --repo <url> [--ref <branch/tag/sha>] [--refresh]"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .pipeline import run_discovery
from .tools import ToolError


def _rel(path: str) -> str:
    try:
        return str(Path(path).relative_to(Path.cwd()))
    except ValueError:
        return path


def print_summary(meta: dict) -> None:
    repo = meta["repo"]
    print()
    print(f"Discovery complete: {meta['app_name']}")
    print(f"  repo:    {repo['url']} @ {repo['commit_sha'][:12]}")
    tv = meta["tool_versions"]
    print(f"  tools:   syft {tv['syft']}, npm {tv['npm']}, node {tv['node']}, git {tv['git']}")
    print(f"  manifests found ({len(meta['manifests'])}):")
    for m in meta["manifests"]:
        print(f"    - {m['path']:<40} {m['ecosystem']:<8} {m['kind']:<9} {m['origin']}")
    failed = [l for l in meta["npm_lockfiles"] if l["status"] == "failed"]
    for l in failed:
        print(f"  WARNING: lockfile generation failed for {l['manifest']}: {l['error']}")
    eco = ", ".join(f"{k}={v}" for k, v in meta["components_by_ecosystem"].items())
    print(f"  components: {meta['component_count']} ({eco})")
    print("  outputs:")
    for key, path in meta["outputs"].items():
        print(f"    {key:<11} {_rel(path)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.discovery.cli",
        description="Clone a repository and generate a CycloneDX SBOM with Syft.",
    )
    parser.add_argument("--repo", required=True, help="Git repository URL")
    parser.add_argument("--ref", help="Branch, tag or commit SHA to check out")
    parser.add_argument("--refresh", action="store_true",
                        help="Delete any existing clone in workspace/ and clone again")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        meta = run_discovery(args.repo, args.ref, refresh=args.refresh)
    except (ToolError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print_summary(meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
