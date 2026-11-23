"""python -m agents.source_deps --repo <url> [--ref R] [--refresh] [--include-all]"""

from __future__ import annotations

import argparse
import sys

from agents.common.cli import add_common_args, guarded_main

from .pipeline import run_source_deps


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m agents.source_deps",
                                description="Source dependencies: lockfiles, native resolvers, Syft/cdxgen/Trivy.")
    add_common_args(p)
    p.add_argument("--ref", help="Branch, tag or commit SHA")
    p.add_argument("--refresh", action="store_true", help="Delete the clone and clone again")
    p.add_argument("--include-all", action="store_true",
                   help="Also scan test/, examples/, docs/, vendor/ ... (skipped by default)")
    return p


def _main(args: argparse.Namespace) -> int:
    meta = run_source_deps(args.repo, args.ref, refresh=args.refresh, include_all=args.include_all)
    s = meta["summary"]
    print(f"\nsource-deps done: {meta['app_id']} @ {meta['repo']['commit_sha'][:12]}")
    for k, v in s.items():
        print(f"  {k:<20} {v}")
    for w in meta["warnings"]:
        print(f"  WARNING: {w}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return guarded_main(_main, build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
