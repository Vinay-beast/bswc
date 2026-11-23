"""python -m agents.inventory --repo <url> [--run-id ID]"""

from __future__ import annotations

import argparse
import sys

from agents.common.cli import add_common_args, guarded_main

from .pipeline import run_inventory


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m agents.inventory",
                                description="Merge source-deps and artifact-inspector outputs into the inventory.")
    add_common_args(p)
    p.add_argument("--run-id", help="Attach to an existing run (default: run.json's run_id)")
    return p


def _main(args: argparse.Namespace) -> int:
    res = run_inventory(args.repo, run_id=args.run_id)
    print("\ninventory done")
    for k, v in res["summary"].items():
        print(f"  {k:<24} {v}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return guarded_main(_main, build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
