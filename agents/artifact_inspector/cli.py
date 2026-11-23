"""python -m agents.artifact_inspector --repo <url> [--image REF | --build-image] [--skip-container]"""

from __future__ import annotations

import argparse
import sys

from agents.common.cli import add_common_args, guarded_main

from .pipeline import run_artifact_inspector


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m agents.artifact_inspector",
                                description="Dockerfiles, container image and CI/CD workflow inspection.")
    add_common_args(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--image", help="Image reference to inspect (default: the app's published image)")
    g.add_argument("--build-image", action="store_true",
                   help="Build the image locally from the repo's Dockerfile (runs its RUN steps in Docker)")
    p.add_argument("--skip-container", action="store_true", help="Do not inspect any container image")
    p.add_argument("--include-all", action="store_true", help="Also look in test/, examples/, docs/ ...")
    p.add_argument("--run-id", help="Attach to an existing run (default: run.json's run_id)")
    return p


def _main(args: argparse.Namespace) -> int:
    res = run_artifact_inspector(args.repo, run_id=args.run_id, image=args.image, build_image=args.build_image,
                                 skip_container=args.skip_container, include_all=args.include_all)
    print("\nartifact-inspector done")
    for k, v in res["summary"].items():
        print(f"  {k:<24} {v}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return guarded_main(_main, build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
