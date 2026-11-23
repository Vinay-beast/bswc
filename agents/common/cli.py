"""Shared CLI plumbing: logging setup and catch-all error handling."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback
from typing import Callable


def add_common_args(parser: argparse.ArgumentParser, *, repo_required: bool = True) -> None:
    parser.add_argument("--repo", required=repo_required, help="Git repository URL (https, ssh or .git)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging and full tracebacks")


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def guarded_main(fn: Callable[[argparse.Namespace], int], args: argparse.Namespace) -> int:
    """Run `fn(args)`, turning ANY exception into a short message and exit code 1.

    Agents mark their own status.json as failed (AgentRun's context manager)
    before the exception reaches this point.
    """
    setup_logging(getattr(args, "verbose", False))
    try:
        return fn(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - this is the top-level boundary
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
        print(f"error: {type(exc).__name__}: {first}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        else:
            print("(run with -v for the full traceback)", file=sys.stderr)
        return 1
