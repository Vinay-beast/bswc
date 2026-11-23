"""Backward-compatible alias: `python -m agents.discovery.cli` runs `python -m agents.discover`."""

import sys

from agents.discover.orchestrator import main

if __name__ == "__main__":
    print("note: agents.discovery is deprecated; use `python -m agents.discover`", file=sys.stderr)
    sys.exit(main())
