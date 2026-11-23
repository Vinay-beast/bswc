"""inventory agent: the merged, deduplicated single source of truth for later stages."""

from .pipeline import run_inventory

__all__ = ["run_inventory"]
