#!/usr/bin/env sh
# Install a pinned Syft release to ~/.local/bin using Anchore's official install script.
# Usage: scripts/install_syft.sh [version]   (default: the pinned version below)
set -eu

SYFT_VERSION="${1:-v1.18.1}"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "$BIN_DIR"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b "$BIN_DIR" "$SYFT_VERSION"

"$BIN_DIR/syft" version
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: add $BIN_DIR to your PATH (the agent also checks it automatically)." ;;
esac
