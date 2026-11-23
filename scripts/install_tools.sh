#!/usr/bin/env bash
# Install the pinned Discover-stage tools into ./tools (repo-local, git-ignored).
#
#   tools/bin/syft     Syft   - release tarball, SHA-256 verified against the release checksums.txt
#   tools/bin/trivy    Trivy  - release tarball, SHA-256 verified against the release checksums.txt
#   tools/node_modules/.bin/cdxgen   OWASP cdxgen via `npm install --ignore-scripts` (never global)
#
# Supported: macOS and Linux, amd64 and arm64. Re-running is idempotent.
# Usage: scripts/install_tools.sh [--force]
set -euo pipefail

SYFT_VERSION="1.57.2"
TRIVY_VERSION="0.76.2"
CDXGEN_VERSION="12.9.3"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
BIN="$TOOLS/bin"
FORCE="${1:-}"
mkdir -p "$BIN"

case "$(uname -s)" in
  Darwin) OS=darwin; TRIVY_OS=macOS ;;
  Linux)  OS=linux;  TRIVY_OS=Linux ;;
  *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64; TRIVY_ARCH=64bit ;;
  arm64|aarch64) ARCH=arm64; TRIVY_ARCH=ARM64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# install_release <name> <version> <base-url> <tarball> <checksums-file>
install_release() {
  local name="$1" version="$2" base="$3" tarball="$4" sums="$5"
  if [[ -x "$BIN/$name" && "$FORCE" != "--force" ]] && "$BIN/$name" --version 2>/dev/null | grep -q "$version"; then
    echo "$name $version already installed"
    return
  fi
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  echo "Downloading $name $version ($tarball)"
  curl -sSfL -o "$tmp/$tarball" "$base/$tarball"
  curl -sSfL -o "$tmp/$sums" "$base/$sums"
  local expected actual
  expected="$(awk -v f="$tarball" '$2 == f || $2 == "*"f {print $1}' "$tmp/$sums")"
  actual="$(sha256 "$tmp/$tarball")"
  if [[ -z "$expected" || "$expected" != "$actual" ]]; then
    echo "Checksum mismatch for $tarball: expected '$expected', got '$actual'" >&2
    exit 1
  fi
  echo "  sha256 OK: $actual"
  tar -xzf "$tmp/$tarball" -C "$tmp" "$name"
  install -m 0755 "$tmp/$name" "$BIN/$name"
}

install_release syft "$SYFT_VERSION" \
  "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION" \
  "syft_${SYFT_VERSION}_${OS}_${ARCH}.tar.gz" "syft_${SYFT_VERSION}_checksums.txt"

install_release trivy "$TRIVY_VERSION" \
  "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION" \
  "trivy_${TRIVY_VERSION}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt"

# cdxgen: local npm install, lifecycle scripts disabled. cdxgen is pure JS, so
# --ignore-scripts only skips optional native helpers' postinstall steps.
if [[ -x "$TOOLS/node_modules/.bin/cdxgen" && "$FORCE" != "--force" ]] \
   && [[ "$("$TOOLS/node_modules/.bin/cdxgen" --version 2>/dev/null | tail -1)" == *"$CDXGEN_VERSION"* ]]; then
  echo "cdxgen $CDXGEN_VERSION already installed"
else
  command -v npm >/dev/null || { echo "npm is required to install cdxgen" >&2; exit 1; }
  echo "Installing @cyclonedx/cdxgen@$CDXGEN_VERSION into tools/node_modules (--ignore-scripts)"
  [[ -f "$TOOLS/package.json" ]] || echo '{"name":"guardian-tools","private":true}' > "$TOOLS/package.json"
  npm install --prefix "$TOOLS" --ignore-scripts --no-audit --no-fund --save-exact \
    "@cyclonedx/cdxgen@$CDXGEN_VERSION" >/dev/null
fi

echo
"$ROOT/scripts/check_tools.sh"
