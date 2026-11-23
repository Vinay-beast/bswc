#!/usr/bin/env bash
# Print a version table of every tool the Discover stage can use.
# Pinned tools are looked up in ./tools first, then on PATH. Never fails.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$ROOT/tools/bin:$ROOT/tools/node_modules/.bin:$PATH:$HOME/.local/bin"

row() { printf "%-10s %-10s %-34s %s\n" "$1" "$2" "$3" "$4"; }
ver() { # name role pinned command...
  local name="$1" role="$2" pinned="$3"; shift 3
  local path; path="$(command -v "$name" 2>/dev/null)"
  if [[ -z "$path" ]]; then row "$name" "$role" "MISSING" "pinned: $pinned"; return; fi
  local v; v="$("$@" 2>&1 | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  row "$name" "$role" "${v:-unknown}" "${path/#$ROOT\//}  (pinned: $pinned)"
}

row TOOL ROLE VERSION PATH
ver syft    required 1.57.2 syft version
ver trivy   required 0.76.2 trivy --version
ver cdxgen  required 12.9.3 cdxgen --version
ver git     required -      git --version
ver node    required -      node --version
ver npm     required -      npm --version
ver go      optional -      go version
ver java    optional -      java -version
ver mvn     optional -      mvn --version
ver gradle  optional -      gradle --version
ver uv      optional -      uv --version
ver python3 optional -      python3 --version
if python3 -m pip --version >/dev/null 2>&1; then
  row pip optional "$(python3 -m pip --version | awk '{print $2}')" "python3 -m pip"
else
  row pip optional MISSING "python3 -m pip"
fi
if command -v docker >/dev/null 2>&1; then
  if server="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"; then
    row docker optional "$(docker version --format '{{.Client.Version}}')" "daemon running (server $server)"
  else
    row docker optional "$(docker version --format '{{.Client.Version}}' 2>/dev/null)" "DAEMON NOT RUNNING - registry scanning is used instead"
  fi
else
  row docker optional MISSING "registry scanning is used instead"
fi
