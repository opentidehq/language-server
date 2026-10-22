#!/usr/bin/env bash
# CI-only Kusto.Language syntax oracle (.github/workflows/oracle.yml).
# Optional locally: without the .NET SDK it skips unless
# OPENTIDE_ORACLE_REQUIRED=1, which CI sets.
# Do not ship Kusto.Language in release artifacts.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

# The oracle project is the only place Kusto.Language may appear. No Rust,
# npm, or Python manifest that feeds a release may depend on it.
manifests=("$root/Cargo.lock" "$root/pyproject.toml" "$root"/crates/*/Cargo.toml "$root"/packages/*/package.json)
if grep -IilE 'kusto[._-]language' "${manifests[@]}"; then
  echo "Kusto.Language is a dependency of a shipped manifest"
  exit 1
fi

if ! command -v dotnet >/dev/null 2>&1; then
  if [[ "${OPENTIDE_ORACLE_REQUIRED:-}" == "1" ]]; then
    echo "dotnet not available and OPENTIDE_ORACLE_REQUIRED=1"
    exit 1
  fi
  echo "dotnet not available; skipping the Kusto.Language oracle (CI runs it)"
  exit 0
fi

export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
python3 "$root/scripts/kusto_oracle.py"
