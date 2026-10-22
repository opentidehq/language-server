#!/usr/bin/env bash
# License scan: release artifacts must not contain Microsoft Kusto.Language.
# Usage: check-no-kusto.sh <file-or-dir>... (wheels, zips and tarballs are unpacked)
set -euo pipefail
if [[ $# -eq 0 ]]; then
  echo "usage: $0 <file-or-dir>..."
  exit 2
fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

n=0
while IFS= read -r -d '' file; do
  n=$((n + 1))
  case "$file" in
    *.whl | *.zip | *.nupkg | *.vsix)
      mkdir -p "$scratch/$n" && unzip -q "$file" -d "$scratch/$n" ;;
    *.tar.gz | *.tgz)
      mkdir -p "$scratch/$n" && tar -xzf "$file" -C "$scratch/$n" ;;
  esac
done < <(find "$@" -type f -print0)

hits="$(
  {
    find "$@" "$scratch" -type f -iname '*kusto*'
    grep -RailE 'kusto[._-]language' "$@" "$scratch" || true
  } | sort -u
)"
if [[ -n "$hits" ]]; then
  echo "$hits"
  echo "Kusto.Language found in release artifacts"
  exit 1
fi
echo "no Kusto.Language in $n artifact files"
