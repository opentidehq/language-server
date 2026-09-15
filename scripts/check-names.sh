#!/usr/bin/env bash
# Names: opentide, never otide. No opentide-sql.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
# Flag real identifiers, not the documentation that forbids them.
if grep -RIn --exclude-dir=target --exclude-dir=.git --exclude-dir=node_modules \
  -E 'createOtideClient\(|opentide-sql' "$root" \
  | grep -v 'not a valid' | grep -v 'never' | grep -v 'check-names' | grep -v 'index.test.ts'; then
  echo "forbidden identifier found"
  exit 1
fi
echo "names ok"
