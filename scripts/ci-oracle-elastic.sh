#!/usr/bin/env bash
# CI-only Elastic oracles (#83): Elasticsearch's EQL grammar, @elastic/esql,
# Kibana's KQL grammar, and the Lucene query parser. They are fetched at a
# pinned version into a scratch directory, run, and thrown away. Nothing
# here ships: the Elastic parsers are ELv2/AGPL/SSPL.
#
# Usage: bash scripts/ci-oracle-elastic.sh [detection-rules checkout]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/scripts/oracles/elastic"
work="${ORACLE_WORK:-$(mktemp -d)}"
es_commit=2c85bbdf4cc32de876c2bb31f009caa3a184c329
kibana_commit=ea2712af211782c2dfd1bc8a81c5d68fec975284
lucene_version=10.5.2
esql_version=4.33.0

mkdir -p "$work"/{queries,engine,oracle,node}
python3 "$here/collect.py" "$work/queries" ${1:+--detection-rules "$1"}

# Engine verdicts.
OPENTIDE_VERDICTS_IN="$work/queries" OPENTIDE_VERDICTS_OUT="$work/engine" \
  cargo test -q -p opentide-analysis --test oracle_verdicts -- --nocapture

raw() { curl -fsSL "https://raw.githubusercontent.com/$1/$2/$3" -o "$4"; }

# Node oracles share one sandbox, installed without install scripts.
(cd "$work/node" && npm init -y >/dev/null && npm pkg set type=commonjs &&
  npm install --no-save --ignore-scripts --no-audit --no-fund \
    "@elastic/esql@$esql_version" antlr-ng@1.0.10 antlr4@4.13.2 peggy@5.1.1 >/dev/null)

# ES|QL
node "$here/esql.cjs" "$work/node" "$work/queries/esql" > "$work/oracle/esql.tsv" || true

# EQL: EqlBase.g4 has no actions, so the generated parser is exact.
# Generated under the sandbox so its `import antlr4` resolves.
mkdir -p "$work/node/eql"
raw elastic/elasticsearch "$es_commit" x-pack/plugin/eql/src/main/antlr/EqlBase.g4 "$work/node/eql/EqlBase.g4"
(cd "$work/node/eql" && ../node_modules/.bin/antlr-ng -Dlanguage=JavaScript -o gen EqlBase.g4 >/dev/null)
node "$here/eql.mjs" "$work/node/eql/gen" "$work/node/node_modules/antlr4" "$work/queries/eql" > "$work/oracle/eql.tsv"

# Kibana KQL
mkdir -p "$work/kuery"
raw elastic/kibana "$kibana_commit" src/platform/packages/shared/kbn-es-query/src/kuery/grammar/grammar.peggy "$work/kuery/grammar.peggy"
"$work/node/node_modules/.bin/peggy" --format commonjs --allowed-start-rules start -o "$work/kuery/kuery.cjs" "$work/kuery/grammar.peggy"
node "$here/kuery.cjs" "$work/kuery/kuery.cjs" "$work/queries/kuery" > "$work/oracle/kuery.tsv"

# Lucene (needs Java 21+)
if command -v java >/dev/null 2>&1; then
  mkdir -p "$work/lucene"
  for jar in core queryparser; do
    curl -fsSL "https://repo1.maven.org/maven2/org/apache/lucene/lucene-$jar/$lucene_version/lucene-$jar-$lucene_version.jar" \
      -o "$work/lucene/$jar.jar"
  done
  java -cp "$work/lucene/core.jar:$work/lucene/queryparser.jar" "$here/LuceneOracle.java" "$work/queries/lucene" \
    > "$work/oracle/lucene.tsv"
else
  echo "java not found; Lucene oracle skipped"
fi

python3 "$here/compare.py" "$work/engine" "$work/oracle"
