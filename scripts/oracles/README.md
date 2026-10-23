# Oracles

CI-only checks that compare the opentide engine with the parser each query language is defined by. They answer one question: where does our engine disagree with Microsoft or Splunk, and is every disagreement known?

| Language | Reference | Runs as | Job |
| --- | --- | --- | --- |
| KQL | Microsoft Kusto.Language 12.4.1 (`KustoCode.Parse`, `GlobalState.Default`) | `kusto/`, a NuGet-locked .NET 10 console tool | `oracle.yml` → Kusto.Language |
| SPL | Splunk Enterprise 10.6.1 `search/parser` REST endpoint, `searchbnf.conf` | `splunk/splunk:10.6.1` service container | `oracle.yml` → Splunk |
| ES\|QL | `@elastic/esql` 4.33.0 (`Parser.parseErrors`) | `elastic/esql.cjs`, npm-locked in `elastic/package-lock.json` | `oracle.yml` → Elastic and Lucene |
| EQL | Elasticsearch `EqlBase.g4` at `2c85bbdf`, generated with antlr-ng 1.0.10 (the grammar has no actions) | `elastic/eql.mjs` | `oracle.yml` → Elastic and Lucene |
| Kibana KQL (`kuery`) | Kibana `grammar.peggy` at `ea2712af`, compiled with peggy 5.1.1 | `elastic/kuery.cjs` | `oracle.yml` → Elastic and Lucene |
| Lucene | Lucene 10.5.2 `QueryParser` (the version Elasticsearch pins), leading wildcards on | `elastic/LuceneOracle.java` | `oracle.yml` → Elastic and Lucene |
| Tide YAML | Pydantic models in the pinned `opentide` package | `scripts/pydantic_object_issues.py` | `ci.yml` (`cargo test`, `tide_corpus.rs`) |

Tide YAML already has its oracle: `tide_corpus.rs` runs the opentide CLI's Pydantic models and requires the LSP to report every issue they find. Configuration TOML gets the same treatment in `#68`. The Elastic references are fetched at CI time: the npm packages from `elastic/package-lock.json` (`npm ci --ignore-scripts`), and `EqlBase.g4`, `grammar.peggy`, and the Lucene jars by URL with a pinned SHA-256 (`FETCH` in `oracle.py`), cached in `elastic/.cache/`. None of them is committed. Later languages (S1QL, Sigma, YARA) get an oracle when they get an engine; see `skills/add-language/SKILL.md`.

## What is compared

`oracle.py` gathers every query in the corpus:

- `testdata/corpus/<lang>/*` (fixture tag line removed, as `corpus_gate.rs` does)
- `testdata/conformance/external/<lang>/*`, including the `.broken.` twins
- `testdata/conformance/perf/*`
- `testdata/oracles/<lang>/*`, one probe per form real detections use
- every `configurations.{sentinel,defender_for_endpoint,splunk}` query in a Tide rule under `testdata/`
- Elastic: `configurations.elastic.query` and `threat.query` in the language their `type` and `language` select, `response.procedure.searches[]` entries with `system: elastic` and a `language`, the verdict tables `testdata/conformance/external/{lucene-queryparser,kuery-opensearch-dashboards}/cases.tsv`, and, when `OPENTIDE_DETECTION_RULES` names an `elastic/detection-rules` checkout (CI pins one), every rule and single-language hunt in it

Each query runs through `opentide-lsp analyze` and through the reference.

**Verdicts.** Ours rejects a query when it reports `kql_parse_error` or `kql_unknown_operator` (`spl_parse_error` or `spl_unknown_command` for SPL; for the Elastic languages, an error-severity syntax code from `REJECT` in `oracle.py`, which leaves out checks Elasticsearch makes after parsing). The reference rejects it when it reports an error. A query where they differ must be listed by path in `testdata/oracles/exceptions.toml`. A `.broken.` fixture the reference accepts always fails: its injected fault breaks nothing. A probe in `testdata/oracles/<lang>/` is a valid detection form, so any error-severity diagnostic from ours on it fails too (an unknown table or function there is a false positive).

**Names.** KQL: `catalogs/kql/core/functions.toml` and `evaluate-plugins.toml` against the functions, aggregates and plugins in Kusto.Language's `GlobalState.Default`, plus any name ours flags `kql_unknown_function` that Kusto.Language knows. SPL: `catalogs/spl/commands.toml` against the `*-command` stanzas and aliases in `searchbnf.conf`, plus any name ours flags `spl_unknown_command` that Splunk knows. Every disagreeing name must be listed.

A listed path or name that no longer disagrees fails as stale, so the exceptions file is the exact ledger of known gaps. Fix a gap and delete its entry in the same change. When a check fails, the output ends with the unlisted items as TOML to start from.

## Splunk setup

The parser expands macros and resolves data models, so `oracle.py` defines them in the container first:

- macros from `splunk/macros.toml`. ESCU macros are copied from `splunk/security_content` (Apache-2.0); CIM helpers are one-line stand-ins. Any `` `<detection>_filter` `` macro is defined as `search *`, which is what ESCU generates.
- data models built from `catalogs/spl/datamodels.toml`, one dataset per entry with its fields. A data model the catalog lacks is a real disagreement.

Text that does not start with `|` is sent as `search <text>`, which is how Splunk runs authored SPL (`docs/spl/README.md`). The engine sees the authored text unchanged.

## Running locally

Both are optional. `scripts/ci-oracle.sh` skips a language whose reference is missing unless `OPENTIDE_ORACLE_REQUIRED=1`.

```bash
# KQL: needs the .NET 10 SDK, cargo and PyYAML
bash scripts/ci-oracle.sh kql

# SPL: needs Docker. Starting the container accepts the Splunk General Terms.
eval "$(bash scripts/oracles/splunk/start.sh)"
bash scripts/ci-oracle.sh spl
```

## Not shipped

Kusto.Language, Splunk, Splunk SDKs, and the Elastic and Lucene references never enter a release artifact. `ci-oracle.sh` fails if a shipped manifest depends on one, and `release.yml` runs `scripts/license-scan.sh` over every artifact (unpacking wheels and zips) before it attaches them.
