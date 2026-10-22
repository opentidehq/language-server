#!/usr/bin/env python3
"""Generate catalogs/esql/*.toml from an Elasticsearch checkout.

Elasticsearch generates one JSON definition per ES|QL function and operator
(docs/reference/query-languages/esql/kibana/generated/x-pack-esql/definition)
and one docs layout per command and function. The layouts carry the
`applies_to` lifecycle (`stack: preview 9.2.0, ga 9.4.0`). This script copies
facts only: names, signatures, parameter names and types, return types,
lifecycle, licence tier, and the elastic.co page.

Elastic's prose is not copied. The definitions come from Elastic License 2.0
code and the docs are AGPL/SSPL/ELv2, none of which this EUPL-1.2 repository
can take. Command and operator summaries below are written for this catalog;
hover links to Elastic's page for the full text.

Usage:
    python scripts/sync_esql_catalog.py --elasticsearch ../elasticsearch

The checkout only needs `docs/reference/query-languages/esql`. Record the
commit printed on stdout in the catalog header; the files are committed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

DOCS = Path("docs/reference/query-languages/esql")
DEFINITIONS = DOCS / "kibana/generated/x-pack-esql/definition"
FUNCTION_LAYOUTS = DOCS / "_snippets/generated/x-pack-esql/functions/layout"
COMMAND_LAYOUTS = DOCS / "_snippets/commands/layout"
SITE = "https://www.elastic.co/docs/reference/query-languages/esql"

# Command layout file -> (canonical name, kind, docs page, summary). The docs
# pages are the elastic.co URLs; layout files are named a little differently.
# Summaries are this catalog's own words.
COMMANDS = {
    "from.md": ("from", "source", "commands/from",
        "Reads rows from indices, data streams, or aliases. `METADATA` adds metadata fields such as `_id`."),
    "ts.md": ("ts", "source", "commands/ts",
        "Reads time series indices and enables the time series aggregation functions."),
    "row.md": ("row", "source", "commands/row",
        "Produces a single row from literal values."),
    "show.md": ("show", "source", "commands/show",
        "Returns information about the deployment (`SHOW INFO`)."),
    "promql.md": ("promql", "source", "commands/promql",
        "Runs a PromQL expression over time series indices."),
    "set.md": ("set", "directive", "directives/set",
        "Sets a query setting before the query: `SET name = value;`."),
    "change_point.md": ("change_point", "processing", "commands/change-point",
        "Finds spikes, dips, and change points in a numeric column."),
    "completion.md": ("completion", "processing", "commands/completion",
        "Sends a prompt to an inference endpoint and stores the reply in a column."),
    "dedup.md": ("dedup", "processing", "commands/dedup",
        "Removes duplicate rows, keeping one row per distinct combination of values."),
    "dense_vector.md": ("dense_vector", "processing", "commands/dense-vector",
        "Computes vector embeddings for text columns through an inference endpoint."),
    "dissect.md": ("dissect", "processing", "commands/dissect",
        "Extracts columns from a string with a delimiter pattern."),
    "drop.md": ("drop", "processing", "commands/drop",
        "Removes columns."),
    "enrich.md": ("enrich", "processing", "commands/enrich",
        "Adds columns from an enrich policy, matched on a field."),
    "eval.md": ("eval", "processing", "commands/eval",
        "Adds or replaces columns computed from expressions."),
    "fork.md": ("fork", "processing", "commands/fork",
        "Runs several processing branches over the same rows and combines their output, tagged by `_fork`."),
    "fuse.md": ("fuse", "processing", "commands/fuse",
        "Merges rows from several result sets and scores them again."),
    "grok.md": ("grok", "processing", "commands/grok",
        "Extracts columns from a string with a grok pattern."),
    "highlight.md": ("highlight", "processing", "commands/highlight",
        "Adds snippets of the text that matched a full-text query, with the matches tagged."),
    "inlinestats-by.md": ("inline stats", "processing", "commands/inlinestats-by",
        "Computes aggregates per group and appends them to every input row; the rows are kept."),
    "ip_location.md": ("ip_location", "processing", "commands/ip-location",
        "Adds geolocation columns for an IP address."),
    "keep.md": ("keep", "processing", "commands/keep",
        "Keeps only the named columns, in that order."),
    "limit.md": ("limit", "processing", "commands/limit",
        "Caps the number of rows returned."),
    "lookup-join.md": ("lookup join", "processing", "commands/lookup-join",
        "Adds columns from a lookup-mode index for rows where the join condition matches."),
    "metrics-info.md": ("metrics_info", "processing", "commands/metrics-info",
        "Lists the metrics in the time series data streams the query reads."),
    "mmr.md": ("mmr", "processing", "commands/mmr",
        "Keeps a diverse subset of rows by maximal marginal relevance."),
    "mv_expand.md": ("mv_expand", "processing", "commands/mv_expand",
        "Turns a multivalued column into one row per value."),
    "registered_domain.md": ("registered_domain", "processing", "commands/registered-domain",
        "Splits a domain name into registered domain, subdomain, and suffix columns."),
    "rename.md": ("rename", "processing", "commands/rename",
        "Renames columns."),
    "rerank.md": ("rerank", "processing", "commands/rerank",
        "Scores rows again with an inference model against a query text."),
    "sample.md": ("sample", "processing", "commands/sample",
        "Keeps a random fraction of the rows."),
    "sort.md": ("sort", "processing", "commands/sort",
        "Orders rows by one or more expressions."),
    "stats-by.md": ("stats", "processing", "commands/stats-by",
        "Aggregates rows, optionally per group (`BY`); the output has one row per group."),
    "ts-info.md": ("ts_info", "processing", "commands/ts-info",
        "Lists the individual time series in the data streams the query reads."),
    "ts_collapse.md": ("ts_collapse", "processing", "commands/ts_collapse",
        "Collapses the per-step rows of PROMQL into one row per time series."),
    "uri_parts.md": ("uri_parts", "processing", "commands/uri-parts",
        "Splits a URI into scheme, host, path, query, and other columns."),
    "user_agent.md": ("user_agent", "processing", "commands/user-agent",
        "Parses a user-agent string into browser, operating system, and device columns."),
    "where.md": ("where", "processing", "commands/where",
        "Keeps the rows where a boolean expression is true."),
}

# Commands the grammar accepts that have no docs page: snapshot builds only
# (the lexer token is gated by isDevVersion()), or a retired spelling.
UNDOCUMENTED = [
    {
        "name": "explain",
        "kind": "source",
        "syntax": "EXPLAIN (query)",
        "docs": "Development command. Release builds reject it.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "fillnull",
        "kind": "processing",
        "syntax": "FILLNULL value ON fields",
        "docs": "Development command. Release builds reject it.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "left join",
        "kind": "processing",
        "syntax": "LEFT JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "right join",
        "kind": "processing",
        "syntax": "RIGHT JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "full join",
        "kind": "processing",
        "syntax": "FULL JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "inlinestats",
        "kind": "processing",
        "syntax": "INLINESTATS aggregates [BY groups]",
        "docs": "Earlier spelling of INLINE STATS, accepted while INLINE STATS was in technical preview.",
        "stack": "preview 9.2",
        "snapshot_only": False,
        "alias_of": "inline stats",
    },
]

# Registered aliases are not in the definition JSON
# (x-pack/plugin/esql/.../function/EsqlFunctionRegistry.java on 8.19; each
# function's DEFINITION on main).
ALIASES = {
    "bucket": ["bin"],
    "to_aggregate_metric_double": ["to_aggregatemetricdouble"],
    "to_boolean": ["to_bool"],
    "to_datetime": ["to_dt"],
    "to_date_nanos": ["to_datenanos"],
    "to_double": ["to_dbl"],
    "to_integer": ["to_int"],
    "to_string": ["to_str"],
    "to_unsigned_long": ["to_ulong", "to_ul"],
    "to_version": ["to_ver"],
}

APPLIES = re.compile(r"```(?:yaml )?\{applies_to\}\n(.*?)```", re.S)


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def stack_lifecycle(text: str) -> str:
    match = APPLIES.search(text)
    if not match:
        return ""
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "stack":
            return value.strip()
    return ""


def first_paragraph(text: str) -> str:
    body = APPLIES.sub("", text)
    body = re.sub(r"^%.*$", "", body, flags=re.M)
    for block in re.split(r"\n\s*\n", body):
        block = block.strip()
        if not block or block.startswith((":::", "#", "```", "::::")):
            continue
        block = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", block)
        block = block.replace("{{esql}}", "ES|QL").replace("{{es}}", "Elasticsearch")
        return " ".join(block.split())
    return ""


def syntax_block(text: str) -> str:
    match = re.search(r"## Syntax.*?```esql\n(.*?)```", text, re.S)
    return match.group(1).strip() if match else ""


def function_pages(es: Path) -> dict[str, str]:
    pages = {}
    root = es / DOCS / "functions-operators"
    for path in root.glob("*/*.md"):
        pages[path.stem] = f"{SITE}/functions-operators/{path.parent.name}/{path.stem}"
    return pages


def signature_label(name: str, params: list[dict], variadic: bool) -> str:
    parts = []
    for i, param in enumerate(params):
        label = param["name"]
        if variadic and i == len(params) - 1:
            label += ", ..."
        parts.append(f"[{label}]" if param.get("optional") else label)
    return f"{name.upper()}({', '.join(parts)})"


def merge_parameters(signatures: list[dict]) -> list[dict]:
    """One row per parameter name, in first-seen order, with the union of types."""
    rows: dict[str, dict] = {}
    for signature in signatures:
        for param in signature["params"]:
            row = rows.setdefault(
                param["name"],
                {
                    "name": param["name"],
                    "types": [],
                    "required": not param.get("optional", False),
                },
            )
            if param["type"] not in row["types"]:
                row["types"].append(param["type"])
            if param.get("optional"):
                row["required"] = False
    return list(rows.values())


def longest_signature(signatures: list[dict]) -> dict:
    return max(signatures, key=lambda s: len(s["params"]), default={"params": [], "variadic": False})


def write_functions(es: Path, out: Path, commit: str) -> int:
    pages = function_pages(es)
    lines = [
        "# ES|QL functions, generated by scripts/sync_esql_catalog.py. Do not edit.",
        "# Facts only (names, signatures, types, lifecycle); hover links to Elastic's page.",
        f"# Source: elastic/elasticsearch@{commit} {DEFINITIONS}/functions/*.json",
        "# and the `applies_to` lifecycle in the function layout snippets.",
        "",
    ]
    count = 0
    for path in sorted((es / DEFINITIONS / "functions").glob("*.json")):
        data = json.loads(path.read_text())
        name = data["name"]
        layout = es / FUNCTION_LAYOUTS / f"{name}.md"
        stack = stack_lifecycle(layout.read_text()) if layout.exists() else ""
        signatures = data.get("signatures", [])
        widest = longest_signature(signatures)
        returns = sorted({s.get("returnType", "") for s in signatures if s.get("returnType")})
        lines += [
            "[[functions]]",
            f"name = {toml_str(name)}",
            f"kind = {toml_str(data['type'])}",
            f"signature = {toml_str(signature_label(name, widest['params'], widest.get('variadic', False)))}",
            f"returns = {json.dumps(returns)}",
            f"aliases = {json.dumps(ALIASES.get(name, []))}",
            f"stack = {toml_str(stack)}",
            f"preview = {str(bool(data.get('preview'))).lower()}",
            f"snapshot_only = {str(bool(data.get('snapshot_only'))).lower()}",
        ]
        if data.get("license"):
            lines.append(f"license = {toml_str(data['license'])}")
        if name in pages:
            lines.append(f"citation = {toml_str(pages[name])}")
        lines.append("")
        for param in merge_parameters(signatures):
            lines += [
                "[[functions.parameters]]",
                f"name = {toml_str(param['name'])}",
                f"types = {json.dumps(param['types'])}",
                f"required = {str(param['required']).lower()}",
                "",
            ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


OPERATOR_SUMMARIES = {
    "add": "Addition. Also adds a time span to a date.",
    "cast": "Converts a value to the named type: `value::type`.",
    "div": "Division. Integer division truncates.",
    "equals": "Equality.",
    "greater_than": "Greater than.",
    "greater_than_or_equal": "Greater than or equal.",
    "in": "True when the value equals any value in the list.",
    "is_not_null": "True when the value is not null.",
    "is_null": "True when the value is null.",
    "less_than": "Less than.",
    "less_than_or_equal": "Less than or equal.",
    "like": "Wildcard match: `*` is any characters, `?` is one character.",
    "match_operator": "Full-text match of a field against a query string: `field:\"text\"`.",
    "mod": "Remainder of a division.",
    "mul": "Multiplication.",
    "neg": "Negation.",
    "not_in": "True when the value equals none of the values in the list.",
    "not_like": "Negated wildcard match.",
    "not_rlike": "Negated regular expression match.",
    "not_equals": "Inequality.",
    "rlike": "Regular expression match over the whole value.",
    "sub": "Subtraction. Also subtracts a time span from a date.",
}


def write_operators(es: Path, out: Path, commit: str) -> int:
    lines = [
        "# ES|QL operators, generated by scripts/sync_esql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {DEFINITIONS}/operators/*.json",
        "",
    ]
    count = 0
    for path in sorted((es / DEFINITIONS / "operators").glob("*.json")):
        data = json.loads(path.read_text())
        lines += [
            "[[operators]]",
            f"name = {toml_str(data['name'])}",
            f"operator = {toml_str(data.get('operator', data['name']))}",
            f"docs = {toml_str(OPERATOR_SUMMARIES.get(data['name'], ''))}",
            f"preview = {str(bool(data.get('preview'))).lower()}",
            f"citation = {toml_str(SITE + '/functions-operators/operators')}",
            "",
        ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


def write_commands(es: Path, out: Path, commit: str) -> int:
    lines = [
        "# ES|QL commands, generated by scripts/sync_esql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {COMMAND_LAYOUTS}/*.md",
        "# Rows without a citation are snapshot-only or retired spellings the grammar still parses.",
        "",
    ]
    rows = []
    for layout, (name, kind, page, summary) in sorted(COMMANDS.items(), key=lambda kv: kv[1][0]):
        path = es / COMMAND_LAYOUTS / layout
        text = path.read_text()
        rows.append(
            {
                "name": name,
                "kind": kind,
                "syntax": syntax_block(text),
                "docs": summary,
                "stack": stack_lifecycle(text),
                "snapshot_only": False,
                "citation": f"{SITE}/{page}",
            }
        )
    rows += UNDOCUMENTED
    for row in rows:
        lines += [
            "[[commands]]",
            f"name = {toml_str(row['name'])}",
            f"kind = {toml_str(row['kind'])}",
            f"syntax = {toml_str(row['syntax'])}",
            f"docs = {toml_str(row['docs'])}",
            f"stack = {toml_str(row['stack'])}",
            f"snapshot_only = {str(row['snapshot_only']).lower()}",
        ]
        if row.get("citation"):
            lines.append(f"citation = {toml_str(row['citation'])}")
        if row.get("alias_of"):
            lines.append(f"alias_of = {toml_str(row['alias_of'])}")
        lines.append("")
    out.write_text("\n".join(lines).rstrip() + "\n")
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch", type=Path, required=True)
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).resolve().parent.parent / "catalogs/esql"
    )
    args = parser.parse_args()
    es = args.elasticsearch.resolve()
    commit = subprocess.run(
        ["git", "-C", str(es), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    args.out.mkdir(parents=True, exist_ok=True)
    functions = write_functions(es, args.out / "functions.toml", commit)
    operators = write_operators(es, args.out / "operators.toml", commit)
    commands = write_commands(es, args.out / "commands.toml", commit)
    print(f"elastic/elasticsearch@{commit}: {commands} commands, {functions} functions, {operators} operators")


if __name__ == "__main__":
    main()
