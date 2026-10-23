#!/usr/bin/env python3
"""Collect Elastic queries for the CI oracles, one file per query.

Writes OUT/<lang>/<name>.<ext> for lang in esql, eql, kuery, lucene from:
- testdata/corpus/<lang>/ (the `prod:` first line is dropped),
- testdata/conformance/external/<lang>/ (public queries and fault twins),
- optionally an elastic/detection-rules checkout (`--detection-rules`):
  each rule's query and threat_query, in the language its type and
  language select, and single-language hunts. Those rules are ELv2: they
  are read at CI time and never committed.

Usage: python scripts/oracles/elastic/collect.py OUT [--detection-rules DIR]
"""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXT = {"esql": "esql", "eql": "eql", "kuery": "kuery", "lucene": "lucene"}


def rule_language(rule_type: str | None, language: str | None) -> str | None:
    """Mirror of opentide_tide::elastic_query_language."""
    if rule_type == "esql":
        return "esql"
    if rule_type == "eql":
        return "eql"
    if rule_type in ("query", "threshold", "new_terms", "threat_match"):
        return {None: "kuery", "kuery": "kuery", "lucene": "lucene"}.get(language)
    return None


def write(out: Path, lang: str, name: str, text: str) -> None:
    path = out / lang / f"{name}.{EXT[lang]}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    parser.add_argument("--detection-rules", type=Path)
    args = parser.parse_args()
    counts: dict[str, int] = {}
    for lang in EXT:
        for f in sorted((ROOT / "testdata/corpus" / lang).glob(f"*.{EXT[lang]}")):
            body = "\n".join(f.read_text().splitlines()[1:])
            write(args.out, lang, f"corpus__{f.stem}", body)
            counts[lang] = counts.get(lang, 0) + 1
        ext_dir = ROOT / "testdata/conformance/external" / lang
        for f in sorted(ext_dir.glob(f"*.{EXT[lang]}")) if ext_dir.is_dir() else []:
            write(args.out, lang, f"external__{f.name[: -len(EXT[lang]) - 1]}", f.read_text())
            counts[lang] = counts.get(lang, 0) + 1
    if args.detection_rules:
        root = args.detection_rules
        for f in sorted(
            p for d in ("rules", "rules_building_block", "hunting") for p in (root / d).rglob("*.toml")
        ):
            try:
                doc = tomllib.loads(f.read_text())
            except (tomllib.TOMLDecodeError, UnicodeDecodeError):
                continue
            stem = "dr__" + str(f.relative_to(root).with_suffix("")).replace("/", "__")
            queries: list[tuple[str, str]] = []
            rule = doc.get("rule") or {}
            lang = rule_language(rule.get("type"), rule.get("language"))
            if lang and isinstance(rule.get("query"), str):
                queries.append((lang, rule["query"].rstrip()))
            tlang = rule_language("threat_match", rule.get("threat_language"))
            if rule.get("type") == "threat_match" and tlang and isinstance(rule.get("threat_query"), str):
                queries.append((tlang, rule["threat_query"].rstrip()))
            hunt = doc.get("hunt") or {}
            hunt_lang = {("ES|QL",): "esql", ("EQL",): "eql"}.get(tuple(hunt.get("language") or []))
            if hunt_lang:
                queries += [(hunt_lang, q.strip()) for q in hunt.get("query") or [] if isinstance(q, str)]
            for i, (lang, query) in enumerate(queries):
                write(args.out, lang, f"{stem}__{i}", query)
                counts[lang] = counts.get(lang, 0) + 1
    print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
