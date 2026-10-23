#!/usr/bin/env python3
"""Compare engine verdicts with the Elastic oracles.

Usage: python compare.py ENGINE_DIR ORACLE_DIR

Each directory holds `<lang>.tsv` lines `file<TAB>OK|ERR<TAB>detail`. A
disagreement is listed unless testdata/oracles/exceptions.toml explains it:
- `[elastic.beyond_parser]` names engine codes for checks Elasticsearch
  makes after parsing (unknown functions, arity, unsupported features). An
  engine error made only of those codes is expected where the oracle, a
  parser, accepts.
- `[[esql]]`, `[[eql]]`, `[[kuery]]`, `[[lucene]]` entries with a `file`
  (a regex over the collected file name) and a `reason`.

Exit 1 when an unexplained disagreement remains.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(path: Path) -> dict[str, tuple[str, str]]:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        name, verdict, detail = (line.split("\t", 2) + ["", ""])[:3]
        out[name] = (verdict, detail)
    return out


def main() -> int:
    engine_dir, oracle_dir = Path(sys.argv[1]), Path(sys.argv[2])
    exceptions = tomllib.loads((ROOT / "testdata/oracles/exceptions.toml").read_text())
    beyond = exceptions.get("elastic", {}).get("beyond_parser", {})
    unexplained = 0
    for lang in ("esql", "eql", "kuery", "lucene"):
        engine, oracle = read(engine_dir / f"{lang}.tsv"), read(oracle_dir / f"{lang}.tsv")
        if not oracle:
            print(f"{lang}: no oracle output, skipped")
            continue
        listed = [(re.compile(e["file"]), e["reason"]) for e in exceptions.get(lang, [])]
        agree = expected = 0
        problems = []
        for name, (o_verdict, o_detail) in sorted(oracle.items()):
            e_verdict, e_codes = engine.get(name, ("MISSING", ""))
            if e_verdict == o_verdict:
                agree += 1
                continue
            codes = {c for c in e_codes.split(",") if c}
            if e_verdict == "ERR" and o_verdict == "OK" and codes and codes <= set(beyond.get(lang, [])):
                expected += 1
                continue
            if any(rx.search(name) for rx, _ in listed):
                expected += 1
                continue
            kind = "engine rejects, oracle accepts" if e_verdict == "ERR" else "engine accepts, oracle rejects"
            problems.append(f"  {name}: {kind} | engine: {e_codes or '-'} | oracle: {o_detail or '-'}")
        print(f"{lang}: {len(oracle)} queries, {agree} agree, {expected} explained, {len(problems)} unexplained")
        print("\n".join(problems))
        unexplained += len(problems)
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
