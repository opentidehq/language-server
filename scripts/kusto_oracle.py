#!/usr/bin/env python3
"""Kusto.Language syntax oracle for the valid KQL corpus.

Every valid KQL fixture must parse with Microsoft's KustoCode.Parse. A file it
rejects is a red build unless a [[kql]] entry in testdata/oracles/exceptions.toml
lists the path. An exception whose files Kusto.Language now accepts is stale and
is also a red build, so the list only holds live disagreements.

Run through scripts/ci-oracle.sh. Needs the .NET SDK and Python 3.11+.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECT = ROOT / "scripts/kusto-oracle"
EXCEPTIONS = ROOT / "testdata/oracles/exceptions.toml"


def corpus() -> list[str]:
    valid = sorted(ROOT.glob("testdata/corpus/kql/*__valid.kql"))
    external = sorted(
        p
        for p in ROOT.glob("testdata/conformance/external/kql/*.kql")
        if not p.name.endswith(".broken.kql")
    )
    return [p.relative_to(ROOT).as_posix() for p in valid + external]


def exceptions(files: set[str], errors: list[str]) -> dict[str, str]:
    """Maps each excepted path to the id of the entry that lists it."""
    entries = tomllib.loads(EXCEPTIONS.read_text()).get("kql", [])
    excepted: dict[str, str] = {}
    for entry in entries:
        ident = entry.get("id")
        if not ident or not entry.get("reason"):
            errors.append(f"[[kql]] exception {ident!r} needs an id and a reason")
            continue
        paths = entry.get("paths") or []
        if not paths:
            errors.append(f"[[kql]] exception {ident}: list the corpus paths it covers in `paths`")
        for path in paths:
            if path not in files:
                errors.append(f"[[kql]] exception {ident}: {path} is not in the valid KQL corpus")
            elif path in excepted:
                errors.append(f"[[kql]] exception {ident}: {path} is already listed by {excepted[path]}")
            else:
                excepted[path] = ident
    return excepted


def parse(files: list[str]) -> dict[str, dict]:
    out = PROJECT / "bin/oracle"
    subprocess.run(
        ["dotnet", "build", str(PROJECT), "-c", "Release", "-o", str(out), "--nologo", "-v", "q"],
        check=True,
        stdout=sys.stderr,
    )
    run = subprocess.run(
        ["dotnet", str(out / "KustoOracle.dll"), *files],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    results = (json.loads(line) for line in run.stdout.splitlines() if line.strip())
    return {r["path"]: r for r in results}


def main() -> int:
    files = corpus()
    errors: list[str] = []
    excepted = exceptions(set(files), errors)
    results = parse(files)

    rejected = known = 0
    for path in files:
        result = results.get(path)
        if result is None:
            errors.append(f"{path}: Kusto.Language returned no result")
            continue
        ident = excepted.get(path)
        if result["accepted"]:
            if ident:
                errors.append(f"{path}: Kusto.Language accepts it; remove it from exception {ident}")
            continue
        rejected += 1
        detail = "; ".join(
            f"{d['code']} at {d['start']}: {d['message']}" for d in result["diagnostics"]
        )
        if ident:
            known += 1
            print(f"known  {path} ({ident}): {detail}")
        else:
            errors.append(f"{path}: Kusto.Language rejects a valid fixture: {detail}")

    print(f"Kusto.Language parsed {len(files)} valid KQL files; {rejected} rejected, {known} excepted")
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
