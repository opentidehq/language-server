#!/usr/bin/env python3
"""Release helpers for the opentide language server.

    release.py version              print the workspace version
    release.py check vX.Y.Z         the tag, every crate pin, and CHANGELOG.md agree
    release.py bump X.Y.Z           set the workspace version and the internal pins
    release.py notes X.Y.Z          print the CHANGELOG.md section for a version
    release.py vendor [--clean]     copy each crate's shared assets into crates/*/assets

Crates embed catalogs, grammars, and highlight queries from the repository root.
Cargo packages only what sits inside a crate, so `vendor` copies the files each
crate reads (every `OPENTIDE_ASSETS` path in its sources, plus the directories in
`[package.metadata.opentide] assets`) into `crates/<name>/assets/`, where build.rs
looks first. Run `vendor --clean` afterwards, or later builds keep reading the copy.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
ASSET_INCLUDE = re.compile(r'env!\("OPENTIDE_ASSETS"\),\s*"/([^"]+)"')
# Shipped in every crate: the licence the manifests name, and the third-party notices.
LEGAL = ["LICENSE", "NOTICE"]


def workspace_version() -> str:
    return tomllib.loads(WORKSPACE.read_text())["workspace"]["package"]["version"]


def internal_pins() -> dict[str, str]:
    deps = tomllib.loads(WORKSPACE.read_text())["workspace"]["dependencies"]
    return {
        name: spec.get("version", "")
        for name, spec in deps.items()
        if isinstance(spec, dict) and "path" in spec
    }


def changelog_section(version: str) -> str | None:
    text = CHANGELOG.read_text()
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |^\[[^\]]+\]: |\Z)",
        text,
        re.M | re.S,
    )
    return match.group(1).strip() if match else None


def check(tag: str) -> list[str]:
    version = workspace_version()
    problems = []
    if tag != f"v{version}":
        problems.append(f"tag {tag} does not match workspace version {version}")
    for name, pin in internal_pins().items():
        if pin != f"={version}":
            problems.append(f"{name} is pinned to {pin or 'no version'}, not ={version}")
    if not changelog_section(version):
        problems.append(f"CHANGELOG.md has no section for {version}")
    return problems


def bump(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"not a version: {version}")
    text = WORKSPACE.read_text()
    text = re.sub(
        r'(\[workspace\.package\]\nversion = )"[^"]+"', rf'\1"{version}"', text, count=1
    )
    text = re.sub(
        r'(opentide-[a-z]+ = \{ path = "[^"]+", version = )"=[^"]+"', rf'\1"={version}"', text
    )
    WORKSPACE.write_text(text)
    subprocess.run(["cargo", "update", "--workspace"], cwd=ROOT, check=True)


def publishable_crates() -> list[dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    # `publish = false` reads as an empty registry list.
    return [p for p in json.loads(out)["packages"] if p.get("publish") != []]


def crate_assets(package: dict) -> list[str]:
    crate = Path(package["manifest_path"]).parent
    found = set()
    for source in crate.glob("src/**/*.rs"):
        found.update(ASSET_INCLUDE.findall(source.read_text()))
    meta = (package.get("metadata") or {}).get("opentide") or {}
    found.update(meta.get("assets", []))
    return sorted(found)


def vendor(clean: bool) -> None:
    for package in publishable_crates():
        crate = Path(package["manifest_path"]).parent
        target = crate / "assets"
        shutil.rmtree(target, ignore_errors=True)
        for name in LEGAL:
            (crate / name).unlink(missing_ok=True)
        if clean:
            continue
        for name in LEGAL:
            shutil.copy2(ROOT / name, crate / name)
        assets = crate_assets(package)
        for rel in assets:
            src = ROOT / rel
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dest)
            elif src.is_file():
                shutil.copy2(src, dest)
            else:
                sys.exit(f"{package['name']}: {rel} does not exist")
        if assets:
            print(f"{package['name']}: {len(assets)} asset paths")


def main(argv: list[str]) -> None:
    match argv:
        case ["version"]:
            print(workspace_version())
        case ["check", tag]:
            problems = check(tag)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if problems:
                sys.exit(1)
            print(f"{tag} is consistent")
        case ["bump", version]:
            bump(version)
        case ["notes", version]:
            section = changelog_section(version.removeprefix("v"))
            if section is None:
                sys.exit(f"CHANGELOG.md has no section for {version}")
            print(section)
        case ["vendor"]:
            vendor(clean=False)
        case ["vendor", "--clean"]:
            vendor(clean=True)
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
