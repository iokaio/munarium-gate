#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The documentation gate: every link resolves, every page under docs/ is listed.

Two checks, over the root *.md files, .github/**/*.md and docs/**/*.md:

  * every relative link names a file or directory that exists (fenced code,
    http(s), mailto and bare #anchors are skipped; a #fragment is stripped);
  * every .md under docs/ is linked from the README.md of its own directory
    or of an ancestor directory, so the index tables stay complete.

    py scripts/docs_linkcheck.py

Exit 1 on any finding, naming the file and line. Stdlib only, no network.
Carried from iokaio/munarium's scripts/docs_linkcheck.py without that
repository's component-specific claim checks.
"""
from __future__ import annotations

import pathlib
import re
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
GITHUB = ROOT / ".github"

LINK = re.compile(r"!?\[[^\]]*\]\(<?([^)>\s]+)>?(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")


def markdown_files() -> list[pathlib.Path]:
    files = sorted(p for p in ROOT.glob("*.md") if p.is_file())
    for base in (GITHUB, DOCS):
        if base.is_dir():
            files += sorted(p for p in base.rglob("*.md") if p.is_file())
    return files


def links_in(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    fence = None
    for lineno, line in enumerate(text.splitlines(), 1):
        marker = FENCE.match(line)
        if fence is not None:
            if (marker and marker[1][0] == fence[0]
                    and len(marker[1]) >= len(fence) and not marker[2].strip()):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        for match in LINK.finditer(line):
            target = match.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = urllib.parse.unquote(target.split("#", 1)[0])
            if target:
                out.append((lineno, target))
    return out


def main() -> int:
    findings: list[str] = []
    files = markdown_files()
    linked_from_index: set[pathlib.Path] = set()

    for file in files:
        text = file.read_text(encoding="utf-8", errors="replace")
        for lineno, target in links_in(text):
            resolved = (file.parent / target).resolve()
            if not resolved.exists():
                rel = file.relative_to(ROOT).as_posix()
                findings.append(f"{rel}:{lineno}: broken link -> {target}")
            elif (file.name == "README.md" and resolved.suffix == ".md"
                  and file.parent.resolve() in resolved.parents):
                linked_from_index.add(resolved)

    for file in files:
        if DOCS not in file.parents or file.name == "README.md":
            continue
        if file.resolve() not in linked_from_index:
            rel = file.relative_to(ROOT).as_posix()
            findings.append(f"{rel}:1: not listed from any README.md index above it")

    for directory in sorted({p.parent for p in files if DOCS in p.parents or p.parent == DOCS}):
        if not (directory / "README.md").is_file():
            rel = directory.relative_to(ROOT).as_posix()
            findings.append(f"{rel}/: directory under docs/ has no README.md index")

    if findings:
        for finding in findings:
            print(finding)
        print(f"docs_linkcheck: {len(findings)} finding(s)")
        return 1
    print(f"docs_linkcheck: {len(files)} markdown files, every link resolves, every page is indexed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
