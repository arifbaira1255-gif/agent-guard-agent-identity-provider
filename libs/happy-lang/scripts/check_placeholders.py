#!/usr/bin/env python3
"""Scan the Happy repository for incomplete / placeholder implementations.

This is the automated half of the Step 16 release audit.  It searches the
``happy/`` package for markers that indicate unfinished work and exits non-zero
when any *genuine* stub is found, so CI can gate on it.

Usage::

    python scripts/check_placeholders.py [--root PATH] [--quiet]

Exit code 0 means "no placeholders found"; 1 means at least one was found.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Tuple

#: Patterns that indicate unfinished work.  Each is (label, compiled regex).
PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("TODO", re.compile(r"\bTODO\b")),
    ("FIXME", re.compile(r"\bFIXME\b")),
    ("XXX", re.compile(r"\bXXX\b")),
    ("HACK", re.compile(r"\bHACK\b")),
    ("PLACEHOLDER", re.compile(r"\bPLACEHOLDER\b")),
    (
        "NotImplementedError",
        re.compile(r"raise\s+NotImplementedError"),
    ),
    (
        "stub-body",
        re.compile(r"^\s*pass\s*#\s*(stub|placeholder|todo)", re.IGNORECASE),
    ),
    (
        "unimplemented-stub",
        re.compile(
            r"(not\s+implemented\s+yet|implementation\s+pending|"
            r"stub\s+implementation|placeholder\s+implementation)",
            re.IGNORECASE,
        ),
    ),
]

#: Lines matching one of these are *legitimate* and must not be flagged.
ALLOWLIST = [
    # Forward-reference type placeholders (a real, deliberate pattern).
    re.compile(r"Optional\[.*\]\s*=\s*None\s*#.*forward"),
    # A forward-declared type variable genuinely named `placeholder`.
    re.compile(r"\bplaceholder\s*=\s*(StructType|EnumType)\("),
    re.compile(r"self\.types\[name\]\s*=\s*placeholder"),
    re.compile(r"type=placeholder\)"),
    re.compile(r"#.*placeholder\s+name"),
    # This script itself.
    re.compile(r"check_placeholders"),
]


def scan(root: str) -> List[Tuple[str, int, str, str]]:
    findings: List[Tuple[str, int, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in {"__pycache__", ".git", ".mypy_cache"}
        ]
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            if "check_placeholders" in path:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if any(pat.search(line) for pat in ALLOWLIST):
                        continue
                    for label, pattern in PATTERNS:
                        if pattern.search(line):
                            findings.append(
                                (os.path.relpath(path, root), lineno, label, line.strip())
                            )
                            break
    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "happy"),
        help="directory to scan (default: the happy/ package)",
    )
    parser.add_argument("--quiet", action="store_true", help="only print the summary")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2

    findings = scan(args.root)
    if not args.quiet:
        for path, lineno, label, text in findings:
            print(f"{path}:{lineno}: [{label}] {text}")
    if findings:
        print(f"\n{len(findings)} placeholder(s) found.")
        return 1
    print("No placeholders found — the implementation is complete.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
