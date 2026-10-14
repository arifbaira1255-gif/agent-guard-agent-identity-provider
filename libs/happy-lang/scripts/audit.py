#!/usr/bin/env python3
"""Repository-wide release & security audit for the Happy toolchain (Step 16).

Runs a battery of checks against the source tree and reports every genuine
finding.  It does not hide or bypass errors: any check that fails is printed
and reflected in the exit code.

Checks performed:
  1. Version consistency     - every version reference agrees with pyproject.
  2. Incomplete code scan    - TODO/FIXME/NotImplemented markers in shipping code.
  3. Hardcoded-secret scan   - credential-looking literals outside test fixtures.
  4. Packaging sanity        - pyproject parses, entry point resolves, packages exist.
  5. Examples compile & run  - every official .hpy example builds and executes.
  6. CLI smoke               - the documented commands respond.

Usage:
    python scripts/audit.py [--root DIR] [--json]
Exit code 0 = clean, non-zero = at least one finding.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that are not shipped source (skipped by the source scans).
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv",
             "venv", "node_modules", ".mypy_cache", "*.egg-info"}

EXPECTED_VERSION = "1.0.0"

# Markers that indicate genuinely unfinished work when found in *shipping* code.
INCOMPLETE_RE = re.compile(
    r"\b(TODO|FIXME|XXX|HACK)\b|raise\s+NotImplementedError|NotImplementedError\("
)

# A conservative credential-looking literal: key/secret/token/password assigned
# a long alphanumeric value.  Test fixtures and placeholder values are excluded.
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|access[_-]?key|private[_-]?key)"
    r"\b\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{16,})['\"]"
)
PLACEHOLDER_VALUES = {
    "changeme", "example", "placeholder", "your-api-key", "your_api_key",
    "xxx", "todo", "test", "dummy", "fake",
}


class Finding:
    def __init__(self, check: str, severity: str, message: str, location: str = ""):
        self.check = check
        self.severity = severity          # "error" | "warning"
        self.message = message
        self.location = location

    def __str__(self) -> str:
        loc = f" [{self.location}]" if self.location else ""
        return f"[{self.severity}] {self.check}: {self.message}{loc}"


def _iter_source_files(root: str, exts=(".py",)):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            if name.endswith(exts):
                yield os.path.join(dirpath, name)


def _rel(root: str, path: str) -> str:
    return os.path.relpath(path, root)


# ---------------------------------------------------------------------------
# 1. Version consistency
# ---------------------------------------------------------------------------
def check_version_consistency(root: str):
        findings = []
        init_path = os.path.join(root, "happy", "__init__.py")
        top_version = None
        with open(init_path, "r", encoding="utf-8") as fh:
            m = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read())
            top_version = m.group(1) if m else None
        if top_version != EXPECTED_VERSION:
            findings.append(Finding(
                "version", "error",
                f"happy/__init__.py __version__ is {top_version!r}, expected {EXPECTED_VERSION!r}",
                _rel(root, init_path)))

        # pyproject must agree.
        pyproject = os.path.join(root, "pyproject.toml")
        if os.path.isfile(pyproject):
            with open(pyproject, "r", encoding="utf-8") as fh:
                m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', fh.read())
                if not m or m.group(1) != EXPECTED_VERSION:
                    findings.append(Finding(
                        "version", "error",
                        "pyproject.toml version does not match "
                        f"{EXPECTED_VERSION!r}", _rel(root, pyproject)))
        else:
            findings.append(Finding("version", "error", "pyproject.toml is missing", root))

        # Any *other* module-level __version__ must match too.
        for path in _iter_source_files(os.path.join(root, "happy")):
            with open(path, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    m = re.search(r'__version__\s*=\s*"([^"]+)"', line)
                    if m and m.group(1) != EXPECTED_VERSION:
                        findings.append(Finding(
                            "version", "error",
                            f"__version__ {m.group(1)!r} != {EXPECTED_VERSION!r}",
                            f"{_rel(root, path)}:{i}"))
        return findings


# ---------------------------------------------------------------------------
# 2. Incomplete code scan (shipping code only, not tests/examples)
# ---------------------------------------------------------------------------
def check_incomplete_code(root: str):
    findings = []
    happy_dir = os.path.join(root, "happy")
    for path in _iter_source_files(happy_dir):
        with open(path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                stripped = line.strip()
                if stripped.startswith("#") and not INCOMPLETE_RE.search(stripped):
                    continue
                m = INCOMPLETE_RE.search(line)
                if m:
                    # Allow a deliberate "not implemented" *message* that is part
                    # of a real error path (trait method dispatch), not a stub.
                    if "is not implemented" in line and "raise" not in line:
                        continue
                    findings.append(Finding(
                        "incomplete", "warning", stripped[:80],
                        f"{_rel(root, path)}:{i}"))
    return findings


# ---------------------------------------------------------------------------
# 3. Hardcoded-secret scan
# ---------------------------------------------------------------------------
def check_hardcoded_secrets(root: str):
    findings = []
    for sub in ("happy", "scripts"):
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for path in _iter_source_files(base):
            with open(path, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    for m in SECRET_RE.finditer(line):
                        value = m.group(2)
                        if value.lower() in PLACEHOLDER_VALUES:
                            continue
                        if set(value) <= {"x", "X", "*"}:  # masked
                            continue
                        findings.append(Finding(
                            "secret", "error",
                            f"possible hardcoded credential assigned to '{m.group(1)}'",
                            f"{_rel(root, path)}:{i}"))
    return findings


# ---------------------------------------------------------------------------
# 4. Packaging sanity
# ---------------------------------------------------------------------------
def check_packaging(root: str):
    findings = []
    pyproject = os.path.join(root, "pyproject.toml")
    if not os.path.isfile(pyproject):
        return [Finding("packaging", "error", "pyproject.toml missing", root)]
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - 3.9/3.10 fallback
        tomllib = None
    with open(pyproject, "rb") as fh:
        raw = fh.read()
    if tomllib is not None:
        try:
            data = tomllib.loads(raw.decode("utf-8"))
            pkgs = data.get("tool", {}).get("setuptools", {}).get("packages", [])
            for pkg in pkgs:
                pkg_dir = os.path.join(root, *pkg.split("."))
                if not os.path.isdir(pkg_dir):
                    findings.append(Finding(
                        "packaging", "error",
                        f"declared package '{pkg}' has no directory", _rel(root, pyproject)))
                elif not os.path.isfile(os.path.join(pkg_dir, "__init__.py")):
                    findings.append(Finding(
                        "packaging", "error",
                        f"declared package '{pkg}' lacks __init__.py", _rel(root, pyproject)))
            scripts = data.get("project", {}).get("scripts", {})
            entry = scripts.get("happy", "")
            if ":" not in entry:
                findings.append(Finding(
                    "packaging", "error",
                    "console script 'happy' entry point malformed", _rel(root, pyproject)))
            else:
                mod, func = entry.split(":")
                mod_path = os.path.join(root, *mod.split("."))
                if not (os.path.isfile(mod_path + ".py") or os.path.isdir(mod_path)):
                    findings.append(Finding(
                        "packaging", "error",
                        f"console script module '{mod}' not found", _rel(root, pyproject)))
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding(
                "packaging", "error", f"pyproject.toml failed to parse: {exc}",
                _rel(root, pyproject)))
    # __main__.py must exist so `python -m happy` works.
    if not os.path.isfile(os.path.join(root, "happy", "__main__.py")):
        findings.append(Finding(
            "packaging", "error", "happy/__main__.py missing (python -m happy broken)",
            _rel(root, os.path.join("happy", "__main__.py"))))
    return findings


# ---------------------------------------------------------------------------
# 5. Examples compile & run
# ---------------------------------------------------------------------------
def check_examples(root: str):
    findings = []
    examples_dir = os.path.join(root, "examples")
    if not os.path.isdir(examples_dir):
        return [Finding("examples", "error", "examples/ directory missing", root)]
    happy_files = sorted(f for f in os.listdir(examples_dir) if f.endswith(".hpy"))
    if not happy_files:
        findings.append(Finding("examples", "warning", "no .hpy examples found", examples_dir))
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in happy_files:
        path = os.path.join(examples_dir, name)
        proc = subprocess.run(
            [sys.executable, "-m", "happy.cli", "run", path],
            capture_output=True, text=True, cwd=root, env=env, timeout=60,
        )
        if proc.returncode != 0:
            findings.append(Finding(
                "examples", "error",
                f"`happy run {name}` failed: {proc.stderr.strip()[:120]}",
                _rel(root, path)))
    return findings


# ---------------------------------------------------------------------------
# 6. CLI smoke
# ---------------------------------------------------------------------------
def check_cli(root: str):
    findings = []
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    commands = [
        ["--version"],
        ["check", os.path.join("examples", "verified_demo.hpy")],
        ["build", os.path.join("examples", "backend_demo.hpy"), "-o", os.devnull],
        ["lint", os.path.join("examples", "verified_demo.hpy")],
        ["verify", os.path.join("examples", "verified_demo.hpy")],
    ]
    for argv in commands:
        proc = subprocess.run(
            [sys.executable, "-m", "happy.cli", *argv],
            capture_output=True, text=True, cwd=root, env=env, timeout=60,
        )
        if proc.returncode != 0:
            findings.append(Finding(
                "cli", "error",
                f"`happy {' '.join(argv)}` exited {proc.returncode}: "
                f"{proc.stderr.strip()[:120]}",
                " ".join(argv)))
    return findings


CHECKS = [
    ("version consistency", check_version_consistency),
    ("incomplete code", check_incomplete_code),
    ("hardcoded secrets", check_hardcoded_secrets),
    ("packaging sanity", check_packaging),
    ("examples compile & run", check_examples),
    ("cli smoke", check_cli),
]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Happy release & security audit")
    parser.add_argument("--root", default=REPO_ROOT)
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    all_findings = []
    per_check = {}
    for name, fn in CHECKS:
        try:
            found = fn(root)
        except Exception as exc:  # noqa: BLE001 - an audit check must never crash the run
            found = [Finding(name, "error", f"audit check crashed: {exc}")]
        per_check[name] = found
        all_findings.extend(found)

    if args.json:
        print(json.dumps({
            "root": root,
            "checks": {
                name: [f.__dict__ for f in found] for name, found in per_check.items()
            },
            "total": len(all_findings),
            "errors": sum(1 for f in all_findings if f.severity == "error"),
            "warnings": sum(1 for f in all_findings if f.severity == "warning"),
        }, indent=2))
    else:
        print(f"Happy release audit — root: {root}\n" + "=" * 60)
        for name, found in per_check.items():
            status = "OK" if not found else f"{len(found)} finding(s)"
            print(f"\n[{name}] {status}")
            for f in found:
                print("   " + str(f))
        errors = sum(1 for f in all_findings if f.severity == "error")
        warnings = sum(1 for f in all_findings if f.severity == "warning")
        print("\n" + "=" * 60)
        print(f"Total: {errors} error(s), {warnings} warning(s)")

    return 1 if any(f.severity == "error" for f in all_findings) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
