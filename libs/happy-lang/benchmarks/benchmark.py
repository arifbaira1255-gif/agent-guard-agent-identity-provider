#!/usr/bin/env python3
"""Reproducible Happy (.hpy) toolchain benchmarks.

Every number printed by this harness is *measured at run time* on the machine
that executes it.  Nothing is hard-coded.  Run it yourself::

    python benchmarks/benchmark.py            # human-readable report
    python benchmarks/benchmark.py --json     # machine-readable JSON
    python benchmarks/benchmark.py --repeat 20

Metrics captured:

* per-stage latency: lex, parse, semantic/type-check, IR lowering, optimize,
  Python codegen, compile-to-executable, and full end-to-end execution
* throughput (operations / second) for each stage
* source-map anchor count produced by the backend (debuggability metric)
* build size ratio (generated Python LOC per Happy LOC)
* security-analyzer latency
* formatter + linter latency and formatter idempotence
* whole-repo code size (LOC, files, modules)

The harness imports the real toolchain through the public ``happy`` API; it is
not a mock and does not stub any stage.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import statistics
import sys
import time
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from typing import Callable, Dict, List

# Make the repository importable when run from a checkout.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from happy.compiler import lexer, parser, semantic, ir as ir_mod, optimizer  # noqa: E402
from happy.backend import python_gen  # noqa: E402
from happy.runtime import RuntimeContext  # noqa: E402
from happy.security import analyzer as security  # noqa: E402
from happy.tools import fmt as fmt_tool, lint as lint_tool  # noqa: E402


# --------------------------------------------------------------------------- #
# Corpus: real Happy programs compiled by this harness.
# --------------------------------------------------------------------------- #

TOUR = os.path.join(_ROOT, "examples", "language_tour.hpy")
BACKEND = os.path.join(_ROOT, "examples", "backend_demo.hpy")
VERIFIED = os.path.join(_ROOT, "examples", "verified_demo.hpy")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def build_corpus() -> Dict[str, str]:
    """A small synthetic corpus that exercises many language features."""
    # A generated program with N structs, functions and app statements.
    lines = ["// generated benchmark corpus", "module bench.corpus", "import std.io", ""]
    for i in range(50):
        lines.append(f"type T{i} {{\n    a: Int\n    b: Int\n}}")
        lines.append(
            f"function f{i}(x: Int, y: Int) -> Int\n"
            f"  requires x >= 0, \"x non-negative\"\n"
            f"  ensures result >= 0\n"
            f"{{ return x + y }}"
        )
    lines.append("app Bench {")
    for i in range(50):
        lines.append(f"    println(str(f{i}({i}, 1)))")
    lines.append("}")
    generated = "\n".join(lines)

    corpus = {
        "language_tour.hpy": _read(TOUR),
        "backend_demo.hpy": _read(BACKEND),
        "verified_demo.hpy": _read(VERIFIED),
        "generated_50fn.hpy": generated,
    }
    return corpus


# --------------------------------------------------------------------------- #
# Measurement helpers
# --------------------------------------------------------------------------- #

@dataclass
class StageStat:
    name: str
    samples_ms: List[float] = field(default_factory=list)

    @property
    def mean_ms(self) -> float:
        return statistics.fmean(self.samples_ms)

    @property
    def median_ms(self) -> float:
        return statistics.median(self.samples_ms)

    @property
    def min_ms(self) -> float:
        return min(self.samples_ms)

    @property
    def p95_ms(self) -> float:
        s = sorted(self.samples_ms)
        idx = min(len(s) - 1, int(round(0.95 * (len(s) - 1))))
        return s[idx]

    @property
    def ops_per_sec(self) -> float:
        m = self.mean_ms
        return (1000.0 / m) if m > 0 else float("inf")

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "runs": len(self.samples_ms),
            "min_ms": round(self.min_ms, 4),
            "mean_ms": round(self.mean_ms, 4),
            "median_ms": round(self.median_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "ops_per_sec": round(self.ops_per_sec, 1),
        }


def time_stage(name: str, fn: Callable[[], object], repeat: int, warmup: int = 3) -> StageStat:
    stat = StageStat(name)
    for _ in range(warmup):
        fn()
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        stat.samples_ms.append((time.perf_counter() - t0) * 1000.0)
    return stat


# --------------------------------------------------------------------------- #
# The benchmark itself
# --------------------------------------------------------------------------- #

def run(repeat: int) -> dict:
    corpus = build_corpus()
    # Benchmark the richest example as the primary subject.
    subject_name = "backend_demo.hpy"
    subject = corpus[subject_name]
    filename = subject_name

    results: Dict[str, StageStat] = {}

    results["lex"] = time_stage(
        "lex", lambda: lexer.tokenize(subject, filename=filename), repeat
    )
    results["parse"] = time_stage(
        "parse", lambda: parser.parse(subject, filename=filename), repeat
    )
    results["semantic_typecheck"] = time_stage(
        "semantic_typecheck", lambda: semantic.analyze(subject, filename=filename), repeat
    )

    analysis = semantic.analyze(subject, filename=filename)
    results["ir_lowering"] = time_stage(
        "ir_lowering", lambda: ir_mod.lower(analysis, source=subject, filename=filename), repeat
    )

    module = ir_mod.lower(analysis, source=subject, filename=filename)
    results["optimize"] = time_stage(
        "optimize", lambda: optimizer.optimize(module), repeat
    )

    results["codegen_python"] = time_stage(
        "codegen_python",
        lambda: python_gen.generate(module, source=subject, filename=filename),
        repeat,
    )

    results["compile_to_python"] = time_stage(
        "compile_to_python",
        lambda: python_gen.compile_source(subject, filename=filename),
        repeat,
    )

    program = python_gen.compile_source(subject, filename=filename)
    sm = getattr(program, "sourcemap", None)
    sourcemap_anchors = len(sm.entries) if sm is not None and hasattr(sm, "entries") else None
    generated_python = getattr(program, "source", None)

    def _execute() -> object:
        ctx = RuntimeContext(filename=filename, source=subject, module=module,
                             sourcemap=getattr(program, "sourcemap", None))
        buf = io.StringIO()
        with redirect_stdout(buf):
            program.run(ctx)
        return buf.getvalue()

    results["end_to_end_execute"] = time_stage("end_to_end_execute", _execute, repeat)

    results["security_analyze"] = time_stage(
        "security_analyze",
        lambda: security.analyze_security(subject, filename=filename),
        repeat,
    )

    results["format"] = time_stage(
        "format", lambda: fmt_tool.format_source(subject, filename=filename), repeat
    )

    results["lint"] = time_stage(
        "lint", lambda: lint_tool.lint_source(subject, filename=filename), repeat
    )

    # Formatter idempotence check (a correctness metric, not a timing).
    once = fmt_tool.format_source(subject, filename=filename)
    once_text = once.formatted if hasattr(once, "formatted") else str(once)
    twice = fmt_tool.format_source(once_text, filename=filename)
    twice_text = twice.formatted if hasattr(twice, "formatted") else str(twice)
    formatter_idempotent = once_text == twice_text

    # Whole-corpus aggregate: full compile of every program.
    def _compile_all() -> int:
        n = 0
        for _name, src in corpus.items():
            python_gen.compile_source(src, filename=_name)
            n += 1
        return n

    results["compile_whole_corpus"] = time_stage("compile_whole_corpus", _compile_all, max(3, repeat // 3))

    # Repository size statistics.
    repo = repo_stats(_ROOT)

    return {
        "meta": {
            "tool": "happy",
            "version": _version(),
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "repeat": repeat,
            "subject": subject_name,
            "subject_loc": len(subject.splitlines()),
            "generated_python_loc": len(generated_python.splitlines()) if generated_python else None,
            "build_size_ratio": (
                round(len(generated_python.splitlines()) / len(subject.splitlines()), 3)
                if generated_python else None
            ),
            "sourcemap_anchors": sourcemap_anchors,
            "formatter_idempotent": formatter_idempotent,
        },
        "stages": {k: v.as_dict() for k, v in results.items()},
        "repo": repo,
    }


def _version() -> str:
    try:
        import happy
        return getattr(happy, "__version__", "unknown")
    except Exception:
        return "unknown"


def repo_stats(root: str) -> dict:
    py_files = 0
    py_lines = 0
    test_files = 0
    test_lines = 0
    happy_lines = 0
    modules = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git", ".pytest_cache"}]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            if fn.endswith(".py"):
                py_files += 1
                try:
                    n = sum(1 for _ in open(p, "r", encoding="utf-8", errors="ignore"))
                except OSError:
                    n = 0
                py_lines += n
                if rel.startswith("tests" + os.sep) or os.sep + "test_" in os.sep + rel or fn.startswith("test_"):
                    test_files += 1
                    test_lines += n
            elif fn.endswith(".hpy"):
                happy_lines += sum(1 for _ in open(p, "r", encoding="utf-8", errors="ignore"))
            if rel.startswith("happy" + os.sep) and fn == "__init__.py":
                modules.add(os.path.dirname(rel))
    return {
        "python_files": py_files,
        "python_lines": py_lines,
        "test_files": test_files,
        "test_lines": test_lines,
        "happy_example_lines": happy_lines,
        "package_initializers": len(modules),
    }


def render_human(data: dict) -> str:
    out = []
    m = data["meta"]
    out.append("Happy (.hpy) toolchain benchmark")
    out.append("=" * 62)
    out.append(f"happy {m['version']}  |  Python {m['python']}  |  {m['platform']}")
    out.append(f"subject: {m['subject']} ({m['subject_loc']} Loc .hpy)")
    out.append(f"runs per stage: {m['repeat']} (plus 3 warm-up runs)")
    if m.get("generated_python_loc"):
        out.append(
            f"codegen: {m['generated_python_loc']} lines Python "
            f"({m['build_size_ratio']}x Happy LOC), "
            f"{m['sourcemap_anchors']} source-map anchors"
        )
    out.append(f"formatter idempotent: {m['formatter_idempotent']}")
    out.append("")
    out.append(f"{'stage':<24}{'min ms':>9}{'mean ms':>10}{'median':>9}{'p95':>9}{'ops/s':>12}")
    out.append("-" * 73)
    for name, s in data["stages"].items():
        out.append(
            f"{name:<24}{s['min_ms']:>9.3f}{s['mean_ms']:>10.3f}"
            f"{s['median_ms']:>9.3f}{s['p95_ms']:>9.3f}{s['ops_per_sec']:>12.1f}"
        )
    out.append("")
    r = data["repo"]
    out.append("repository size")
    out.append("-" * 73)
    out.append(f"  python files           : {r['python_files']}")
    out.append(f"  python lines           : {r['python_lines']}")
    out.append(f"  test files / lines     : {r['test_files']} / {r['test_lines']}")
    out.append(f"  .hpy example lines     : {r['happy_example_lines']}")
    out.append(f"  package initializers   : {r['package_initializers']}")
    out.append("")
    out.append("NOTE: every value above was measured on this machine at run time.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Happy toolchain benchmarks")
    ap.add_argument("--repeat", type=int, default=20, help="runs per stage (default 20)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--out", type=str, default=None, help="write JSON to a file")
    args = ap.parse_args()

    data = run(max(1, args.repeat))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(render_human(data))
        if args.out:
            print(f"\n(JSON written to {args.out})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
