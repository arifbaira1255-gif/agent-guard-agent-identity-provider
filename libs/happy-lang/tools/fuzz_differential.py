"""Differential fuzzer for the Happy compiler.

Generates random well-typed expression programs and checks three oracles:
  1. optimizer ON vs OFF give the same output,
  2. ``happy fmt`` output behaves identically and is idempotent,
  3. integer ``+ - *`` and comparisons agree with a Python reference.
Usage: python tools/fuzz_differential.py [count] [seed]
"""
from __future__ import annotations

import random
import sys

sys.path.insert(0, ".")
from happy.backend import compile_source as backend_compile
from happy.runtime import RuntimeContext
from happy.tools.fmt import format_source


def gen_int(rng: random.Random, depth: int) -> str:
    if depth <= 0 or rng.random() < 0.25:
        n = rng.randint(0, 9)
        return str(n) if rng.random() < 0.8 else f"({-n})"
    k = rng.random()
    a, b = gen_int(rng, depth - 1), gen_int(rng, depth - 1)
    if k < 0.55:
        return f"({a} {rng.choice('+-*')} {b})" if rng.random() < 0.6 else f"{a} {rng.choice('+-*')} {b}"
    if k < 0.7:
        return f"-({a})"
    if k < 0.85:
        return f"({a}) ** {rng.randint(0, 3)}"
    return f"len([{a}, {b}])"


def gen_bool(rng: random.Random, depth: int) -> str:
    a, b = gen_int(rng, depth), gen_int(rng, depth)
    return f"({a}) {rng.choice(['<', '<=', '>', '>=', '==', '!='])} ({b})"


def run(src: str, optimize: bool) -> str:
    prog = backend_compile(src, filename="fz.hpy", optimize=optimize, strict=True)
    ctx = RuntimeContext(filename="fz.hpy", module=prog.module, sourcemap=prog.sourcemap)
    res = prog.run(ctx)
    return getattr(res, "output", None) or ctx.output


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rng = random.Random(seed)
    failures = 0
    for i in range(count):
        e = gen_int(rng, rng.randint(1, 4)) if rng.random() < 0.7 else gen_bool(rng, 2)
        src = f"app A {{\n println(str({e}))\n}}\n"
        problems = []
        try:
            on, off = run(src, True), run(src, False)
            if on != off:
                problems.append(f"optimizer changed result: on={on!r} off={off!r}")
            fmt = format_source(src).formatted
            if run(fmt, True) != on:
                problems.append(f"formatter changed result: {fmt.strip()!r}")
            if format_source(fmt).formatted != fmt:
                problems.append("formatter not idempotent")
            py = e.replace("len([", "_len([").replace("true", "True")
            ref = eval(py, {"_len": len})  # noqa: S307 - trusted generator output
            want = ("true" if ref else "false") if isinstance(ref, bool) else str(ref)
            if on.strip() != want:
                problems.append(f"differs from Python: happy={on.strip()!r} python={want!r}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"crash: {type(exc).__name__}: {str(exc)[:120]}")
        if problems:
            failures += 1
            if failures <= 8:
                print(f"[{i}] {e}")
                for p in problems:
                    print("    -", p)
    print(f"{count} programs, {failures} failing (seed={seed})")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
