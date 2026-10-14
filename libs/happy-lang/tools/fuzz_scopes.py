"""Scope fuzzer: random nested let / for / if / mutable-assign programs checked
against an independent reference interpreter with proper lexical scopes."""
from __future__ import annotations

import random
import sys

sys.path.insert(0, ".")
from happy.backend import compile_source as backend_compile
from happy.runtime import RuntimeContext

NAMES = ["a", "b", "c", "x", "i"]


def gen_block(rng, env, depth, budget, loop_var=None):
    """env: names visible; a ``for`` variable lives in the body scope."""
    stmts, here = [], ({loop_var} if loop_var else set())
    for _ in range(rng.randint(1, 4)):
        k = rng.random()
        if k < 0.35 and len(here) < len(NAMES):
            name = rng.choice([n for n in NAMES if n not in here])
            e = gen_expr(rng, env + sorted(here))
            stmts.append(("let", name, e)); here.add(name)
        elif k < 0.6 and (env or here):
            stmts.append(("print", gen_expr(rng, env + sorted(here))))
        elif k < 0.8 and depth > 0:
            blk = gen_block(rng, env + sorted(here), depth - 1, budget)
            stmts.append(("if", rng.choice([True, True, False]), blk))
        elif depth > 0:
            var = rng.choice(NAMES)
            blk = gen_block(rng, env + sorted(here) + [var], depth - 1, budget, loop_var=var)
            stmts.append(("for", var, [rng.randint(0, 5) for _ in range(rng.randint(0, 3))], blk))
        else:
            stmts.append(("print", gen_expr(rng, env + sorted(here)) if (env or here) else ("int", 1)))
    return stmts


def gen_expr(rng, names):
    if not names or rng.random() < 0.25:
        return ("int", rng.randint(0, 9))
    n = rng.choice(names)
    if rng.random() < 0.5:
        return ("var", n)
    return ("add", ("var", n), ("int", rng.randint(1, 9)))


def src_expr(e):
    return {"int": lambda: str(e[1]), "var": lambda: e[1],
            "add": lambda: f"{src_expr(e[1])} + {src_expr(e[2])}"}[e[0]]()


def src_block(stmts, ind):
    pad, out = "  " * ind, []
    for s in stmts:
        if s[0] == "let":
            out.append(f"{pad}let {s[1]} = {src_expr(s[2])}")
        elif s[0] == "print":
            out.append(f"{pad}println(str({src_expr(s[1])}))")
        elif s[0] == "if":
            out.append(f"{pad}if {'true' if s[1] else 'false'} {{")
            out += src_block(s[2], ind + 1)
            out.append(f"{pad}}}")
        else:
            out.append(f"{pad}for {s[1]} in [{', '.join(map(str, s[2]))}] {{")
            out += src_block(s[3], ind + 1)
            out.append(f"{pad}}}")
    return out


def ev(e, scopes):
    if e[0] == "int":
        return e[1]
    if e[0] == "var":
        for sc in reversed(scopes):
            if e[1] in sc:
                return sc[e[1]]
        raise KeyError(e[1])
    return ev(e[1], scopes) + ev(e[2], scopes)


def ref(stmts, scopes, out):
    scopes.append({})
    for s in stmts:
        if s[0] == "let":
            scopes[-1][s[1]] = ev(s[2], scopes)
        elif s[0] == "print":
            out.append(str(ev(s[1], scopes)))
        elif s[0] == "if":
            if s[1]:
                ref(s[2], scopes, out)
        else:
            for v in s[2]:
                scopes.append({s[1]: v})
                ref(s[3], scopes, out)
                scopes.pop()
    scopes.pop()


def run(src):
    prog = backend_compile(src, filename="sc.hpy", strict=True)
    ctx = RuntimeContext(filename="sc.hpy", module=prog.module, sourcemap=prog.sourcemap)
    res = prog.run(ctx)
    return getattr(res, "output", None) or ctx.output


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rng, bad, skipped = random.Random(seed), 0, 0
    for i in range(count):
        stmts = gen_block(rng, [], 3, [0])
        src = "app A {\n" + "\n".join(src_block(stmts, 1)) + "\n}\n"
        try:
            out = []
            ref(stmts, [], out)
            want = "".join(x + "\n" for x in out)
        except KeyError:
            skipped += 1
            continue
        try:
            got = run(src)
        except Exception as exc:  # noqa: BLE001
            got = f"CRASH {type(exc).__name__}: {str(exc)[:200]}"
        if got != want:
            bad += 1
            if bad <= 3:
                print(f"--- case {i}\n{src}want={want!r}\n got={got!r}")
    print(f"{count} programs ({skipped} skipped), {bad} mismatches (seed={seed})")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
