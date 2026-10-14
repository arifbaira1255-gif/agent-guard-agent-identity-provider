"""Soundness fuzzer for the static contract prover.

Generates random functions with ``requires`` / ``ensures`` and random call
sites, asks the prover for its verdicts, then checks every claim by brute force
over a grid of inputs using an independent Python evaluation.

Claims checked (a failure means the prover is UNSOUND):
  * ensures "proved"           -> holds for every valid input
  * E4031 (violated all paths) -> fails for every valid input
  * E4032 (contradiction)      -> no input satisfies the requires clauses
  * call "proved"              -> the call's requires holds
  * E4030 (call violates)      -> the call's requires is false
Also reports precision (how many contracts were decided).
Usage: python tools/fuzz_contracts.py [count] [seed]
"""
from __future__ import annotations

import random
import sys

sys.path.insert(0, ".")
from happy.compiler import parse
from happy.compiler import ast as hast
from happy.compiler.contract_proofs import (
    ContractVerifier, Interval, eval_cond, eval_expr, narrow, verify_program,
)

GRID = range(-7, 8)


def gen_expr(rng, depth):
    if depth <= 0 or rng.random() < 0.3:
        return rng.choice(["a", "b", str(rng.randint(0, 6)), str(rng.randint(0, 6))])
    k = rng.random()
    x, y = gen_expr(rng, depth - 1), gen_expr(rng, depth - 1)
    if k < 0.75:
        return f"({x} {rng.choice('+-*')} {y})"
    return f"(0 - {x})"


def gen_cmp(rng):
    return f"{gen_expr(rng, 1)} {rng.choice(['<', '<=', '>', '>=', '==', '!='])} {gen_expr(rng, 1)}"


def gen_cond(rng):
    c = gen_cmp(rng)
    return f"{c} && {gen_cmp(rng)}" if rng.random() < 0.3 else c


def gen_body(rng, depth, ind):
    pad = "  " * ind
    if depth <= 0 or rng.random() < 0.3:
        e = gen_expr(rng, 2)
        return [f"{pad}return {e}"], ("ret", e)
    cond = gen_cond(rng)
    t_src, t_ast = gen_body(rng, depth - 1, ind + 1)
    e_src, e_ast = gen_body(rng, depth - 1, ind + 1)
    src = [f"{pad}if {cond} {{", *t_src, f"{pad}}} else {{", *e_src, f"{pad}}}"]
    return src, ("if", cond, t_ast, e_ast)


def gen_flow(rng):
    """Straight-line + branching + loop body that assigns a local ``t``.

    Returns (happy_lines, python_lines); both compute the same function.
    """
    def ex(d=2):
        return gen_expr(rng, d).replace("a", "@").replace("b", "a").replace("@", "a") if False else \
            rng.choice([gen_expr(rng, d), f"(t {rng.choice('+-*')} {gen_expr(rng, 1)})", "t"])

    h, p = [f"  var t = {gen_expr(rng, 1)}"], []
    p.append(f"    t = {h[0].split('= ', 1)[1]}")
    for _ in range(rng.randint(1, 3)):
        k = rng.random()
        if k < 0.45:
            cond, e1 = gen_cond(rng), ex()
            h += [f"  if {cond} {{", f"    t = {e1}", "  }"]
            p += [f"    if {py(cond)}:", f"        t = {e1}"]
        elif k < 0.8:
            cond, e1, e2 = gen_cond(rng), ex(), ex()
            h += [f"  if {cond} {{", f"    t = {e1}", "  } else {", f"    t = {e2}", "  }"]
            p += [f"    if {py(cond)}:", f"        t = {e1}", "    else:", f"        t = {e2}"]
        else:
            e1 = ex(1)
            h += ["  var k = 0", "  while k < 3 {", "    k = k + 1", f"    t = {e1}", "  }"]
            p += ["    k = 0", "    while k < 3:", "        k = k + 1", f"        t = {e1}"]
    ret = rng.choice(["t", f"(t {rng.choice('+-*')} {gen_expr(rng, 1)})", gen_expr(rng, 1)])
    h.append(f"  return {ret}")
    p.append(f"    return {ret}")
    return h, p


def py(expr):
    return expr.replace("&&", " and ")


def run_body(node, env):
    if node[0] == "ret":
        return eval(py(node[1]), {}, env)  # noqa: S307 - generator output
    return run_body(node[2] if eval(py(node[1]), {}, env) else node[3], env)


_AST_CACHE = {}


def _parsed(kind, text):
    """Parse an expression / condition into its AST (cached)."""
    key = (kind, text)
    if key not in _AST_CACHE:
        if kind == "expr":
            src = f"function f(a: Int, b: Int) -> Int {{\n return {text}\n}}\n"
            prog = parse(src, filename="d.hpy")
            _AST_CACHE[key] = prog.declarations[0].body.statements[0].value
        else:
            src = f"function f(a: Int, b: Int) -> Int\n  requires {text}\n{{\n return 0\n}}\n"
            prog = parse(src, filename="d.hpy")
            _AST_CACHE[key] = prog.declarations[0].contracts[0].condition
    return _AST_CACHE[key]


def _rand_interval(rng):
    lo = rng.choice([-INFV, rng.randint(-8, 8)])
    hi = rng.choice([INFV, rng.randint(-8, 8)])
    if lo != -INFV and hi != INFV and lo > hi:
        lo, hi = hi, lo
    elif lo == INFV or (hi == -INFV):
        lo, hi = -INFV, INFV
    return Interval(lo, hi, True)


INFV = float("inf")


def domain_check(rng, expr_src, cond_src):
    """Directly test eval_expr / eval_cond / narrow against concrete points."""
    env = {"a": _rand_interval(rng), "b": _rand_interval(rng)}
    pts = [
        (a, b)
        for a in range(-9, 10)
        for b in range(-9, 10)
        if env["a"].lo <= a <= env["a"].hi and env["b"].lo <= b <= env["b"].hi
    ]
    problems = []
    e_ast, c_ast = _parsed("expr", expr_src), _parsed("cond", cond_src)
    iv = eval_expr(e_ast, env, {})
    for a, b in pts:
        v = eval(py(expr_src), {}, {"a": a, "b": b})  # noqa: S307
        if not (iv.lo <= v <= iv.hi):
            problems.append(f"eval_expr: {expr_src} = {v} at ({a},{b}) outside [{iv.lo},{iv.hi}] for env a={env['a'].lo}..{env['a'].hi} b={env['b'].lo}..{env['b'].hi}")
            break
    concrete = [bool(eval(py(cond_src), {}, {"a": a, "b": b})) for a, b in pts]  # noqa: S307
    t = eval_cond(c_ast, env, {})
    if t is True and not all(concrete):
        problems.append(f"eval_cond: {cond_src} claimed True but false at {pts[concrete.index(False)]}")
    if t is False and any(concrete):
        problems.append(f"eval_cond: {cond_src} claimed False but true at {pts[concrete.index(True)]}")
    for truth in (True, False):
        n = narrow(c_ast, env, truth, {})
        sat = [pt for pt, c in zip(pts, concrete) if c == truth]
        if n is None:
            if sat:
                problems.append(f"narrow({cond_src}, {truth}) said infeasible but {sat[0]} satisfies it")
        else:
            for a, b in sat:
                if not (n["a"].lo <= a <= n["a"].hi and n["b"].lo <= b <= n["b"].hi):
                    problems.append(f"narrow({cond_src}, {truth}) dropped satisfying point ({a},{b})")
                    break
    return problems


LAST = {}


def collect(src):
    out = []
    v = ContractVerifier(parse(src, filename="fz.hpy"), lambda sev, code, msg, loc, hint: out.append(code))
    rep = v.run()
    LAST["returns"] = v.return_intervals.get("f", [])
    return rep, out


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rng = random.Random(seed)
    unsound, decided, total = 0, 0, 0
    for i in range(count):
        reqs = [gen_cond(rng) for _ in range(rng.randint(1, 2))]
        body_src, body = gen_body(rng, rng.randint(0, 2), 1)
        mode = ("ensures", "call", "flow")[i % 3]
        flow_py = None
        ens = "x" if mode in ("ensures", "flow") else None
        if mode == "flow":
            body_src, flow_py = gen_flow(rng)
        if ens is not None:  # ensures talks about `result`
            ens = f"result {rng.choice(['<', '<=', '>', '>=', '==', '!='])} {gen_expr(rng, 1)}"
        ca, cb = rng.randint(-8, 8), rng.randint(-8, 8)
        src = "function f(a: Int, b: Int) -> Int\n"
        src += "".join(f"  requires {r}\n" for r in reqs)
        if ens:
            src += f"  ensures {ens}\n"
        src += "{\n" + "\n".join(body_src) + "\n}\n"
        src += f"app A {{\n  println(str(f({ca}, {cb})))\n}}\n" if mode == "call" else "app A {\n  println(\"x\")\n}\n"
        try:
            rep, codes = collect(src)
        except Exception as exc:  # noqa: BLE001
            print(f"[{i}] PROVER CRASH {type(exc).__name__}: {exc}\n{src}")
            unsound += 1
            continue
        total += 1
        for dp in (domain_check(rng, gen_expr(rng, 3), gen_cond(rng)) for _ in range(4)):
            if dp:
                unsound += 1
                if unsound <= 4:
                    print(f"[{i}] DOMAIN UNSOUND: {dp}")

        def req_ok(a, b):
            return all(eval(py(r), {}, {"a": a, "b": b}) for r in reqs)

        valid = [(a, b) for a in GRID for b in GRID if req_ok(a, b)]
        problems = []
        if "E4032" in codes and valid:
            problems.append(f"E4032 but {valid[0]} satisfies the requires")
        if mode in ("ensures", "flow") and "E4032" not in codes:
            if mode == "flow":
                ns = {}
                exec("def g(a, b):\n" + "\n".join(flow_py), ns)  # noqa: S102 - generator output
                results = [ns["g"](a, b) for a, b in valid]
            else:
                results = [run_body(body, {"a": a, "b": b}) for a, b in valid]
            holds = [eval(py(f"result {ens[7:]}"), {}, {"a": a, "b": b, "result": r}) for (a, b), r in zip(valid, results)]
            # Direct flow-soundness oracle: each concrete result must lie inside
            # the interval computed for *some* return path.
            ivs = LAST["returns"]
            for (a, b), r in zip(valid, results):
                if ivs and not any(iv.lo <= r <= iv.hi for iv in ivs):
                    problems.append(f"flow: result {r} at ({a},{b}) outside every return interval {[(iv.lo, iv.hi) for iv in ivs]}")
                    break
            if rep.proved == 1 and not all(holds):
                bad = valid[holds.index(False)]
                problems.append(f"ensures PROVED but fails at {bad}")
            if "E4031" in codes and any(holds):
                good = valid[holds.index(True)]
                problems.append(f"E4031 (violated everywhere) but holds at {good}")
            decided += 1 if rep.proved + rep.violated else 0
        if mode == "call" and "E4032" not in codes:
            ok = req_ok(ca, cb)
            if rep.proved >= len(reqs) and not ok:
                problems.append(f"call PROVED but requires is false at ({ca}, {cb})")
            if "E4030" in codes and ok:
                problems.append(f"E4030 but requires holds at ({ca}, {cb})")
            decided += 1 if rep.proved + rep.violated else 0
        if problems:
            unsound += 1
            if unsound <= 4:
                print(f"[{i}] UNSOUND: {problems}\n{src}")
    print(f"{total} programs, {unsound} soundness failures, {decided} with a static verdict (seed={seed})")
    return 1 if unsound else 0


if __name__ == "__main__":
    raise SystemExit(main())
