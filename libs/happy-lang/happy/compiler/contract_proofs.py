"""Static contract *proofs* (``requires`` / ``ensures`` / ``invariant``).

The existing :mod:`happy.compiler.contracts` engine type-checks contracts and
lowers them to run-time assertions.  This module goes one step further and
proves or refutes as many of them as possible **at compile time**, with no
external solver, using interval abstract interpretation.

Soundness rule
--------------
Every abstract value is an interval that is a *superset* of the values the
variable can really take.  Consequently:

* a condition that is true for every point of the intervals is **proved**;
* a condition that is false for every point is **definitely violated**;
* anything else is **unknown** and left to the run-time check.

Errors are reported only for definite violations, so the pass never rejects a
correct program; at worst it fails to prove a true contract ("unknown").

Diagnostics
-----------
``E4030``  a call provably violates the callee's ``requires``
``E4031``  an ``ensures`` is provably violated on every return path
``E4032``  the ``requires`` clauses contradict each other (no valid call exists)
``E4034``  a struct literal provably violates an ``invariant``
``W4033``  an ``ensures`` is provably violated on one return path
"""
from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import ast

INF = math.inf
_AND = {"&&", "and"}
_OR = {"||", "or"}
_CMP = {"<", "<=", ">", ">=", "==", "!="}
Tri = Optional[bool]  # True / False / None (unknown)


# ---------------------------------------------------------------------------
# Interval domain
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Interval:
    lo: float = -INF
    hi: float = INF
    integral: bool = False

    @property
    def empty(self) -> bool:
        return self.lo > self.hi

    @property
    def singleton(self) -> bool:
        return self.lo == self.hi and not math.isinf(self.lo)

    def hull(self, o: "Interval") -> "Interval":
        return Interval(min(self.lo, o.lo), max(self.hi, o.hi), self.integral and o.integral)

    def meet(self, o: "Interval") -> "Interval":
        return Interval(max(self.lo, o.lo), min(self.hi, o.hi), self.integral or o.integral)

    def __add__(self, o: "Interval") -> "Interval":
        return Interval(self.lo + o.lo, self.hi + o.hi, self.integral and o.integral)

    def __sub__(self, o: "Interval") -> "Interval":
        return Interval(self.lo - o.hi, self.hi - o.lo, self.integral and o.integral)

    def __neg__(self) -> "Interval":
        return Interval(-self.hi, -self.lo, self.integral)

    def __mul__(self, o: "Interval") -> "Interval":
        def m(a: float, b: float) -> float:
            return 0.0 if (a == 0 or b == 0) else a * b  # 0 * inf = 0

        p = [m(a, b) for a in (self.lo, self.hi) for b in (o.lo, o.hi)]
        return Interval(min(p), max(p), self.integral and o.integral)


TOP_INT = Interval(-INF, INF, True)
TOP = Interval(-INF, INF, False)
Env = Dict[str, Interval]


def _const(v: float, integral: bool) -> Interval:
    return Interval(v, v, integral)


def _join(a: Optional[Env], b: Optional[Env]) -> Optional[Env]:
    if a is None:
        return b
    if b is None:
        return a
    return {k: a[k].hull(b[k]) for k in a if k in b}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def eval_expr(e, env: Env, sums: Dict[str, "Summary"]) -> Interval:
    if isinstance(e, ast.IntLiteral):
        return _const(float(e.value), True)
    if isinstance(e, ast.FloatLiteral):
        return _const(float(e.value), False)
    if isinstance(e, ast.Identifier):
        return env.get(e.name, TOP)
    if isinstance(e, ast.UnaryOp):
        v = eval_expr(e.operand, env, sums)
        return -v if e.op == "-" else v if e.op == "+" else TOP
    if isinstance(e, ast.BinaryOp):
        if e.op in ("+", "-", "*"):
            a, b = eval_expr(e.left, env, sums), eval_expr(e.right, env, sums)
            return a + b if e.op == "+" else a - b if e.op == "-" else a * b
        if e.op == "**":
            a, b = eval_expr(e.left, env, sums), eval_expr(e.right, env, sums)
            if b.singleton and b.lo in (0.0, 1.0, 2.0) and a.integral:
                if b.lo == 0.0:
                    return _const(1.0, True)
                if b.lo == 1.0:
                    return a
                lo = 0.0 if a.lo <= 0 <= a.hi else min(a.lo * a.lo, a.hi * a.hi)
                return Interval(lo, max(a.lo * a.lo, a.hi * a.hi), True)
        return TOP
    if isinstance(e, ast.CallExpr) and isinstance(e.callee, ast.Identifier):
        name = e.callee.name
        if name in env:
            return TOP  # a local value shadows the function
        s = sums.get(name)
        if s is not None and s.result is not None:
            return s.result
        if name == "len":
            return Interval(0.0, INF, True)
    return TOP


def eval_cond(e, env: Env, sums: Dict[str, "Summary"]) -> Tri:
    if isinstance(e, ast.BoolLiteral):
        return bool(e.value)
    if isinstance(e, ast.UnaryOp) and e.op in ("!", "not"):
        t = eval_cond(e.operand, env, sums)
        return None if t is None else (not t)
    if isinstance(e, ast.BinaryOp):
        if e.op in _AND:
            l, r = eval_cond(e.left, env, sums), eval_cond(e.right, env, sums)
            if l is False or r is False:
                return False
            return True if (l is True and r is True) else None
        if e.op in _OR:
            l, r = eval_cond(e.left, env, sums), eval_cond(e.right, env, sums)
            if l is True or r is True:
                return True
            return False if (l is False and r is False) else None
        if e.op in _CMP:
            a, b = eval_expr(e.left, env, sums), eval_expr(e.right, env, sums)
            if a.empty or b.empty:
                return None
            if e.op == "<":
                return True if a.hi < b.lo else False if a.lo >= b.hi else None
            if e.op == "<=":
                return True if a.hi <= b.lo else False if a.lo > b.hi else None
            if e.op == ">":
                return True if a.lo > b.hi else False if a.hi <= b.lo else None
            if e.op == ">=":
                return True if a.lo >= b.hi else False if a.hi < b.lo else None
            disjoint = a.hi < b.lo or b.hi < a.lo
            same = a.singleton and b.singleton and a.lo == b.lo
            if e.op == "==":
                return True if same else False if disjoint else None
            return False if same else True if disjoint else None
    return None


_NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def narrow(e, env: Env, truth: bool, sums) -> Optional[Env]:
    """Assume ``e`` evaluates to ``truth``; ``None`` means that is impossible."""
    t = eval_cond(e, env, sums)
    if t is not None and t != truth:
        return None
    if isinstance(e, ast.UnaryOp) and e.op in ("!", "not"):
        return narrow(e.operand, env, not truth, sums)
    if isinstance(e, ast.BinaryOp):
        if (e.op in _AND and truth) or (e.op in _OR and not truth):
            mid = narrow(e.left, env, truth, sums)
            return None if mid is None else narrow(e.right, mid, truth, sums)
        if e.op in _CMP:
            return _narrow_cmp(e, env, truth, sums)
    return env


def _narrow_cmp(e: ast.BinaryOp, env: Env, truth: bool, sums) -> Optional[Env]:
    op = e.op if truth else _NEGATE[e.op]
    left, right = e.left, e.right
    if not isinstance(left, ast.Identifier) and isinstance(right, ast.Identifier):
        left, right, op = right, left, _FLIP[op]
    if not isinstance(left, ast.Identifier):
        return env
    cur = env.get(left.name, TOP)
    other = eval_expr(right, env, sums)
    if other.empty:
        return env
    lo, hi = cur.lo, cur.hi

    def up(x: float) -> float:  # smallest integer >= x
        return x if math.isinf(x) else float(math.ceil(x))

    def down(x: float) -> float:  # largest integer <= x
        return x if math.isinf(x) else float(math.floor(x))

    if cur.integral:
        # Integer variables: bounds snap to integers whatever the other side is
        # (``x < 2.5`` means ``x <= 2``, not ``x <= 1.5``).
        if op == "<":
            hi = min(hi, up(other.hi) - 1.0)
        elif op == "<=":
            hi = min(hi, down(other.hi))
        elif op == ">":
            lo = max(lo, down(other.lo) + 1.0)
        elif op == ">=":
            lo = max(lo, up(other.lo))
        elif op == "==":
            lo, hi = max(lo, up(other.lo)), min(hi, down(other.hi))
        elif op == "!=" and other.singleton:
            if lo == other.lo:
                lo += 1.0
            if hi == other.lo:
                hi -= 1.0
    else:
        # Real variables: a strict bound cannot be tightened (superset is sound).
        if op in ("<", "<="):
            hi = min(hi, other.hi)
        elif op in (">", ">="):
            lo = max(lo, other.lo)
        elif op == "==":
            lo, hi = max(lo, other.lo), min(hi, other.hi)
    new = Interval(lo, hi, cur.integral)
    if new.empty:
        return None
    out = dict(env)
    out[left.name] = new
    return out


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------
@dataclass
class Summary:
    decl: ast.FunctionDecl
    requires: List[ast.ContractClause]
    ensures: List[ast.ContractClause]
    param_env: Env
    result: Optional[Interval] = None  # bound on the result implied by `ensures`


@dataclass
class ProofReport:
    proved: int = 0
    violated: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.proved + self.violated + self.unknown


def _domain(type_node) -> Interval:
    return TOP_INT if getattr(type_node, "name", None) == "Int" else TOP


def show(e) -> str:
    """Compact rendering of a condition for messages."""
    if isinstance(e, ast.IntLiteral):
        return str(e.value)
    if isinstance(e, ast.FloatLiteral):
        return repr(e.value)
    if isinstance(e, ast.BoolLiteral):
        return "true" if e.value else "false"
    if isinstance(e, ast.StringLiteral):
        return '"..."'
    if isinstance(e, ast.Identifier):
        return e.name
    if isinstance(e, ast.UnaryOp):
        return f"{e.op}{show(e.operand)}"
    if isinstance(e, ast.BinaryOp):
        return f"({show(e.left)} {e.op} {show(e.right)})"
    if isinstance(e, ast.CallExpr):
        return f"{show(e.callee)}(...)"
    if isinstance(e, ast.MemberExpr):
        return f"{show(e.obj)}.{e.name}"
    return "<expr>"


#: (severity, code, message, location, suggestion)
Reporter = Callable[[str, str, str, object, Optional[str]], None]


class ContractVerifier:
    def __init__(self, program: ast.Program, report: Reporter) -> None:
        self.program, self.report = program, report
        self.stats = ProofReport()
        self.summaries: Dict[str, Summary] = {}
        self.structs: Dict[str, ast.StructDecl] = {}
        #: Per function, the interval computed for every return path.  Kept for
        #: inspection and for the soundness fuzzer (``tools/fuzz_contracts.py``).
        self.return_intervals: Dict[str, List[Interval]] = {}

    def run(self) -> ProofReport:
        funcs = [d for d in self.program.declarations if isinstance(d, ast.FunctionDecl)]
        for d in self.program.declarations:
            if isinstance(d, ast.StructDecl):
                self.structs[d.name] = d
        for f in funcs:
            self.summaries[f.name] = self._summarise(f)
        for f in funcs:
            if f.body is not None:
                self._verify_function(f)
        for d in self.program.declarations:
            if isinstance(d, ast.AppDecl) and d.body is not None:
                self._walk_block(d.body, {}, set(), None)
        return self.stats

    def _summarise(self, f: ast.FunctionDecl) -> Summary:
        reqs = [c for c in f.contracts if c.kind == "requires"]
        ens = [c for c in f.contracts if c.kind == "ensures"]
        s = Summary(f, reqs, ens, {p.name: _domain(p.type_annotation) for p in f.params})
        if getattr(f.returns, "name", None) in ("Int", "Float"):
            res = _domain(f.returns)
            for c in ens:
                n = narrow(c.condition, {"result": res}, True, {})
                if n is not None:
                    res = n["result"]
            if res.lo > -INF or res.hi < INF:
                s.result = res
        return s

    def _verify_function(self, f: ast.FunctionDecl) -> None:
        s = self.summaries[f.name]
        env: Optional[Env] = dict(s.param_env)
        for c in s.requires:
            env = narrow(c.condition, env, True, self.summaries)
            if env is None:
                self.stats.violated += 1
                self.report(
                    "error", "E4032",
                    f"the 'requires' clauses of '{f.name}' contradict each other, "
                    f"so no call can ever satisfy them",
                    c.loc, "remove or correct one of the preconditions",
                )
                return
        assigned = _assigned_names(f.body)
        ens_env = {k: (v if k not in assigned else s.param_env[k]) for k, v in env.items()}
        returns: List[Tuple[Env, Interval, object]] = []
        self._walk_block(f.body, dict(env), set(env), returns)
        self.return_intervals[f.name] = [r for _e, r, _l in returns]
        self._check_ensures(f, s, ens_env, returns)

    def _check_ensures(self, f, s: Summary, ens_env: Env, returns) -> None:
        if not s.ensures:
            return
        if not returns:
            self.stats.unknown += len(s.ensures)
            return
        for c in s.ensures:
            verdicts = []
            for _env, r, loc in returns:
                e2 = dict(ens_env)
                e2["result"] = r
                verdicts.append((eval_cond(c.condition, e2, self.summaries), loc))
            if all(v is True for v, _ in verdicts):
                self.stats.proved += 1
            elif all(v is False for v, _ in verdicts):
                self.stats.violated += 1
                self.report(
                    "error", "E4031",
                    f"'ensures {show(c.condition)}' of '{f.name}' is violated on every return path",
                    c.loc, "fix the postcondition or the returned value",
                )
            else:
                bad = [loc for v, loc in verdicts if v is False]
                if bad:
                    self.stats.violated += 1
                    for loc in bad:
                        self.report(
                            "warning", "W4033",
                            f"this return always violates 'ensures {show(c.condition)}' of '{f.name}'",
                            loc, "the contract will fail at run time if this path runs",
                        )
                else:
                    self.stats.unknown += 1

    # -- statements -----------------------------------------------------
    def _walk_block(self, block, env: Optional[Env], names: Set[str], returns) -> Optional[Env]:
        if block is None:
            return env
        local = set(names)
        for st in block.statements:
            if env is None:
                break
            env = self._walk_stmt(st, env, local, returns)
        return env

    def _walk_stmt(self, st, env: Env, names: Set[str], returns) -> Optional[Env]:
        if isinstance(st, ast.LetStmt):
            self._scan(st.value, env, names)
            dom = _domain(st.type_annotation) if st.type_annotation is not None else None
            if st.value is not None:
                v = eval_expr(st.value, env, self.summaries)
                if dom is not None and dom.integral and not v.integral:
                    v = TOP_INT
            else:
                v = dom if dom is not None else TOP
            names.add(st.name)
            return {**env, st.name: v}
        if isinstance(st, ast.AssignStmt):
            self._scan(st.value, env, names)
            if isinstance(st.target, ast.Identifier):
                cur = env.get(st.target.name, TOP)
                v = eval_expr(st.value, env, self.summaries)
                if st.op == "=":
                    new = v
                elif st.op in ("+=", "-=", "*="):
                    new = {"+=": cur + v, "-=": cur - v, "*=": cur * v}[st.op]
                else:
                    new = Interval(-INF, INF, cur.integral)
                env = {**env, st.target.name: new}
            return env
        if isinstance(st, ast.ExprStmt):
            self._scan(st.expr, env, names)
            return env
        if isinstance(st, ast.ReturnStmt):
            self._scan(st.value, env, names)
            if returns is not None:
                r = eval_expr(st.value, env, self.summaries) if st.value is not None else TOP
                returns.append((env, r, st.loc))
            return None
        if isinstance(st, ast.IfStmt):
            return self._walk_if(st, env, names, returns)
        if isinstance(st, (ast.WhileStmt, ast.ForStmt)):
            self._scan(getattr(st, "condition", None) or getattr(st, "iterable", None), env, names)
            havoc = _assigned_names(st.body)
            loop_env = {k: (Interval(-INF, INF, v.integral) if k in havoc else v) for k, v in env.items()}
            extra = set()
            if isinstance(st, ast.ForStmt):
                loop_env[st.variable] = TOP
                extra = {st.variable}
            self._walk_block(st.body, loop_env, names | extra, returns)
            return {k: (Interval(-INF, INF, v.integral) if k in havoc else v) for k, v in env.items()}
        if isinstance(st, ast.MatchStmt):
            return self._walk_match(st, env, names, returns)
        return env

    def _walk_match(self, st: ast.MatchStmt, env: Env, names, returns) -> Optional[Env]:
        self._scan(st.subject, env, names)
        out: Optional[Env] = None
        any_open = False
        for arm in st.arms:
            aenv = dict(env)
            bound = _pattern_bindings(arm.pattern)
            for b in bound:
                aenv[b] = TOP
            body = arm.body
            if getattr(arm, "bare_expr", False) and body and len(body.statements) == 1 \
                    and isinstance(body.statements[0], ast.ExprStmt):
                inner = body.statements[0]
                self._scan(inner.expr, aenv, names | set(bound))
                if returns is not None:
                    returns.append((aenv, eval_expr(inner.expr, aenv, self.summaries), inner.loc))
                continue  # a bare arm yields the function's result
            res = self._walk_block(body, aenv, names | set(bound), returns)
            if res is not None:
                any_open = True
                out = _join(out, {k: v for k, v in res.items() if k in env})
        if not st.arms:
            return env
        return out if any_open else None

    def _walk_if(self, st: ast.IfStmt, env: Env, names, returns) -> Optional[Env]:
        self._scan(st.condition, env, names)
        then_env = narrow(st.condition, env, True, self.summaries)
        else_env = narrow(st.condition, env, False, self.summaries)
        t_out = self._walk_block(st.then_branch, then_env, names, returns) if then_env is not None else None
        if st.else_branch is None:
            e_out = else_env
        elif else_env is None:
            e_out = None
        elif isinstance(st.else_branch, ast.IfStmt):
            e_out = self._walk_if(st.else_branch, else_env, names, returns)
        else:
            e_out = self._walk_block(st.else_branch, else_env, names, returns)
        if t_out is None and e_out is None:
            return None
        keep = set(env)
        return _join(
            {k: v for k, v in t_out.items() if k in keep} if t_out is not None else None,
            {k: v for k, v in e_out.items() if k in keep} if e_out is not None else None,
        )

    # -- calls and struct literals --------------------------------------
    def _scan(self, node, env: Env, names: Set[str]) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                self._scan(item, env, names)
            return
        if not isinstance(node, ast.Node):
            return
        cls = type(node).__name__
        if "Lambda" in cls or "Closure" in cls:
            return
        if isinstance(node, ast.CallExpr):
            self._check_call(node, env, names)
        elif isinstance(node, ast.StructLiteral):
            self._check_struct(node, env)
        for f in dataclasses.fields(node):
            if f.name != "loc":
                child = getattr(node, f.name, None)
                if isinstance(child, (ast.Node, list, tuple)):
                    self._scan(child, env, names)

    def _check_call(self, call: ast.CallExpr, env: Env, names: Set[str]) -> None:
        if not isinstance(call.callee, ast.Identifier):
            return
        name = call.callee.name
        s = self.summaries.get(name)
        if s is None or name in names or name in env or not s.requires:
            return
        params = s.decl.params
        if len(call.args) > len(params):
            return
        cenv: Env = dict(s.param_env)
        for p, arg in zip(params, call.args):
            v = eval_expr(arg, env, self.summaries)
            if not v.empty:
                cenv[p.name] = cenv[p.name].meet(v)
        for p in params[len(call.args):]:
            if p.default is None:
                return  # arity error: reported by the type checker
            cenv[p.name] = eval_expr(p.default, {}, self.summaries)
        for c in s.requires:
            t = eval_cond(c.condition, cenv, self.summaries)
            if t is True:
                self.stats.proved += 1
            elif t is False:
                self.stats.violated += 1
                note = f' ("{c.message}")' if c.message else ""
                self.report(
                    "error", "E4030",
                    f"this call to '{name}' violates its precondition "
                    f"'requires {show(c.condition)}'{note}",
                    call.loc, "pass arguments that satisfy the precondition",
                )
            else:
                self.stats.unknown += 1

    def _check_struct(self, lit: ast.StructLiteral, env: Env) -> None:
        decl = self.structs.get(lit.type_name)
        if decl is None or not decl.invariants:
            return
        fenv: Env = {fd.name: _domain(fd.type_annotation) for fd in decl.fields}
        for fi in lit.fields:
            if fi.name in fenv and fi.value is not None:
                v = eval_expr(fi.value, env, self.summaries)
                if not v.empty:
                    fenv[fi.name] = fenv[fi.name].meet(v)
        for inv in decl.invariants:
            t = eval_cond(inv.condition, fenv, self.summaries)
            if t is True:
                self.stats.proved += 1
            elif t is False:
                self.stats.violated += 1
                note = f' ("{inv.message}")' if inv.message else ""
                self.report(
                    "error", "E4034",
                    f"this '{lit.type_name}' literal violates its invariant "
                    f"'{show(inv.condition)}'{note}",
                    lit.loc, "use field values that satisfy the invariant",
                )
            else:
                self.stats.unknown += 1


def _assigned_names(block) -> Set[str]:
    out: Set[str] = set()

    def visit(node) -> None:
        if isinstance(node, (list, tuple)):
            for x in node:
                visit(x)
            return
        if not isinstance(node, ast.Node):
            return
        if isinstance(node, ast.AssignStmt) and isinstance(node.target, ast.Identifier):
            out.add(node.target.name)
        for f in dataclasses.fields(node):
            if f.name != "loc":
                child = getattr(node, f.name, None)
                if isinstance(child, (ast.Node, list, tuple)):
                    visit(child)

    visit(block)
    return out


def _pattern_bindings(pat) -> List[str]:
    if pat is None:
        return []
    out: List[str] = []
    name = getattr(pat, "name", None)
    if isinstance(name, str) and name != "_" and getattr(pat, "kind", "") in ("binding", "ident", "name"):
        out.append(name)
    out.extend(b for b in (getattr(pat, "bindings", None) or []) if isinstance(b, str))
    return out


def verify_program(program: ast.Program, report: Reporter) -> ProofReport:
    """Run the verifier over a parsed program, reporting through ``report``."""
    return ContractVerifier(program, report).run()
