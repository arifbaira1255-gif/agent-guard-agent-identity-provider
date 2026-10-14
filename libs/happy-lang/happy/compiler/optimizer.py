"""The Happy IR optimizer (Step 8).

The optimizer runs between IR lowering and code generation and performs a
small set of *semantics-preserving* transformations on the typed IR:

* **constant folding** — arithmetic, comparison, boolean and string ``+``
  expressions over literals are evaluated at compile time;
* **constant-condition pruning** — ``if`` with a constant condition, ``while``
  with a constant-false condition, and ``requires``/``ensures``/``rule`` clauses
  whose predicate is literally ``true`` are simplified away;
* **dead-code elimination** — statements after a ``return``/``break``/
  ``continue`` in the same block are removed;
* **pure inlining** — calls to *pure* functions whose body is a single
  ``return <expr>`` are inlined when the arguments are side-effect free.

Every transformation is deterministic: nodes are visited in source order and
no sets/dicts are iterated without a stable ordering.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import ir

__all__ = ["OptimizationReport", "Optimizer", "optimize", "DEFAULT_LEVEL"]


#: Default optimisation level used by the compile pipeline.
DEFAULT_LEVEL = 2


@dataclass
class OptimizationReport:
    """Counts of the transformations the optimizer applied."""

    folded_expressions: int = 0
    pruned_conditions: int = 0
    pruned_contracts: int = 0
    eliminated_statements: int = 0
    inlined_calls: int = 0
    level: int = DEFAULT_LEVEL

    @property
    def total(self) -> int:
        return (
            self.folded_expressions
            + self.pruned_conditions
            + self.pruned_contracts
            + self.eliminated_statements
            + self.inlined_calls
        )

    def as_dict(self) -> Dict[str, int]:
        return {
            "folded_expressions": self.folded_expressions,
            "pruned_conditions": self.pruned_conditions,
            "pruned_contracts": self.pruned_contracts,
            "eliminated_statements": self.eliminated_statements,
            "inlined_calls": self.inlined_calls,
            "total": self.total,
            "level": self.level,
        }


_INT_KINDS = {"int", "bool", "char"}
_NUMERIC_KINDS = {"int", "float"}
_COMPARISONS = {"==", "!=", "<", "<=", ">", ">="}
_ARITH = {"+", "-", "*", "/", "%"}


class Optimizer:
    """Optimises an :class:`~happy.compiler.ir.IRModule` in place."""

    def __init__(self, module: ir.IRModule, level: int = DEFAULT_LEVEL) -> None:
        self.module = module
        self.level = level
        self.report = OptimizationReport(level=level)
        self._counter = 0
        #: pure function name -> (param names, return expression)
        self._inlineable: Dict[str, Tuple[List[str], ir.IRExpr]] = {}

    # -- entry ----------------------------------------------------------
    def optimize(self) -> OptimizationReport:
        if self.level <= 0:
            return self.report
        self._build_inline_set()
        self._optimize_function_containers()
        return self.report

    # -- pure inlining table -------------------------------------------
    def _build_inline_set(self) -> None:
        if self.level < 2:
            return
        for fn in self._all_functions():
            if not self._is_simple_pure(fn):
                continue
            body = fn.body
            ret = body.statements[0]
            assert isinstance(ret, ir.IRReturn)
            self._inlineable[fn.name] = (
                [p.name for p in fn.params],
                ret.value if ret.value is not None else _unit_literal(ret.loc),
            )

    @staticmethod
    def _is_simple_pure(fn: ir.IRFunction) -> bool:
        if fn.contracts:
            return False
        if fn.declared_effects or fn.inferred_effects:
            return False
        if fn.is_async:
            return False
        # Inlining would drop the Int -> Float widening applied at the call
        # boundary (parameters and return value), so Float functions stay calls.
        for ty in [getattr(fn, "returns", None)] + [p.type for p in fn.params]:
            disp = getattr(ty, "display", None)
            if callable(disp) and disp() == "Float":
                return False
        body = fn.body
        if body is None or len(body.statements) != 1:
            return False
        ret = body.statements[0]
        if not isinstance(ret, ir.IRReturn) or ret.value is None:
            return False
        # Only total (non-raising) expressions are inlined.  A raising
        # expression (division, modulo, indexing, field access) would move a
        # runtime error's source location away from its original line, which
        # would break source-map fidelity.
        return _is_total_expr(ret.value)

    def _all_functions(self) -> List[ir.IRFunction]:
        out: List[ir.IRFunction] = list(self.module.functions)
        for impl in self.module.impls:
            out.extend(impl.methods)
        for agent in self.module.agents:
            out.extend(agent.functions)
        return out

    # -- containers -----------------------------------------------------
    def _optimize_function_containers(self) -> None:
        for fn in list(self.module.functions):
            self._optimize_function(fn)
        for impl in self.module.impls:
            for fn in impl.methods:
                self._optimize_function(fn)
        for agent in self.module.agents:
            for fn in agent.functions:
                self._optimize_function(fn)
        for trait in self.module.traits:
            for m in trait.methods:
                self._prune_contracts(m.contracts)
                if m.body is not None:
                    m.body = self._optimize_block(m.body)
                for p in m.params:
                    if p.default is not None:
                        p.default = self._fold(p.default)
        # Rule bodies + conditions.
        for rule in self.module.rules:
            if rule.condition is not None:
                rule.condition = self._fold(rule.condition)
            if rule.body is not None:
                rule.body = self._optimize_block(rule.body)
        for app in self.module.apps:
            if app.body is not None:
                app.body = self._optimize_block(app.body)
        for c in self.module.constants:
            if c.value is not None:
                c.value = self._fold(c.value)

    def _optimize_function(self, fn: ir.IRFunction) -> None:
        self._prune_contracts(fn.contracts)
        for p in fn.params:
            if p.default is not None:
                p.default = self._fold(p.default)
        if fn.body is not None:
            fn.body = self._optimize_block(fn.body)

    # -- statements -----------------------------------------------------
    def _optimize_block(self, block: ir.IRBlock) -> ir.IRBlock:
        out: List[ir.IRStmt] = []
        terminated = False
        for stmt in block.statements:
            if terminated:
                # Unreachable statement after return/break/continue.
                self.report.eliminated_statements += 1
                continue
            optimized = self._optimize_stmt(stmt, out)
            if optimized is None:
                continue
            out.append(optimized)
            if isinstance(optimized, (ir.IRReturn, ir.IRBreak, ir.IRContinue)):
                terminated = True
        block.statements = out
        return block

    def _optimize_stmt(
        self, stmt: ir.IRStmt, out: List[ir.IRStmt]
    ) -> Optional[ir.IRStmt]:
        if isinstance(stmt, ir.IRLet):
            if stmt.value is not None:
                stmt.value = self._fold(stmt.value)
            return stmt
        if isinstance(stmt, ir.IRAssign):
            if stmt.value is not None:
                stmt.value = self._fold(stmt.value)
            if stmt.target is not None:
                stmt.target = self._fold(stmt.target)
            return stmt
        if isinstance(stmt, ir.IRExprStmt):
            if stmt.expr is not None:
                stmt.expr = self._fold(stmt.expr)
            return stmt
        if isinstance(stmt, ir.IRIf):
            return self._optimize_if(stmt, out)
        if isinstance(stmt, ir.IRWhile):
            if stmt.condition is not None:
                stmt.condition = self._fold(stmt.condition)
            if stmt.body is not None:
                stmt.body = self._optimize_block(stmt.body)
            if _is_bool_literal(stmt.condition, False):
                self.report.pruned_conditions += 1
                return None  # `while false` never runs
            return stmt
        if isinstance(stmt, ir.IRFor):
            if stmt.iterable is not None:
                stmt.iterable = self._fold(stmt.iterable)
            if stmt.body is not None:
                stmt.body = self._optimize_block(stmt.body)
            return stmt
        if isinstance(stmt, ir.IRReturn):
            if stmt.value is not None:
                stmt.value = self._fold(stmt.value)
            return stmt
        if isinstance(stmt, ir.IRAssert):
            if stmt.predicate is not None:
                stmt.predicate = self._fold(stmt.predicate)
            if _is_bool_literal(stmt.predicate, True):
                # A trivially-true contract assert can never fail.
                self.report.pruned_contracts += 1
                return None
            return stmt
        if isinstance(stmt, ir.IRMatch):
            if stmt.subject is not None:
                stmt.subject = self._fold(stmt.subject)
            for arm in stmt.arms:
                if arm.body is not None:
                    arm.body = self._optimize_block(arm.body)
            return stmt
        return stmt

    def _optimize_if(
        self, stmt: ir.IRIf, out: List[ir.IRStmt]
    ) -> Optional[ir.IRStmt]:
        if stmt.condition is not None:
            stmt.condition = self._fold(stmt.condition)
        if stmt.then_branch is not None:
            stmt.then_branch = self._optimize_block(stmt.then_branch)
        if isinstance(stmt.else_branch, ir.IRBlock):
            stmt.else_branch = self._optimize_block(stmt.else_branch)
        elif isinstance(stmt.else_branch, ir.IRIf):
            inner = self._optimize_if(stmt.else_branch, out)
            stmt.else_branch = inner

        cond_true = _is_bool_literal(stmt.condition, True)
        cond_false = _is_bool_literal(stmt.condition, False)

        if cond_true:
            self.report.pruned_conditions += 1
            then_stmts = stmt.then_branch.statements if stmt.then_branch else []
            if _spliceable(then_stmts):
                out.extend(then_stmts)
                return None
            return stmt

        if cond_false:
            self.report.pruned_conditions += 1
            else_branch = stmt.else_branch
            if else_branch is None:
                return None
            if isinstance(else_branch, ir.IRBlock):
                if _spliceable(else_branch.statements):
                    out.extend(else_branch.statements)
                    return None
                return stmt
            if isinstance(else_branch, ir.IRIf):  # `elif` chain
                return else_branch
        return stmt

    # -- constant folding ----------------------------------------------
    def _fold(self, expr: Optional[ir.IRExpr]) -> Optional[ir.IRExpr]:
        if expr is None:
            return None
        if isinstance(expr, ir.IRUnary):
            expr.operand = self._fold(expr.operand)
            folded = _fold_unary(expr)
            if folded is not None:
                self.report.folded_expressions += 1
                return folded
            return expr
        if isinstance(expr, ir.IRBinary):
            expr.left = self._fold(expr.left)
            expr.right = self._fold(expr.right)
            folded = _fold_binary(expr)
            if folded is not None:
                self.report.folded_expressions += 1
                return folded
            return expr
        if isinstance(expr, ir.IRCall):
            inlined = self._try_inline(expr)
            if inlined is not None:
                self.report.inlined_calls += 1
                return self._fold(inlined)
            expr.args = [self._fold(a) for a in expr.args]
            expr.callee = self._fold(expr.callee)
            return expr
        if isinstance(expr, ir.IRMember):
            expr.obj = self._fold(expr.obj)
            return expr
        if isinstance(expr, ir.IRIndex):
            expr.obj = self._fold(expr.obj)
            expr.index = self._fold(expr.index)
            return expr
        if isinstance(expr, ir.IRList):
            expr.elements = [self._fold(e) for e in expr.elements]
            return expr
        if isinstance(expr, ir.IRStruct):
            expr.fields = [(n, self._fold(v)) for n, v in expr.fields]
            return expr
        if isinstance(expr, ir.IRAwait):
            expr.operand = self._fold(expr.operand)
            return expr
        if isinstance(expr, ir.IRAiExpr):
            if expr.prompt is not None:
                expr.prompt = self._fold(expr.prompt)
            return expr
        return expr

    # -- pure inlining --------------------------------------------------
    def _try_inline(self, call: ir.IRCall) -> Optional[ir.IRExpr]:
        if self.level < 2:
            return None
        callee = call.callee
        if not isinstance(callee, ir.IRName):
            return None
        entry = self._inlineable.get(callee.name)
        if entry is None:
            return None
        params, body_expr = entry
        if len(params) != len(call.args):
            return None
        if not all(_is_total_expr(a) for a in call.args):
            return None
        mapping = dict(zip(params, call.args))
        return self._clone(body_expr, mapping)

    def _clone(
        self, expr: ir.IRExpr, mapping: Dict[str, ir.IRExpr]
    ) -> ir.IRExpr:
        if isinstance(expr, ir.IRName) and expr.name in mapping:
            return dataclasses.replace(mapping[expr.name])
        new = dataclasses.replace(expr)
        self._counter += 1
        new.id = f"__opt_{self._counter}"
        if isinstance(new, ir.IRUnary):
            new.operand = self._clone(new.operand, mapping)
        elif isinstance(new, ir.IRBinary):
            new.left = self._clone(new.left, mapping)
            new.right = self._clone(new.right, mapping)
        elif isinstance(new, ir.IRCall):
            new.callee = self._clone(new.callee, mapping)
            new.args = [self._clone(a, mapping) for a in new.args]
        elif isinstance(new, ir.IRMember):
            new.obj = self._clone(new.obj, mapping)
        elif isinstance(new, ir.IRIndex):
            new.obj = self._clone(new.obj, mapping)
            new.index = self._clone(new.index, mapping)
        elif isinstance(new, ir.IRList):
            new.elements = [self._clone(e, mapping) for e in new.elements]
        elif isinstance(new, ir.IRStruct):
            new.fields = [(n, self._clone(v, mapping)) for n, v in new.fields]
        elif isinstance(new, ir.IRAwait):
            new.operand = self._clone(new.operand, mapping)
        return new

    # -- contracts ------------------------------------------------------
    def _prune_contracts(self, contracts: List[ir.IRContract]) -> None:
        kept: List[ir.IRContract] = []
        for c in contracts:
            if c.condition is not None:
                c.condition = self._fold(c.condition)
            # A trivially-true pre/post/invariant is unreachable-to-fail.
            if c.kind in ("requires", "ensures", "invariant") and _is_bool_literal(
                c.condition, True
            ):
                self.report.pruned_contracts += 1
                continue
            kept.append(c)
        contracts[:] = kept


# ---------------------------------------------------------------------------
# Folding helpers
# ---------------------------------------------------------------------------
def _literal(value, kind: str, like: ir.IRExpr) -> ir.IRLiteral:
    return ir.IRLiteral(loc=like.loc, id=like.id, value=value, literal_kind=kind)


def _is_bool_literal(expr: Optional[ir.IRExpr], value: bool) -> bool:
    return (
        isinstance(expr, ir.IRLiteral)
        and expr.literal_kind == "bool"
        and bool(expr.value) is value
    )


def _unit_literal(loc) -> ir.IRLiteral:
    return ir.IRLiteral(loc=loc, value=None, literal_kind="null")


def _spliceable(statements: List[ir.IRStmt]) -> bool:
    """A branch may be spliced into its parent only if it declares no names.

    ``let`` bindings inside a branch are scoped to that branch; moving them to
    the parent could shadow or duplicate an enclosing binding, so such branches
    are left untouched.
    """
    for stmt in statements:
        if isinstance(stmt, (ir.IRLet, ir.IRFunction)):
            return False
    return True


def _is_simple_expr(expr: Optional[ir.IRExpr]) -> bool:
    if expr is None:
        return True
    if isinstance(expr, ir.IRLiteral):
        return True
    if isinstance(expr, ir.IRName):
        return True
    if isinstance(expr, ir.IRUnary):
        return _is_simple_expr(expr.operand)
    if isinstance(expr, ir.IRBinary):
        return _is_simple_expr(expr.left) and _is_simple_expr(expr.right)
    if isinstance(expr, ir.IRMember):
        return _is_simple_expr(expr.obj)
    if isinstance(expr, ir.IRIndex):
        return _is_simple_expr(expr.obj) and _is_simple_expr(expr.index)
    if isinstance(expr, ir.IRList):
        return all(_is_simple_expr(e) for e in expr.elements)
    return False


#: Binary operators that can never raise on well-typed operands.
_TOTAL_BINOPS = {
    "+",
    "-",
    "*",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "&&",
    "||",
    "and",
    "or",
}


def _is_total_expr(expr: Optional[ir.IRExpr]) -> bool:
    """True for expressions that cannot raise at runtime.

    Used to guard pure inlining: inlining a *raising* expression would relocate
    a runtime error to the call site and destroy source-map fidelity.
    """
    if expr is None:
        return True
    if isinstance(expr, ir.IRLiteral):
        return True
    if isinstance(expr, ir.IRName):
        return True
    if isinstance(expr, ir.IRUnary):
        return expr.op in ("!", "not", "-", "+", "~") and _is_total_expr(
            expr.operand
        )
    if isinstance(expr, ir.IRBinary):
        return (
            expr.op in _TOTAL_BINOPS
            and _is_total_expr(expr.left)
            and _is_total_expr(expr.right)
        )
    if isinstance(expr, ir.IRList):
        return all(_is_total_expr(e) for e in expr.elements)
    return False


def _fold_unary(expr: ir.IRUnary) -> Optional[ir.IRLiteral]:
    operand = expr.operand
    if not isinstance(operand, ir.IRLiteral):
        return None
    kind = operand.literal_kind
    value = operand.value
    if expr.op in ("!", "not"):
        if kind == "bool":
            return _literal(not bool(value), "bool", expr)
        return None
    if expr.op == "-":
        if kind == "int":
            return _literal(-int(value), "int", expr)
        if kind == "float":
            return _literal(-float(value), "float", expr)
        return None
    if expr.op == "+":
        if kind in _NUMERIC_KINDS:
            return _literal(value, kind, expr)
        return None
    if expr.op == "~":
        if kind == "int":
            return _literal(~int(value), "int", expr)
        return None
    return None


def _fold_binary(expr: ir.IRBinary) -> Optional[ir.IRLiteral]:
    left, right = expr.left, expr.right
    if not (isinstance(left, ir.IRLiteral) and isinstance(right, ir.IRLiteral)):
        return None
    lk, rk = left.literal_kind, right.literal_kind
    lv, rv = left.value, right.value
    op = expr.op

    # Boolean short-circuit logic.
    if op in ("&&", "and"):
        if lk == "bool" and rk == "bool":
            return _literal(bool(lv) and bool(rv), "bool", expr)
        return None
    if op in ("||", "or"):
        if lk == "bool" and rk == "bool":
            return _literal(bool(lv) or bool(rv), "bool", expr)
        return None

    # Comparisons on same-kind scalars.
    if op in _COMPARISONS:
        if lk == rk and lk in ("int", "float", "string", "bool", "char"):
            lv = int(lv) if lk == "int" else lv
            rv = int(rv) if lk == "int" else rv
            result = {
                "==": lv == rv,
                "!=": lv != rv,
                "<": lv < rv,
                "<=": lv <= rv,
                ">": lv > rv,
                ">=": lv >= rv,
            }[op]
            return _literal(result, "bool", expr)
        return None

    # String concatenation.
    if op == "+" and lk == "string" and rk == "string":
        return _literal(str(lv) + str(rv), "string", expr)

    # Arithmetic on matching numeric kinds.
    if op in _ARITH and lk == rk and lk in _NUMERIC_KINDS:
        a = int(lv) if lk == "int" else float(lv)
        b = int(rv) if lk == "int" else float(rv)
        try:
            if op == "+":
                res = a + b
            elif op == "-":
                res = a - b
            elif op == "*":
                res = a * b
            elif op == "/":
                if b == 0:
                    return None  # do not fold division by zero
                # Happy's '/' is *true* division: it always yields a Float,
                # even for two Int operands (7 / 2 == 3.5).  Folding it as
                # integer floor division produced wrong answers.
                res = a / b
                if res != res or res in (float("inf"), float("-inf")):
                    return None  # overflow: leave it to fail at run time
                return _literal(res, "float", expr)
            else:  # "%"
                if b == 0:
                    return None
                res = a % b
        except (ZeroDivisionError, OverflowError):
            return None
        if lk == "float" and (res != res or res in (float("inf"), float("-inf"))):
            return None  # never fold to a non-finite literal
        return _literal(res, lk, expr)
    return None


def optimize(module: ir.IRModule, level: int = DEFAULT_LEVEL) -> OptimizationReport:
    """Optimise ``module`` in place and return the report of what changed."""
    return Optimizer(module, level=level).optimize()
