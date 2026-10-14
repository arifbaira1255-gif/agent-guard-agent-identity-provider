"""Effect tracking for the Happy language.

Every function in Happy may declare the *side-effects* it is allowed to perform
with an ``effects [...]`` annotation.  The tracker does three jobs:

1. **Inference** — it walks the IR body of each function and derives the set of
   effects the body actually performs (calls to ``http_get`` → ``Network``,
   ``write_file`` → ``FileSystem``, ``ai { … }`` → ``AI``, a ``secret`` field
   read → ``Secrets``, and so on).  Inference is inter-procedural: effects
   propagate along the call graph until a fixed point is reached, so a function
   that calls an impure helper is itself impure.

2. **Enforcement** — it compares *declared* against *inferred* effects and
   reports **purity violations** (a body performs an effect it did not declare)
   and **over-declaration** (a function claims an effect it never uses).

3. **Purity** — a function with no declared and no inferred effects is
   *pure*; the tracker verifies that pure functions really are side-effect
   free.

Diagnostics follow the same coded, line/column + caret + ``help:`` style as the
rest of the compiler.

Entry point::

    from happy.compiler import parse, analyze, lower
    from happy.compiler.effects import EffectTracker

    module = lower(analyze(parse(source)))
    report = EffectTracker(source=source, filename="demo.hpy").analyze(module)
    print(report.summary())
    if not report.ok:
        print(report.format())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .errors import SourceLocation, format_diagnostic
from .ir import (
    IRAgent,
    IRAi,
    IRAssign,
    IRAwait,
    IRBlock,
    IRBreak,
    IRCall,
    IRContinue,
    IRExpr,
    IRExprStmt,
    IRFor,
    IRFunction,
    IRIf,
    IRLet,
    IRList,
    IRMember,
    IRModule,
    IRReturn,
    IRStmt,
    IRStruct,
    IRWhile,
    canonical_effects,
)

__all__ = [
    "EffectKind",
    "EFFECT_BUILTINS",
    "SIDE_EFFECT_FREE",
    "FunctionEffects",
    "EffectDiagnostic",
    "EffectReport",
    "EffectOptions",
    "EffectTracker",
    "track_effects",
    "check_effects",
    # codes
    "CODE_UNDECLARED_EFFECT",
    "CODE_PURE_VIOLATION",
    "CODE_UNKNOWN_EFFECT",
    "CODE_EFFECT_ON_PURE_CALL",
    "W_OVERDECLARED_EFFECT",
    "W_MISSING_EFFECT_ANNOTATION",
    "N_PURE",
    "N_INFERRED",
]


# ---------------------------------------------------------------------------
# Canonical effect kinds
# ---------------------------------------------------------------------------
class EffectKind:
    """The canonical effect set Happy reasons about."""

    IO = "IO"
    NETWORK = "Network"
    DATABASE_READ = "DatabaseRead"
    DATABASE_WRITE = "DatabaseWrite"
    FILESYSTEM = "FileSystem"
    SECRETS = "Secrets"
    PAYMENTS = "Payments"
    AI = "AI"
    LOG = "Log"
    TIME = "Time"
    RANDOM = "Random"
    STATE = "State"
    GPU = "GPU"
    ENV = "Env"
    PROCESS = "Process"

    ALL = (
        IO, NETWORK, DATABASE_READ, DATABASE_WRITE, FILESYSTEM, SECRETS,
        PAYMENTS, AI, LOG, TIME, RANDOM, STATE, GPU, ENV, PROCESS,
    )


#: Builtin function -> the effect(s) invoking it performs.
#: An empty tuple marks a *pure* builtin.
EFFECT_BUILTINS: Dict[str, Tuple[str, ...]] = {
    "print": (EffectKind.IO,),
    "println": (EffectKind.IO,),
    "read_file": (EffectKind.FILESYSTEM,),
    "write_file": (EffectKind.FILESYSTEM,),
    "http_get": (EffectKind.NETWORK,),
    "http_post": (EffectKind.NETWORK,),
    "json_parse": (),
    "len": (),
    "str": (),
    "int": (),
    "float": (),
    "now": (EffectKind.TIME,),
    "rand": (EffectKind.RANDOM,),
}

#: An explicit "no effects" marker used by purity checks.
SIDE_EFFECT_FREE: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Diagnostic codes (7xxx band)
# ---------------------------------------------------------------------------
CODE_UNDECLARED_EFFECT = "E7001"
CODE_PURE_VIOLATION = "E7002"
CODE_UNKNOWN_EFFECT = "E7003"
CODE_EFFECT_ON_PURE_CALL = "E7004"

W_OVERDECLARED_EFFECT = "W7011"
W_MISSING_EFFECT_ANNOTATION = "W7012"

N_PURE = "N7001"
N_INFERRED = "N7002"


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class FunctionEffects:
    """The declared vs inferred effects of one callable."""

    name: str
    qualified: str = ""
    declared: Tuple[str, ...] = ()
    inferred: Tuple[str, ...] = ()
    owner: Optional[str] = None
    is_method: bool = False
    loc: Optional[SourceLocation] = None
    has_body: bool = True
    has_annotation: bool = False
    call_depth_effects: Tuple[str, ...] = ()

    @property
    def undeclared(self) -> Tuple[str, ...]:
        return tuple(e for e in self.inferred if e not in self.declared)

    @property
    def overdeclared(self) -> Tuple[str, ...]:
        return tuple(e for e in self.declared if e not in self.inferred)

    @property
    def is_pure(self) -> bool:
        return not self.inferred and not self.declared

    @property
    def declared_pure(self) -> bool:
        return self.has_annotation and not self.declared

    def summary(self) -> str:
        d = ", ".join(self.declared) or "∅"
        i = ", ".join(self.inferred) or "∅"
        tag = "pure" if self.is_pure else "effectful"
        return f"{self.qualified or self.name}: declared[{d}] inferred[{i}] ({tag})"


@dataclass
class EffectDiagnostic:
    """A single effect diagnostic."""

    code: str
    message: str
    location: Optional[SourceLocation] = None
    suggestion: Optional[str] = None
    severity: str = "error"
    filename: Optional[str] = None
    source: Optional[str] = None

    def render(self) -> str:
        return format_diagnostic(
            f"[{self.code}] {self.message}",
            location=self.location,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )

    @property
    def line(self) -> int:
        return self.location.line if self.location else 0

    @property
    def column(self) -> int:
        return self.location.column if self.location else 0

    def __str__(self) -> str:  # pragma: no cover
        return self.render()


@dataclass
class EffectOptions:
    """Tunable behaviour of the effect tracker."""

    #: Report a body performing an effect it did not declare (purity violation).
    enforce_declared: bool = True
    #: Report a function with no annotation that performs effects.
    warn_missing_annotation: bool = True
    #: Report declared effects the body never performs.
    report_overdeclaration: bool = True
    #: Emit an informational note for every pure function.
    note_pure: bool = True
    #: Emit an informational note summarising inferred effects.
    note_inferred: bool = False
    #: Effects that may never appear in a pure (unannotated) function.
    hard_purity: bool = True


@dataclass
class EffectReport:
    """The outcome of an effect-analysis run."""

    module_name: Optional[str] = None
    functions: List[FunctionEffects] = field(default_factory=list)
    diagnostics: List[EffectDiagnostic] = field(default_factory=list)
    call_graph: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    # -- queries --------------------------------------------------------
    @property
    def errors(self) -> List[EffectDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self) -> List[EffectDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "warning"]

    @property
    def notes(self) -> List[EffectDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "note"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def pure_functions(self) -> List[FunctionEffects]:
        return [f for f in self.functions if f.is_pure]

    @property
    def effectful_functions(self) -> List[FunctionEffects]:
        return [f for f in self.functions if not f.is_pure]

    def function(self, name: str) -> Optional[FunctionEffects]:
        for f in self.functions:
            if f.name == name or f.qualified == name:
                return f
        return None

    def summary(self) -> str:
        return (
            f"{len(self.functions)} function(s) "
            f"({len(self.pure_functions)} pure / "
            f"{len(self.effectful_functions)} effectful), "
            f"{len(self.errors)} error(s), {len(self.warnings)} warning(s), "
            f"{len(self.notes)} note(s)"
        )

    def sorted(self) -> List[EffectDiagnostic]:
        return sorted(self.diagnostics, key=lambda d: (d.line, d.column, d.code))

    def format(self) -> str:
        if not self.diagnostics:
            return "(no effect diagnostics)"
        return "\n\n".join(d.render() for d in self.sorted())

    def effect_matrix(self) -> Dict[str, Tuple[str, ...]]:
        return {f.qualified or f.name: f.inferred for f in self.functions}


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------
class EffectTracker:
    """Infers, propagates and enforces effects over a Happy IR module."""

    def __init__(
        self,
        source: Optional[str] = None,
        filename: Optional[str] = None,
        options: Optional[EffectOptions] = None,
    ) -> None:
        self.source = source
        self.filename = filename
        self.options = options or EffectOptions()
        self.diagnostics: List[EffectDiagnostic] = []
        #: direct (non-call) effects per function
        self._direct: Dict[str, Set[str]] = {}
        #: callees per function
        self._calls: Dict[str, Set[str]] = {}
        self._functions: Dict[str, IRFunction] = {}
        self._owner: Dict[str, Optional[str]] = {}
        self._declared: Dict[str, Tuple[str, ...]] = {}
        #: True when the source carried an explicit ``effects`` annotation
        #: (including ``effects []`` for pure functions).
        self._annotated: Dict[str, bool] = {}

    # -- diagnostics ----------------------------------------------------
    def _emit(self, code, message, loc, suggestion=None, severity="error"):
        self.diagnostics.append(
            EffectDiagnostic(
                code=code,
                message=message,
                location=loc,
                suggestion=suggestion,
                severity=severity,
                filename=self.filename,
                source=self.source,
            )
        )

    # -- entry ----------------------------------------------------------
    def analyze(self, module: IRModule) -> EffectReport:
        """Run effect inference, propagation and enforcement."""
        self._collect(module)
        inferred = self._solve_fixed_point()
        report = self._build_report(module, inferred)
        self._enforce(report)
        report.diagnostics = sorted(
            self.diagnostics, key=lambda d: (d.line, d.column, d.code)
        )
        return report

    # -- collection -----------------------------------------------------
    def _collect(self, module: IRModule) -> None:
        for fn in module.functions:
            self._register(fn, owner=None, is_method=False)
        for agent in module.agents:
            for fn in agent.functions:
                self._register(fn, owner=agent.name, is_method=True)
        for ai in module.ai_blocks:
            for stmt in (ai.body.statements if ai.body else []):
                if isinstance(stmt, IRFunction):
                    self._register(stmt, owner=ai.name, is_method=True)

    def _register(
        self, fn: IRFunction, owner: Optional[str], is_method: bool
    ) -> None:
        key = self._key(owner, fn.name)
        self._functions[key] = fn
        self._owner[key] = owner
        self._declared[key] = canonical_effects(
            [e.canonical or e.name for e in fn.declared_effects]
        )
        self._annotated[key] = bool(getattr(fn, "has_effect_annotation", False))
        direct: Set[str] = set()
        calls: Set[str] = set()
        self._scan_block(fn.body, direct, calls, owner)
        # AI-declared bodies imply the AI effect.
        self._direct[key] = direct
        self._calls[key] = calls

    def _key(self, owner: Optional[str], name: str) -> str:
        return f"{owner}.{name}" if owner else name

    def _scan_block(
        self,
        block: Optional[IRBlock],
        direct: Set[str],
        calls: Set[str],
        owner: Optional[str],
    ) -> None:
        if block is None:
            return
        for stmt in block.statements:
            self._scan_stmt(stmt, direct, calls, owner)

    def _scan_stmt(
        self,
        stmt: IRStmt,
        direct: Set[str],
        calls: Set[str],
        owner: Optional[str],
    ) -> None:
        if isinstance(stmt, IRLet):
            self._scan_expr(stmt.value, direct, calls)
        elif isinstance(stmt, IRAssign):
            self._scan_expr(stmt.target, direct, calls)
            self._scan_expr(stmt.value, direct, calls)
        elif isinstance(stmt, IRExprStmt):
            self._scan_expr(stmt.expr, direct, calls)
        elif isinstance(stmt, IRIf):
            self._scan_expr(stmt.condition, direct, calls)
            if stmt.then_branch is not None:
                self._scan_block(stmt.then_branch, direct, calls, owner)
            if isinstance(stmt.else_branch, IRBlock):
                self._scan_block(stmt.else_branch, direct, calls, owner)
            elif isinstance(stmt.else_branch, IRIf):
                self._scan_stmt(stmt.else_branch, direct, calls, owner)
        elif isinstance(stmt, IRWhile):
            self._scan_expr(stmt.condition, direct, calls)
            if stmt.body is not None:
                self._scan_block(stmt.body, direct, calls, owner)
        elif isinstance(stmt, IRFor):
            self._scan_expr(stmt.iterable, direct, calls)
            if stmt.body is not None:
                self._scan_block(stmt.body, direct, calls, owner)
        elif isinstance(stmt, IRReturn):
            self._scan_expr(stmt.value, direct, calls)
        elif isinstance(stmt, (IRBreak, IRContinue)):
            return

    def _scan_expr(
        self,
        expr: Optional[IRExpr],
        direct: Set[str],
        calls: Set[str],
    ) -> None:
        if expr is None:
            return
        if isinstance(expr, IRAwait):
            # Suspension itself is not an effect; the awaited call carries its
            # own effects, which propagate through the normal call graph.
            self._scan_expr(expr.operand, direct, calls)
            return
        if type(expr).__name__ == "IRAiExpr":
            direct.add(EffectKind.AI)
            prompt = getattr(expr, "prompt", None)
            self._scan_expr(prompt, direct, calls)
            body = getattr(expr, "body", None)
            if body is not None:
                self._scan_block(body, direct, calls, None)
            return
        if isinstance(expr, IRCall):
            name = _callee_name(expr)
            if name is not None:
                if name in EFFECT_BUILTINS:
                    direct.update(EFFECT_BUILTINS[name])
                else:
                    calls.add(name)
            for arg in expr.args:
                self._scan_expr(arg, direct, calls)
            return
        if isinstance(expr, IRMember):
            # reading a `secret` field is a Secrets effect
            if "secret" in expr.name.lower():
                direct.add(EffectKind.SECRETS)
            self._scan_expr(expr.obj, direct, calls)
            return
        if isinstance(expr, (IRList, IRStruct)):
            for child in expr.children():
                self._scan_expr(child, direct, calls)
            return
        # generic fallback
        for child in expr.children():
            self._scan_expr(child, direct, calls)

    # -- fixed-point propagation ---------------------------------------
    def _solve_fixed_point(self) -> Dict[str, Tuple[str, ...]]:
        # resolve call edges to qualified keys where possible
        resolved: Dict[str, Set[str]] = {}
        for key, callees in self._calls.items():
            owner = self._owner.get(key)
            out: Set[str] = set()
            for c in callees:
                target = self._resolve_callee(c, owner)
                if target is not None and target != key:
                    out.add(target)
            resolved[key] = out

        inferred: Dict[str, Set[str]] = {
            key: set(self._direct.get(key, set())) for key in self._functions
        }
        # iterate to a fixed point (call graph may contain cycles)
        changed = True
        guard = 0
        while changed and guard < 1000:
            changed = False
            guard += 1
            for key, callees in resolved.items():
                acc = set(self._direct.get(key, set()))
                for callee in callees:
                    acc |= inferred.get(callee, set())
                if acc != inferred[key]:
                    inferred[key] = acc
                    changed = True

        # deterministic ordering: canonical order first, then lexical
        order = {kind: i for i, kind in enumerate(EffectKind.ALL)}
        result: Dict[str, Tuple[str, ...]] = {}
        for key, kinds in inferred.items():
            result[key] = tuple(
                sorted(kinds, key=lambda k: (order.get(k, 999), k))
            )
        return result

    def _resolve_callee(self, name: str, owner: Optional[str]) -> Optional[str]:
        # prefer a method on the same owner, then a module-level function
        if owner is not None:
            local = self._key(owner, name)
            if local in self._functions:
                return local
        if name in self._functions:
            return name
        # any function with this bare name
        for key, fn in self._functions.items():
            if fn.name == name:
                return key
        return None

    # -- reporting ------------------------------------------------------
    def _build_report(
        self, module: IRModule, inferred: Dict[str, Tuple[str, ...]]
    ) -> EffectReport:
        funcs: List[FunctionEffects] = []
        for key, fn in self._functions.items():
            owner = self._owner.get(key)
            declared = self._declared.get(key, ())
            inf = inferred.get(key, ())
            fe = FunctionEffects(
                name=fn.name,
                qualified=key,
                declared=declared,
                inferred=inf,
                owner=owner,
                is_method=owner is not None,
                loc=fn.loc,
                has_body=fn.body is not None,
                has_annotation=self._annotated.get(key, False),
            )
            funcs.append(fe)
        funcs.sort(key=lambda f: (f.owner or "", f.name))
        report = EffectReport(
            module_name=module.name,
            functions=funcs,
            call_graph={k: tuple(sorted(v)) for k, v in self._calls.items()},
        )
        return report

    def _enforce(self, report: EffectReport) -> None:
        for fe in report.functions:
            if not fe.has_body:
                continue
            undeclared = fe.undeclared
            if undeclared and self.options.enforce_declared:
                # A function with a declared annotation and an undeclared
                # effect is an error; an unannotated impure function is a
                # warning unless hard purity is requested.
                if fe.has_annotation:
                    self._emit(
                        CODE_UNDECLARED_EFFECT,
                        f"'{fe.qualified}' performs undeclared effect(s): "
                        f"{', '.join(undeclared)}",
                        fe.loc,
                        "declare them with 'effects ["
                        + ", ".join(_to_source(e) for e in fe.inferred)
                        + "]', or remove the offending operation",
                    )
                elif self.options.warn_missing_annotation:
                    self._emit(
                        W_MISSING_EFFECT_ANNOTATION,
                        f"'{fe.qualified}' performs effect(s) "
                        f"{', '.join(fe.inferred)} but declares no 'effects'",
                        fe.loc,
                        "add an 'effects [...]' annotation so callers can see "
                        "the behaviour",
                        severity="warning",
                    )
            if fe.declared and fe.overdeclared and self.options.report_overdeclaration:
                self._emit(
                    W_OVERDECLARED_EFFECT,
                    f"'{fe.qualified}' declares unused effect(s): "
                    f"{', '.join(fe.overdeclared)}",
                    fe.loc,
                    "remove them, or make use of the declared capability",
                    severity="warning",
                )
            if fe.is_pure and self.options.note_pure:
                self._emit(
                    N_PURE,
                    f"'{fe.qualified}' is pure (no effects)",
                    fe.loc,
                    severity="note",
                )
            elif fe.inferred and self.options.note_inferred:
                self._emit(
                    N_INFERRED,
                    f"'{fe.qualified}' inferred effects: "
                    f"{', '.join(fe.inferred)}",
                    fe.loc,
                    severity="note",
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _callee_name(call: IRCall) -> Optional[str]:
    callee = call.callee
    if callee is None:
        return None
    if type(callee).__name__ == "IRName":
        return getattr(callee, "name", None)
    if isinstance(callee, IRMember):
        return callee.name
    return None


def _declared_pure(fn: IRFunction) -> bool:
    """True when the source explicitly said ``effects []``."""
    return fn.declared_effects is not None and len(fn.declared_effects) == 0 and not fn.is_async


#: canonical -> source spelling used in suggestions
_CANONICAL_TO_SOURCE = {
    EffectKind.IO: "io",
    EffectKind.NETWORK: "net",
    EffectKind.DATABASE_READ: "db",
    EffectKind.DATABASE_WRITE: "dbwrite",
    EffectKind.FILESYSTEM: "fs",
    EffectKind.SECRETS: "secret",
    EffectKind.PAYMENTS: "payments",
    EffectKind.AI: "ai",
    EffectKind.LOG: "log",
    EffectKind.TIME: "time",
    EffectKind.RANDOM: "rand",
    EffectKind.STATE: "state",
    EffectKind.GPU: "gpu",
    EffectKind.ENV: "env",
    EffectKind.PROCESS: "proc",
}


def _to_source(effect: str) -> str:
    return _CANONICAL_TO_SOURCE.get(effect, effect.lower())


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def track_effects(
    source_or_module,
    filename: Optional[str] = None,
    options: Optional[EffectOptions] = None,
    source: Optional[str] = None,
) -> EffectReport:
    """Track effects of a module or of raw source."""
    module = _as_module(source_or_module, filename)
    src = source if source is not None else (
        source_or_module if isinstance(source_or_module, str) else None
    )
    return EffectTracker(source=src, filename=filename, options=options).analyze(
        module
    )


#: Alias matching the module name used in the task description.
check_effects = track_effects


def _as_module(source_or_module, filename: Optional[str]) -> IRModule:
    from . import ast as _ast
    from .ir import lower

    if isinstance(source_or_module, IRModule):
        return source_or_module
    if isinstance(source_or_module, str):
        from .semantic import analyze as _analyze

        return lower(_analyze(source_or_module, filename=filename))
    if isinstance(source_or_module, _ast.Program):
        from .semantic import analyze as _analyze

        return lower(_analyze(source_or_module, filename=filename))
    return lower(source_or_module)
