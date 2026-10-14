"""Contract analysis and lowering for the Happy language.

Happy lets developers attach *design by contract* clauses to their code:

* ``requires``  — preconditions checked on entry to a function / rule / agent;
* ``ensures``   — postconditions checked before every exit (may reference the
  ``result`` pseudo-variable and the ``old(...)`` / ``pre`` state);
* ``invariant`` — type invariants attached to a ``type`` declaration (and, on
  functions, additional guarantees checked on entry and exit).

This stage consumes the typed :mod:`happy.compiler.ir` produced by
:func:`happy.compiler.ir.lower` and does two things:

1. **Static checking** — it verifies that every predicate is a ``Bool``
   expression, that ``result`` is only used where it makes sense, that contract
   variables resolve to parameters / fields, and that no clause is trivially
   redundant.  Problems are reported as coded diagnostics with precise
   line/column, a caret and a ``help:`` suggestion, matching the Step 1/2 style.

2. **Lowering** — it turns each clause into an executable :class:`~happy.compiler.ir.IRAssert`
   node: preconditions become *entry assertions*, postconditions become *exit
   assertions* (to be spliced before every ``return``), and type invariants
   become assertions attached to the owning type's methods.

Entry point::

    from happy.compiler import parse, analyze, lower
    from happy.compiler.contracts import ContractEngine

    module = lower(analyze(parse(source)))
    report = ContractEngine(source=source, filename="demo.hpy").analyze(module)
    print(report.summary())
    if not report.ok:
        print(report.format())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import ast
from .errors import SourceLocation, format_diagnostic
from .ir import (
    IRAssert,
    IRBlock,
    IRContract,
    IRExpr,
    IRFunction,
    IRModule,
    IRName,
    IRRule,
    IRStruct,
    IRTypeDecl,
    IRAgent,
    IRAi,
    IRAwait,
    IRBinary,
)
from .ir import IRBuilder  # deterministic id allocation for assertions
from .types import UNIT, Type, UnknownType, AnyType, UnitType

__all__ = [
    "ContractKind",
    "ContractDiagnostic",
    "CheckedContract",
    "ContractInfo",
    "ContractReport",
    "ContractOptions",
    "ContractEngine",
    "check_contracts",
    "CODE_CONTRACT_NOT_BOOL",
    "CODE_RESULT_ON_UNIT",
    "CODE_INVARIANT_UNKNOWN_FIELD",
    "CODE_UNKNOWN_CONTRACT_VAR",
    "W_TRIVIAL_CONTRACT",
    "W_DUPLICATE_CONTRACT",
    "N_OLD_STATE",
    "N_ABSTRACT_CONTRACT",
]


# ---------------------------------------------------------------------------
# Diagnostic codes
# ---------------------------------------------------------------------------
CODE_CONTRACT_NOT_BOOL = "E5001"
CODE_RESULT_ON_UNIT = "E5002"
CODE_INVARIANT_UNKNOWN_FIELD = "E5003"
CODE_UNKNOWN_CONTRACT_VAR = "W5004"
CODE_EMPTY_CONTRACT = "E5005"

W_TRIVIAL_CONTRACT = "W5011"
W_DUPLICATE_CONTRACT = "W5012"
W_SHADOWED_INVARIANT = "W5013"

N_OLD_STATE = "N5001"
N_ABSTRACT_CONTRACT = "N5002"


class ContractKind:
    """The three contract clause kinds."""

    REQUIRES = "requires"
    ENSURES = "ensures"
    INVARIANT = "invariant"
    ALL = (REQUIRES, ENSURES, INVARIANT)


#: Names that are not real free variables inside a contract predicate.
_PSEUDO_NAMES = {"result", "old", "pre", "true", "false", "null", "self"}


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
@dataclass
class ContractDiagnostic:
    """A single contract-stage message with a code and precise location."""

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
class ContractOptions:
    """Tunable behaviour of the contract engine."""

    #: Report contract predicates that are syntactically non-Bool.
    check_bool: bool = True
    #: Report free variables that do not resolve to a parameter / field.
    check_free_vars: bool = True
    #: Report trivially-true predicates (``requires true`` …).
    check_trivial: bool = True
    #: Report duplicate clauses.
    check_duplicates: bool = True
    #: Emit an informational note when ``old`` / ``pre`` is referenced.
    note_old_state: bool = True
    #: Emit an informational note on contracts without a body to check.
    note_abstract: bool = True


# ---------------------------------------------------------------------------
# Checked contract model
# ---------------------------------------------------------------------------
@dataclass
class CheckedContract:
    """A single contract clause after static checking and lowering."""

    kind: str
    clause: IRContract
    predicate: Optional[IRExpr]
    is_bool: Optional[bool]  # True / False / None(unknown)
    free_vars: Tuple[str, ...] = ()
    refers_to_result: bool = False
    refers_to_old: bool = False
    trivial: bool = False
    assertion: Optional[IRAssert] = None

    @property
    def message(self) -> Optional[str]:
        return self.clause.message

    @property
    def loc(self) -> Optional[SourceLocation]:
        return self.clause.loc or (self.predicate.loc if self.predicate else None)


@dataclass
class ContractInfo:
    """All contracts of one declaration, with their lowered assertions."""

    name: str
    kind: str  # "function" | "struct" | "rule" | "agent" | "ai" | "method"
    contracts: List[CheckedContract] = field(default_factory=list)
    entry_assertions: List[IRAssert] = field(default_factory=list)
    exit_assertions: List[IRAssert] = field(default_factory=list)
    invariant_assertions: List[IRAssert] = field(default_factory=list)
    owner_type: Optional[str] = None
    loc: Optional[SourceLocation] = None

    def of_kind(self, kind: str) -> List[CheckedContract]:
        return [c for c in self.contracts if c.kind == kind]

    @property
    def requires(self) -> List[CheckedContract]:
        return self.of_kind(ContractKind.REQUIRES)

    @property
    def ensures(self) -> List[CheckedContract]:
        return self.of_kind(ContractKind.ENSURES)

    @property
    def invariants(self) -> List[CheckedContract]:
        return self.of_kind(ContractKind.INVARIANT)

    def summary(self) -> str:
        return (
            f"{self.name}: {len(self.requires)} requires, "
            f"{len(self.ensures)} ensures, {len(self.invariants)} invariant "
            f"({len(self.entry_assertions)} entry / "
            f"{len(self.exit_assertions)} exit assertions)"
        )


@dataclass
class ContractReport:
    """The outcome of a contract-analysis run over a whole module."""

    module_name: Optional[str] = None
    infos: List[ContractInfo] = field(default_factory=list)
    diagnostics: List[ContractDiagnostic] = field(default_factory=list)

    # -- queries --------------------------------------------------------
    @property
    def errors(self) -> List[ContractDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self) -> List[ContractDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "warning"]

    @property
    def notes(self) -> List[ContractDiagnostic]:
        return [d for d in self.diagnostics if d.severity == "note"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def total_contracts(self) -> int:
        return sum(len(i.contracts) for i in self.infos)

    def info(self, name: str) -> Optional[ContractInfo]:
        for i in self.infos:
            if i.name == name:
                return i
        return None

    def summary(self) -> str:
        return (
            f"{len(self.infos)} contract holder(s), "
            f"{self.total_contracts} clause(s), "
            f"{len(self.errors)} error(s), {len(self.warnings)} warning(s), "
            f"{len(self.notes)} note(s)"
        )

    def sorted(self) -> List[ContractDiagnostic]:
        return sorted(self.diagnostics, key=lambda d: (d.line, d.column, d.code))

    def format(self) -> str:
        if not self.diagnostics:
            return "(no contract diagnostics)"
        return "\n\n".join(d.render() for d in self.sorted())


# ---------------------------------------------------------------------------
# Predicate helpers (lightweight, purely syntactic)
# ---------------------------------------------------------------------------
_BOOL_OPS = {"==", "!=", "<", "<=", ">", ">=", "&&", "||", "and", "or"}


def _is_unit(type_: Optional[Type]) -> bool:
    """Return True when ``type_`` denotes the Unit type."""
    if type_ is None:
        return False
    if isinstance(type_, UnitType):
        return True
    from .types import PrimitiveType

    return isinstance(type_, PrimitiveType) and type_.name == "Unit"


def _predicate_is_bool(expr: Optional[IRExpr]) -> Optional[bool]:
    """Return ``True``/``False`` if the predicate's Bool-ness is decidable.

    ``None`` means "cannot tell" — e.g. a bare identifier whose type the IR
    stage did not resolve.  We never report a contract error on ``None``.
    """
    if expr is None:
        return None
    if isinstance(expr, IRBinary):
        if expr.op in _BOOL_OPS:
            return True
        if expr.op in {"+", "-", "*", "/", "%", "**"}:
            return False
    if type(expr).__name__ == "IRUnary":
        if getattr(expr, "op", None) in {"!", "not"}:
            return True
        if getattr(expr, "op", None) in {"-", "+"}:
            return False
    if type(expr).__name__ == "IRLiteral":
        lk = getattr(expr, "literal_kind", "")
        if lk == "bool":
            return True
        if lk in {"int", "float", "string", "char", "null"}:
            return False
    return None


def _predicate_is_trivially_true(expr: Optional[IRExpr]) -> bool:
    if expr is None:
        return False
    if type(expr).__name__ == "IRLiteral" and getattr(expr, "literal_kind", "") == "bool":
        return bool(getattr(expr, "value", False))
    if isinstance(expr, IRBinary) and expr.op in {"||", "or"}:
        return _predicate_is_trivially_true(expr.left) or _predicate_is_trivially_true(
            expr.right
        )
    return False


def _free_names(expr: Optional[IRExpr]) -> Tuple[str, ...]:
    """Return the free identifier names referenced by ``expr`` (ordered)."""
    if expr is None:
        return ()
    names: List[str] = []
    for node in expr.walk():
        if isinstance(node, IRName) and node.name not in _PSEUDO_NAMES:
            if node.name not in names:
                names.append(node.name)
    return tuple(names)


def _expr_fingerprint(expr: Optional[IRExpr]) -> str:
    """A structural fingerprint of a predicate, ignoring node IDs."""
    if expr is None:
        return ""

    def rec(node) -> str:
        if node is None:
            return "·"
        if isinstance(node, IRName):
            return f"Name({node.name})"
        if type(node).__name__ == "IRLiteral":
            return f"Lit({getattr(node, 'literal_kind', '')}:{getattr(node, 'value', '')})"
        if isinstance(node, IRBinary):
            return f"Bin({node.op},{rec(node.left)},{rec(node.right)})"
        if type(node).__name__ == "IRUnary":
            return f"Un({getattr(node, 'op', '')},{rec(getattr(node, 'operand', None))})"
        if type(node).__name__ == "IRCall":
            args = ",".join(rec(a) for a in getattr(node, "args", []))
            return f"Call({rec(getattr(node, 'callee', None))};{args})"
        if type(node).__name__ == "IRMember":
            return f"Mem({rec(getattr(node, 'obj', None))}.{getattr(node, 'name', '')})"
        # generic fallback: kind + children
        kids = ",".join(rec(c) for c in node.children())
        return f"{node.kind_name()}({kids})"

    return rec(expr)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class ContractEngine:
    """Checks and lowers the contracts of a Happy IR module."""

    def __init__(
        self,
        source: Optional[str] = None,
        filename: Optional[str] = None,
        options: Optional[ContractOptions] = None,
    ) -> None:
        self.source = source
        self.filename = filename
        self.options = options or ContractOptions()
        self.diagnostics: List[ContractDiagnostic] = []
        self._builder = IRBuilder()
        self._module: Optional[IRModule] = None
        self._known_names: Set[str] = set()

    # -- diagnostics ----------------------------------------------------
    def _emit(
        self,
        code: str,
        message: str,
        loc: Optional[SourceLocation],
        suggestion: Optional[str] = None,
        severity: str = "error",
    ) -> None:
        self.diagnostics.append(
            ContractDiagnostic(
                code=code,
                message=message,
                location=loc,
                suggestion=suggestion,
                severity=severity,
                filename=self.filename,
                source=self.source,
            )
        )

    def _error(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, "error")

    def _warn(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, "warning")

    def _note(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, "note")

    # -- entry ----------------------------------------------------------
    def analyze(self, module: IRModule) -> ContractReport:
        """Check and lower every contract in ``module``."""
        self._module = module
        self._collect_known_names(module)
        infos: List[ContractInfo] = []

        # Type invariants
        for t in module.types:
            info = self._analyze_type_invariants(t)
            if info is not None:
                infos.append(info)

        # Functions
        for f in module.functions:
            info = self._analyze_function(f, kind="function")
            if info is not None:
                infos.append(info)

        # Rules
        for r in module.rules:
            info = self._analyze_rule(r)
            if info is not None:
                infos.append(info)

        # Agents (goal + entry/exit contracts + nested functions)
        for a in module.agents:
            info = self._analyze_agent(a)
            if info is not None:
                infos.append(info)
            for f in a.functions:
                sub = self._analyze_function(f, kind="method", owner=a.name)
                if sub is not None:
                    infos.append(sub)

        # AI blocks
        for ai in module.ai_blocks:
            info = self._analyze_ai(ai)
            if info is not None:
                infos.append(info)

        # Apps
        for app in module.apps:
            if app.contracts:
                info = self._analyze_clause_list(
                    owner=app.name,
                    kind="app",
                    clauses=app.contracts,
                    allowed_names=set(),
                    returns=None,
                    permissive=True,
                    loc=app.loc,
                )
                infos.append(info)

        return ContractReport(
            module_name=module.name,
            infos=infos,
            diagnostics=sorted(
                self.diagnostics, key=lambda d: (d.line, d.column, d.code)
            ),
        )

    # -- known names ----------------------------------------------------
    def _collect_known_names(self, module: IRModule) -> None:
        names: Set[str] = set()
        names.update(t.name for t in module.types)
        names.update(e.name for e in module.enums)
        names.update(f.name for f in module.functions)
        names.update(r.name for r in module.rules)
        names.update(p.name for p in module.permissions)
        names.update(c.name for c in module.capabilities)
        names.update(a.name for a in module.agents)
        names.update(a.name for a in module.ai_blocks)
        for i in module.imports:
            names.update(i.symbols)
            names.update(i.local_names)
        self._known_names = names

    # -- generic clause-list analysis -----------------------------------
    def _analyze_clause_list(
        self,
        owner: str,
        kind: str,
        clauses: Sequence[IRContract],
        allowed_names: Set[str],
        returns: Optional[Type],
        loc: Optional[SourceLocation],
        owner_type: Optional[str] = None,
        permissive: bool = False,
    ) -> ContractInfo:
        info = ContractInfo(
            name=owner, kind=kind, owner_type=owner_type, loc=loc
        )
        seen_fingerprints: Dict[Tuple[str, str], IRContract] = {}
        for clause in clauses:
            if clause.condition is None:
                self._error(
                    CODE_EMPTY_CONTRACT,
                    f"'{clause.kind}' clause has no condition",
                    clause.loc,
                    "write a Bool predicate, e.g. "
                    f"'{clause.kind} value >= 0'",
                )
                continue

            checked = CheckedContract(
                kind=clause.kind,
                clause=clause,
                predicate=clause.condition,
                is_bool=_predicate_is_bool(clause.condition),
                free_vars=_free_names(clause.condition),
                refers_to_result=clause.refers_to_result,
                refers_to_old=clause.refers_to_old,
                trivial=_predicate_is_trivially_true(clause.condition),
            )
            loc_c = clause.condition.loc or clause.loc

            # -- static check: Bool-typed predicate ---------------------
            if self.options.check_bool and checked.is_bool is False:
                self._error(
                    CODE_CONTRACT_NOT_BOOL,
                    f"'{clause.kind}' predicate must be Bool, "
                    "but this expression is a value",
                    loc_c,
                    "use a comparison or logical expression, "
                    "e.g. 'x > 0', 'a && b', or a Bool-returning call",
                )

            # -- static check: `result` only for non-Unit returns -------
            if (
                clause.kind == ContractKind.ENSURES
                and checked.refers_to_result
                and returns is not None
                and _is_unit(returns)
            ):
                self._error(
                    CODE_RESULT_ON_UNIT,
                    f"'ensures' references 'result' but '{owner}' returns Unit",
                    loc_c,
                    "remove the 'result' reference or declare a return type",
                )

            # -- static check: old-state note ---------------------------
            if checked.refers_to_old and self.options.note_old_state:
                self._note(
                    N_OLD_STATE,
                    f"'{clause.kind}' references the pre-state "
                    "(old/pre) — accepted and recorded for runtime checking",
                    loc_c,
                    "old-state references are supported but not yet "
                    "statically verified",
                )

            # -- static check: trivially true ---------------------------
            if self.options.check_trivial and checked.trivial:
                self._warn(
                    W_TRIVIAL_CONTRACT,
                    f"'{clause.kind}' predicate is always true",
                    loc_c,
                    "a trivially-true contract adds no guarantee; "
                    "express a meaningful condition or remove it",
                )

            # -- static check: duplicate clause -------------------------
            fp = (clause.kind, _expr_fingerprint(clause.condition))
            if self.options.check_duplicates and fp in seen_fingerprints:
                self._warn(
                    W_DUPLICATE_CONTRACT,
                    f"duplicate '{clause.kind}' clause",
                    clause.loc or loc_c,
                    "this predicate is already stated for the same target",
                )
            else:
                seen_fingerprints[fp] = clause

            # -- static check: free variables resolve -------------------
            if self.options.check_free_vars and not permissive:
                resolved = allowed_names | self._known_names | _PSEUDO_NAMES
                for name in checked.free_vars:
                    if name not in resolved:
                        self._warn(
                            CODE_UNKNOWN_CONTRACT_VAR,
                            f"'{clause.kind}' references unknown name '{name}'",
                            loc_c,
                            "contracts may reference parameters, fields, "
                            "'result', and module-level names",
                        )

            # -- lower to an IR assertion -------------------------------
            checked.assertion = self._build_assertion(
                kind=clause.kind,
                predicate=clause.condition,
                message=clause.message,
                owner=owner,
            )
            if clause.kind == ContractKind.REQUIRES:
                info.entry_assertions.append(checked.assertion)
            elif clause.kind == ContractKind.ENSURES:
                info.exit_assertions.append(checked.assertion)
            elif clause.kind == ContractKind.INVARIANT:
                info.invariant_assertions.append(checked.assertion)

            info.contracts.append(checked)

        return info

    def _build_assertion(
        self,
        kind: str,
        predicate: IRExpr,
        message: Optional[str],
        owner: str,
    ) -> IRAssert:
        return self._builder.attach(
            IRAssert(
                loc=predicate.loc,
                kind=kind,
                predicate=predicate,
                message=message,
                owner=owner,
            )
        )

    # -- per-declaration ------------------------------------------------
    def _analyze_type_invariants(self, decl: IRTypeDecl) -> Optional[ContractInfo]:
        invs = [c for c in decl.invariants if c.kind == ContractKind.INVARIANT]
        if not invs:
            return None
        field_names = {f.name for f in decl.fields}
        info = self._analyze_clause_list(
            owner=decl.name,
            kind="struct",
            clauses=invs,
            allowed_names=field_names | {"self"},
            returns=None,
            loc=decl.loc,
            owner_type=decl.name,
            permissive=False,
        )
        info.owner_type = decl.name
        # Invariants also become anchors on entry/exit of the type's methods.
        info.invariant_assertions = list(info.entry_assertions)
        return info

    def _analyze_function(
        self, decl: IRFunction, kind: str = "function", owner: Optional[str] = None
    ) -> Optional[ContractInfo]:
        if not decl.contracts:
            return None
        allowed = {p.name for p in decl.params}
        if decl.owner:
            allowed.add(decl.owner)
        info = self._analyze_clause_list(
            owner=decl.name,
            kind=kind,
            clauses=decl.contracts,
            allowed_names=allowed,
            returns=decl.returns,
            loc=decl.loc,
            owner_type=owner,
        )
        if self.options.note_abstract and decl.body is None:
            self._note(
                N_ABSTRACT_CONTRACT,
                f"'{decl.name}' declares contracts but has no body to check",
                decl.loc,
                "declare an interface signature or add an implementation",
            )
        return info

    def _analyze_rule(self, decl: IRRule) -> Optional[ContractInfo]:
        allowed = {p.name for p in decl.params}
        clauses = list(decl.contracts)
        if decl.condition is not None:
            clauses = clauses + [
                IRContract(
                    loc=decl.condition.loc,
                    kind=ContractKind.ENSURES,
                    condition=decl.condition,
                    message=f"rule '{decl.name}'",
                )
            ]
        if not clauses:
            return None
        return self._analyze_clause_list(
            owner=decl.name,
            kind="rule",
            clauses=clauses,
            allowed_names=allowed,
            returns=None,
            loc=decl.loc,
            permissive=True,
        )

    def _analyze_agent(self, decl: IRAgent) -> Optional[ContractInfo]:
        if not decl.contracts:
            return None
        # Agent-level contracts may reference free agent state, so resolve
        # free variables permissively.
        return self._analyze_clause_list(
            owner=decl.name,
            kind="agent",
            clauses=decl.contracts,
            allowed_names=set(),
            returns=None,
            loc=decl.loc,
            permissive=True,
        )

    def _analyze_ai(self, decl: IRAi) -> Optional[ContractInfo]:
        if not decl.contracts:
            return None
        return self._analyze_clause_list(
            owner=decl.name,
            kind="ai",
            clauses=decl.contracts,
            allowed_names=set(),
            returns=None,
            loc=decl.loc,
            permissive=True,
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def check_contracts(
    source_or_module,
    filename: Optional[str] = None,
    options: Optional[ContractOptions] = None,
    source: Optional[str] = None,
) -> ContractReport:
    """Check the contracts of a module or of raw source.

    ``source_or_module`` may be Happy source (``str``), an AST ``Program``, an
    ``AnalysisResult``, or an already-lowered :class:`~happy.compiler.ir.IRModule`.
    """
    from . import ast as _ast

    if isinstance(source_or_module, IRModule):
        module = source_or_module
        src = source
    else:
        # Program / AnalysisResult / source string -> lowered module
        from .ir import lower

        if isinstance(source_or_module, str):
            from .semantic import analyze as _analyze

            src = source_or_module
            analysis = _analyze(source_or_module, filename=filename)
        elif isinstance(source_or_module, _ast.Program):
            from .semantic import analyze as _analyze

            src = None
            analysis = _analyze(source_or_module, filename=filename)
        else:
            src = source
            analysis = source_or_module
        module = lower(analysis)

    return ContractEngine(
        source=src, filename=filename, options=options
    ).analyze(module)
