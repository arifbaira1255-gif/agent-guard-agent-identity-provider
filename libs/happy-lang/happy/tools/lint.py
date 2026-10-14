"""Static linter for the Happy language (Step 6).

``happy lint`` runs a set of opinionated, deterministic checks over a ``.hpy``
program.  Unlike the compiler's semantic analyzer (which reports *errors* that
make a program invalid), the linter reports *style and safety smells* that a
program can technically compile with but that a reviewer would flag.

Rule families
-------------
======================  =====================================================
Code                    Rule
======================  =====================================================
``L001``                **Naming conventions** — types/enums/capabilities/
                        permissions are ``PascalCase``; functions, variables,
                        fields, rules and enum variants are ``snake_case``;
                        constants are ``SCREAMING_SNAKE_CASE``.
``L002``                **Missing contracts** — a function with parameters
                        has no ``requires``; a function returning a non-``Unit``
                        value has no ``ensures``; a struct with fields has no
                        ``invariant``.
``L003``                **Unused code** — unused imports, unused local
                        variables, unused private functions.
``L004``                **Weak permission model** — an agent with capabilities
                        but no permissions; a permission that only grants
                        (``can``) and never denies (``cannot``); a capability
                        granting a high-risk action; an agent performing a
                        sensitive operation with no capability at all.
======================  =====================================================

Every finding carries a stable code, a severity (``error`` / ``warning`` /
``info``), a precise ``.hpy`` location and a remediation hint.  ``LintReport.ok``
is true when there are no ``error``-severity findings.

Typical use::

    from happy.tools.lint import lint_source

    report = lint_source(source, filename="demo.hpy")
    if not report.ok:
        print(report.format())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..compiler import ast
from ..compiler.errors import HappyError, SourceLocation, format_diagnostic
from ..compiler.parser import parse
from ..compiler.permissions import ENFORCEMENT_MAP, _normalise_action
from ..security.analyzer import HIGH_RISK_ACTIONS

__all__ = [
    "Severity",
    "LintFinding",
    "LintReport",
    "Linter",
    "lint_source",
    "lint_program",
    "PASCAL_RE",
    "SNAKE_RE",
    "SCREAMING_RE",
]


class Severity:
    """Lint finding severities."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


#: ``PascalCase`` — a capitalised identifier with no underscores.
PASCAL_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
#: ``snake_case`` — lowercase words joined by single underscores.
SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
#: ``SCREAMING_SNAKE_CASE`` — uppercase words joined by single underscores.
SCREAMING_RE = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")

#: Actions that are inherently high-risk when granted by a capability.
_HIGH_RISK = set(HIGH_RISK_ACTIONS)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@dataclass
class LintFinding:
    """A single lint finding."""

    code: str
    message: str
    severity: str = Severity.WARNING
    location: Optional[SourceLocation] = None
    suggestion: Optional[str] = None
    rule: str = ""
    filename: Optional[str] = None
    source: Optional[str] = None

    @property
    def blocking(self) -> bool:
        return self.severity == Severity.ERROR

    def render(self) -> str:
        return format_diagnostic(
            f"[{self.code}] {self.message}",
            location=self.location,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()


@dataclass
class LintReport:
    """The outcome of a lint run."""

    filename: Optional[str] = None
    findings: List[LintFinding] = field(default_factory=list)
    parse_error: Optional[HappyError] = None

    # -- queries --------------------------------------------------------
    @property
    def errors(self) -> List[LintFinding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> List[LintFinding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def infos(self) -> List[LintFinding]:
        return [f for f in self.findings if f.severity == Severity.INFO]

    @property
    def ok(self) -> bool:
        return not self.errors and self.parse_error is None

    def by_code(self, code: str) -> List[LintFinding]:
        return [f for f in self.findings if f.code == code]

    def codes(self) -> List[str]:
        return sorted({f.code for f in self.findings})

    # -- rendering ------------------------------------------------------
    def sorted(self) -> List[LintFinding]:
        return sorted(
            self.findings,
            key=lambda f: (
                f.location.line if f.location else 0,
                f.location.column if f.location else 0,
                f.code,
            ),
        )

    def format(self) -> str:
        if self.parse_error is not None:
            return self.parse_error.render()
        if not self.findings:
            return "lint: no findings"
        return "\n\n".join(f.render() for f in self.sorted())

    def summary(self) -> str:
        return (
            f"lint: {len(self.findings)} finding(s) "
            f"({len(self.errors)} error, {len(self.warnings)} warning, "
            f"{len(self.infos)} info)"
        )

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.format()


# ---------------------------------------------------------------------------
# Linter
# ---------------------------------------------------------------------------
class Linter:
    """The rule engine.  Stateless; safe to reuse across files."""

    def __init__(self, strict: bool = False) -> None:
        #: When True, naming warnings are promoted to errors.
        self.strict = strict

    # -- public API -----------------------------------------------------
    def lint(self, source: str, filename: Optional[str] = None) -> LintReport:
        report = LintReport(filename=filename)
        try:
            program = parse(source, filename=filename)
        except HappyError as exc:
            report.parse_error = exc
            return report
        self.lint_program(program, report, source=source, filename=filename)
        return report

    def lint_program(
        self,
        program: ast.Program,
        report: Optional[LintReport] = None,
        source: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> LintReport:
        report = report or LintReport(filename=filename)
        self._check_naming(program, report, source, filename)
        self._check_contracts(program, report, source, filename)
        self._check_unused(program, report, source, filename)
        self._check_permissions(program, report, source, filename)
        return report

    # -- helpers --------------------------------------------------------
    def _finding(
        self,
        report: LintReport,
        code: str,
        message: str,
        node: Any = None,
        severity: str = Severity.WARNING,
        suggestion: Optional[str] = None,
        rule: str = "",
        source: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> None:
        loc = getattr(node, "loc", None) if node is not None else None
        if loc is not None and not isinstance(loc, SourceLocation):
            loc = SourceLocation(
                line=int(getattr(loc, "line", 0) or 0),
                column=int(getattr(loc, "column", 0) or 0),
            )
        report.findings.append(
            LintFinding(
                code=code,
                message=message,
                severity=severity,
                location=loc,
                suggestion=suggestion,
                rule=rule,
                filename=filename,
                source=source,
            )
        )

    def _naming_severity(self) -> str:
        return Severity.ERROR if self.strict else Severity.WARNING

    # ------------------------------------------------------------------
    # L001 — naming conventions
    # ------------------------------------------------------------------
    def _check_naming(
        self,
        program: ast.Program,
        report: LintReport,
        source: Optional[str],
        filename: Optional[str],
    ) -> None:
        sev = self._naming_severity()

        def check_pascal(name: str, node: Any, what: str) -> None:
            if not PASCAL_RE.match(name):
                self._finding(
                    report, "L001",
                    f"{what} '{name}' should be PascalCase",
                    node=node, severity=sev,
                    suggestion=f"rename to '{_to_pascal(name)}'",
                    rule="naming", source=source, filename=filename,
                )

        def check_snake(name: str, node: Any, what: str) -> None:
            if not SNAKE_RE.match(name):
                self._finding(
                    report, "L001",
                    f"{what} '{name}' should be snake_case",
                    node=node, severity=sev,
                    suggestion=f"rename to '{_to_snake(name)}'",
                    rule="naming", source=source, filename=filename,
                )

        for decl in program.declarations:
            if isinstance(decl, ast.StructDecl):
                check_pascal(decl.name, decl, "type")
                for f in decl.fields:
                    check_snake(f.name, f, "field")
            elif isinstance(decl, ast.EnumDecl):
                check_pascal(decl.name, decl, "enum")
                for v in decl.variants:
                    check_pascal(v.name, v, "enum variant")
            elif isinstance(decl, ast.FunctionDecl):
                check_snake(decl.name, decl, "function")
                for p in decl.params:
                    check_snake(p.name, p, "parameter")
            elif isinstance(decl, ast.RuleDecl):
                check_snake(decl.name, decl, "rule")
            elif isinstance(decl, ast.PermissionDecl):
                check_pascal(decl.name, decl, "permission")
            elif isinstance(decl, ast.CapabilityDecl):
                check_pascal(decl.name, decl, "capability")
            elif isinstance(decl, ast.AgentDecl):
                check_pascal(decl.name, decl, "agent")
                if decl.body is not None:
                    for stmt in decl.body.statements:
                        if isinstance(stmt, ast.FunctionDecl):
                            check_snake(stmt.name, stmt, "function")
            elif isinstance(decl, ast.AiDecl):
                check_pascal(decl.name, decl, "ai block")
            elif isinstance(decl, ast.AppDecl):
                check_pascal(decl.name, decl, "app")

    # ------------------------------------------------------------------
    # L002 — missing contracts
    # ------------------------------------------------------------------
    def _check_contracts(
        self,
        program: ast.Program,
        report: LintReport,
        source: Optional[str],
        filename: Optional[str],
    ) -> None:
        for decl in program.declarations:
            if isinstance(decl, ast.StructDecl):
                if decl.fields and not decl.invariants:
                    self._finding(
                        report, "L002",
                        f"type '{decl.name}' has fields but no 'invariant'",
                        node=decl, severity=Severity.INFO,
                        suggestion="add an 'invariant' clause to document the "
                        "type's validity condition",
                        rule="missing_contract", source=source, filename=filename,
                    )
            elif isinstance(decl, ast.FunctionDecl):
                self._check_function_contracts(decl, report, source, filename)
            elif isinstance(decl, ast.AgentDecl):
                if decl.body is not None:
                    for stmt in decl.body.statements:
                        if isinstance(stmt, ast.FunctionDecl):
                            self._check_function_contracts(
                                stmt, report, source, filename
                            )

    def _check_function_contracts(
        self,
        fn: ast.FunctionDecl,
        report: LintReport,
        source: Optional[str],
        filename: Optional[str],
    ) -> None:
        kinds = {c.kind for c in fn.contracts}
        if fn.params and "requires" not in kinds:
            self._finding(
                report, "L002",
                f"function '{fn.name}' takes parameters but has no 'requires' "
                "precondition",
                node=fn, severity=Severity.WARNING,
                suggestion="add a 'requires' clause documenting the accepted "
                "input domain",
                rule="missing_contract", source=source, filename=filename,
            )
        returns_value = fn.returns is not None and not _is_unit(fn.returns)
        if returns_value and "ensures" not in kinds:
            self._finding(
                report, "L002",
                f"function '{fn.name}' returns a value but has no 'ensures' "
                "postcondition",
                node=fn, severity=Severity.INFO,
                suggestion="add an 'ensures' clause describing the result",
                rule="missing_contract", source=source, filename=filename,
            )

    # ------------------------------------------------------------------
    # L003 — unused code
    # ------------------------------------------------------------------
    def _check_unused(
        self,
        program: ast.Program,
        report: LintReport,
        source: Optional[str],
        filename: Optional[str],
    ) -> None:
        # (a) unused imports.
        used_names = _all_identifiers(program)
        for imp in program.imports:
            if imp.symbols:
                for sym in imp.symbols:
                    if sym not in used_names:
                        self._finding(
                            report, "L003",
                            f"imported symbol '{sym}' is never used",
                            node=imp, severity=Severity.INFO,
                            suggestion=f"remove '{sym}' from the import",
                            rule="unused_code", source=source, filename=filename,
                        )
            else:
                local = imp.alias or imp.name.split(".")[0]
                if local not in used_names:
                    self._finding(
                        report, "L003",
                        f"import '{imp.name}' is never used",
                        node=imp, severity=Severity.INFO,
                        suggestion="remove the unused import",
                        rule="unused_code", source=source, filename=filename,
                    )

        # (b) unused local variables (per function body).
        for fn in _iter_functions(program):
            if fn.body is None:
                continue
            declared: Dict[str, ast.LetStmt] = {}
            for stmt in _walk_stmts(fn.body):
                if isinstance(stmt, ast.LetStmt):
                    declared.setdefault(stmt.name, stmt)
            used = _identifiers_in_block(fn.body)
            for name, stmt in declared.items():
                # A binding is "used" if it appears anywhere other than its own
                # declaration; count occurrences to avoid the declaration itself.
                if used.get(name, 0) <= 0:
                    self._finding(
                        report, "L003",
                        f"variable '{name}' is declared but never used",
                        node=stmt, severity=Severity.WARNING,
                        suggestion=f"remove '{name}' or use it",
                        rule="unused_code", source=source, filename=filename,
                    )

        # (c) unused private functions (leading underscore, never referenced).
        for fn in _iter_functions(program):
            if fn.name.startswith("_") and used_names.get(fn.name, 0) == 0:
                self._finding(
                    report, "L003",
                    f"private function '{fn.name}' is never called",
                    node=fn, severity=Severity.INFO,
                    suggestion="remove it or make it public",
                    rule="unused_code", source=source, filename=filename,
                )

    # ------------------------------------------------------------------
    # L004 — weak permission model
    # ------------------------------------------------------------------
    def _check_permissions(
        self,
        program: ast.Program,
        report: LintReport,
        source: Optional[str],
        filename: Optional[str],
    ) -> None:
        cap_grants: Dict[str, Set[str]] = {}
        for decl in program.declarations:
            if isinstance(decl, ast.CapabilityDecl):
                cap_grants[decl.name] = {_normalise_action(g) for g in decl.grants}

        for decl in program.declarations:
            if isinstance(decl, ast.PermissionDecl):
                if decl.can and not decl.cannot:
                    self._finding(
                        report, "L004",
                        f"permission '{decl.name}' only grants ('can') and never "
                        "denies ('cannot')",
                        node=decl, severity=Severity.INFO,
                        suggestion="add a 'cannot' clause to bound the permission",
                        rule="weak_permission", source=source, filename=filename,
                    )
            elif isinstance(decl, ast.CapabilityDecl):
                risky = sorted(cap_grants.get(decl.name, set()) & _HIGH_RISK)
                for action in risky:
                    self._finding(
                        report, "L004",
                        f"capability '{decl.name}' grants high-risk action "
                        f"'{action}'",
                        node=decl, severity=Severity.WARNING,
                        suggestion="scope the capability to the minimum action "
                        "required, or pair it with a permission that denies it",
                        rule="weak_permission", source=source, filename=filename,
                    )
            elif isinstance(decl, ast.AgentDecl):
                if decl.capabilities and not decl.permissions:
                    self._finding(
                        report, "L004",
                        f"agent '{decl.name}' wields capabilities but declares no "
                        "permission",
                        node=decl, severity=Severity.WARNING,
                        suggestion="add a 'permission [...]' clause to bound the "
                        "agent's authority",
                        rule="weak_permission", source=source, filename=filename,
                    )
                if not decl.capabilities:
                    sensitive = _sensitive_calls_in_agent(decl)
                    for callee, node in sensitive:
                        self._finding(
                            report, "L004",
                            f"agent '{decl.name}' performs sensitive operation "
                            f"'{callee}' but declares no capability",
                            node=node, severity=Severity.WARNING,
                            suggestion="grant a capability that covers this "
                            "operation",
                            rule="weak_permission", source=source, filename=filename,
                        )


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
def _is_unit(node: ast.TypeNode) -> bool:
    return isinstance(node, ast.PrimitiveType) and node.name == "Unit"


def _iter_functions(program: ast.Program) -> Iterable[ast.FunctionDecl]:
    for decl in program.declarations:
        if isinstance(decl, ast.FunctionDecl):
            yield decl
        elif isinstance(decl, ast.AgentDecl) and decl.body is not None:
            for stmt in decl.body.statements:
                if isinstance(stmt, ast.FunctionDecl):
                    yield stmt


def _walk_stmts(block: ast.Block) -> Iterable[ast.Stmt]:
    for stmt in block.statements:
        yield stmt
        for child in _child_blocks(stmt):
            yield from _walk_stmts(child)


def _child_blocks(stmt: ast.Stmt) -> List[ast.Block]:
    out: List[ast.Block] = []
    if isinstance(stmt, ast.IfStmt):
        if stmt.then_branch is not None:
            out.append(stmt.then_branch)
        eb = stmt.else_branch
        while isinstance(eb, ast.IfStmt):
            if eb.then_branch is not None:
                out.append(eb.then_branch)
            eb = eb.else_branch
        if isinstance(eb, ast.Block):
            out.append(eb)
    elif isinstance(stmt, (ast.WhileStmt, ast.ForStmt)):
        if stmt.body is not None:
            out.append(stmt.body)
    elif isinstance(stmt, ast.Block):
        out.append(stmt)
    return out


def _identifiers_in_block(block: ast.Block) -> Dict[str, int]:
    """Count identifier *uses* in a block, excluding let-declaration names."""
    counts: Dict[str, int] = {}

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    def visit_expr(expr: Optional[ast.Expr]) -> None:
        if expr is None:
            return
        if isinstance(expr, ast.Identifier):
            bump(expr.name)
        for child in expr.children():
            if isinstance(child, ast.Expr):
                visit_expr(child)
            elif isinstance(child, ast.FieldInit):
                visit_expr(child.value)

    for stmt in _walk_stmts(block):
        if isinstance(stmt, ast.LetStmt):
            visit_expr(stmt.value)
        elif isinstance(stmt, ast.AssignStmt):
            visit_expr(stmt.target)
            visit_expr(stmt.value)
        elif isinstance(stmt, ast.ExprStmt):
            visit_expr(stmt.expr)
        elif isinstance(stmt, ast.ReturnStmt):
            visit_expr(stmt.value)
        elif isinstance(stmt, ast.IfStmt):
            visit_expr(stmt.condition)
        elif isinstance(stmt, ast.WhileStmt):
            visit_expr(stmt.condition)
        elif isinstance(stmt, ast.ForStmt):
            visit_expr(stmt.iterable)
    return counts


def _all_identifiers(program: ast.Program) -> Dict[str, int]:
    counts: Dict[str, int] = {}

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    def visit_expr(expr: Optional[ast.Expr]) -> None:
        if expr is None:
            return
        if isinstance(expr, ast.Identifier):
            bump(expr.name)
        for child in expr.children():
            if isinstance(child, ast.Expr):
                visit_expr(child)
            elif isinstance(child, ast.FieldInit):
                visit_expr(child.value)

    for decl in program.declarations:
        if isinstance(decl, ast.FunctionDecl) and decl.body is not None:
            for stmt in _walk_stmts(decl.body):
                if isinstance(stmt, ast.ExprStmt):
                    visit_expr(stmt.expr)
                elif isinstance(stmt, ast.AssignStmt):
                    visit_expr(stmt.target)
                    visit_expr(stmt.value)
                elif isinstance(stmt, ast.LetStmt):
                    visit_expr(stmt.value)
                elif isinstance(stmt, ast.ReturnStmt):
                    visit_expr(stmt.value)
                elif isinstance(stmt, ast.IfStmt):
                    visit_expr(stmt.condition)
                elif isinstance(stmt, ast.WhileStmt):
                    visit_expr(stmt.condition)
                elif isinstance(stmt, ast.ForStmt):
                    visit_expr(stmt.iterable)
        elif isinstance(decl, ast.AppDecl) and decl.body is not None:
            for stmt in _walk_stmts(decl.body):
                if isinstance(stmt, ast.ExprStmt):
                    visit_expr(stmt.expr)
                elif isinstance(stmt, ast.AssignStmt):
                    visit_expr(stmt.target)
                    visit_expr(stmt.value)
                elif isinstance(stmt, ast.LetStmt):
                    visit_expr(stmt.value)
                elif isinstance(stmt, ast.ReturnStmt):
                    visit_expr(stmt.value)
        elif isinstance(decl, ast.AgentDecl) and decl.body is not None:
            for stmt in decl.body.statements:
                if isinstance(stmt, ast.FunctionDecl) and stmt.body is not None:
                    for s in _walk_stmts(stmt.body):
                        if isinstance(s, ast.ExprStmt):
                            visit_expr(s.expr)
                        elif isinstance(s, ast.AssignStmt):
                            visit_expr(s.target)
                            visit_expr(s.value)
                        elif isinstance(s, ast.LetStmt):
                            visit_expr(s.value)
                        elif isinstance(s, ast.ReturnStmt):
                            visit_expr(s.value)
    return counts


def _sensitive_calls_in_agent(agent: ast.AgentDecl) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if agent.body is None:
        return out
    for stmt in agent.body.statements:
        if isinstance(stmt, ast.FunctionDecl) and stmt.body is not None:
            for s in _walk_stmts(stmt.body):
                expr = None
                if isinstance(s, ast.ExprStmt):
                    expr = s.expr
                elif isinstance(s, ast.AssignStmt):
                    expr = s.value
                elif isinstance(s, ast.LetStmt):
                    expr = s.value
                elif isinstance(s, ast.ReturnStmt):
                    expr = s.value
                for call in _calls_in(expr):
                    name = _callee_name(call)
                    if name in ENFORCEMENT_MAP:
                        out.append((name, call))
    return out


def _calls_in(expr: Optional[ast.Expr]) -> Iterable[ast.CallExpr]:
    if expr is None:
        return
    if isinstance(expr, ast.CallExpr):
        yield expr
    for child in expr.children():
        if isinstance(child, ast.Expr):
            yield from _calls_in(child)


def _callee_name(call: ast.CallExpr) -> Optional[str]:
    callee = call.callee
    if isinstance(callee, ast.Identifier):
        return callee.name
    if isinstance(callee, ast.MemberExpr):
        return callee.name
    return None


# ---------------------------------------------------------------------------
# Name-case conversion (for suggestions)
# ---------------------------------------------------------------------------
def _to_snake(name: str) -> str:
    out: List[str] = []
    for i, ch in enumerate(name):
        if ch.isupper():
            if i > 0 and (not name[i - 1].isupper() or (i + 1 < len(name) and name[i + 1].islower())):
                out.append("_")
            out.append(ch.lower())
        elif ch == "-":
            out.append("_")
        else:
            out.append(ch)
    return "".join(out).strip("_")


def _to_pascal(name: str) -> str:
    parts = re.split(r"[_\-\s]+", name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------
def lint_program(
    program: ast.Program, filename: Optional[str] = None, strict: bool = False
) -> LintReport:
    """Lint an already-parsed :class:`~happy.compiler.ast.Program`."""
    return Linter(strict=strict).lint_program(program, filename=filename)


def lint_source(
    source: str, filename: Optional[str] = None, strict: bool = False
) -> LintReport:
    """Parse and lint ``source``; a parse error is reported, never raised."""
    return Linter(strict=strict).lint(source, filename=filename)
