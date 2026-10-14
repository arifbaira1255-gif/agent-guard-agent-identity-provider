"""Static security analyzer for the Happy language (Step 5).

The analyzer is a small, deterministic **rule engine** that runs over the typed
IR (and, where the IR is not expressive enough, over the raw source) looking for
four classes of security defect that matter for AI-generated code:

======================  =====================================================
Code                    Rule
======================  =====================================================
``SEC001``              **Secret exposure** — a ``secret`` value flows into a
                        log / string / serialization sink.
``SEC002``              **Unverified payment execution** — a payment-like
                        operation runs without a contract, rule or capability
                        guarding it.
``SEC003``              **Permission escalation** — an agent wields a
                        capability that exceeds its declared permissions, or
                        performs an operation no capability covers.
``SEC004``              **Unsafe IO** — file / network operations with
                        dynamic (non-literal) targets, or writes without an
                        input-sanitisation rule.
``SEC011``              **Capability bypass** — a sensitive operation runs
                        outside any agent scope (in an ``app`` body or in a
                        plain function reachable from one).
``SEC012``              **Indirect sensitive reference** — a sensitive
                        built-in is aliased / passed as a value, hiding the
                        call from name-based checks.
======================  =====================================================

Every finding carries a stable code, a severity, a precise ``.hpy`` location and
a remediation suggestion.  :class:`SecurityReport` exposes ``ok`` (no blocking
findings) and ``blocking`` (the errors), which is exactly what the verification
pipeline's APPROVED gate consumes.

Typical use::

    from happy.security.analyzer import SecurityAnalyzer

    report = SecurityAnalyzer().analyze(source, filename="generated.hpy")
    if not report.ok:
        print(report.format())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..compiler import analyze, parse
from ..compiler.errors import SourceLocation, format_diagnostic
from ..compiler.ir import (
    IRAgent,
    IRAi,
    IRAiExpr,
    IRApp,
    IRAssign,
    IRAwait,
    IRBinary,
    IRBlock,
    IRCall,
    IRExpr,
    IRExprStmt,
    IRFor,
    IRFunction,
    IRIf,
    IRIndex,
    IRLet,
    IRList,
    IRLiteral,
    IRMember,
    IRModule,
    IRName,
    IRReturn,
    IRStruct,
    IRUnary,
    IRWhile,
    lower,
)
from ..compiler.permissions import ENFORCEMENT_MAP, _normalise_action

__all__ = [
    "Severity",
    "SecurityFinding",
    "SecurityReport",
    "SecurityAnalyzer",
    "analyze_security",
    "SECRET_SINKS",
    "PAYMENT_PATTERNS",
    "UNSAFE_IO_OPS",
]


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
class Severity:
    """Finding severities."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


#: Functions that render their argument into a string / log (secret sinks).
SECRET_SINKS: Set[str] = {
    "print",
    "println",
    "eprint",
    "str",
    "log",
    "debug",
    "info",
    "warn",
    "error",
    "json_encode",
    "json_stringify",
    "to_json",
    "serialize",
    "format",
}

#: Name fragments that mark a payment-like operation.
PAYMENT_PATTERNS: Tuple[str, ...] = (
    "pay",
    "payment",
    "charge",
    "transfer",
    "refund",
    "withdraw",
    "debit",
    "credit",
    "settle",
    "invoice",
    "checkout",
)

#: Operations that touch the filesystem or the network.
UNSAFE_IO_OPS: Set[str] = {
    "read_file",
    "write_file",
    "append_file",
    "http_get",
    "http_post",
    "http_request",
    "download",
    "tcp_connect",
    "tcp_send",
    "remove_file",
    "remove_dir",
    "copy_file",
    "move_file",
    "make_dir",
    "shell",
    "spawn_process",
    "open",
    "exec",
    "eval",
    "system",
    "subprocess",
}

#: Actions that are inherently high-risk when granted.
HIGH_RISK_ACTIONS: Set[str] = {"payments", "secrets", "admin", "proc", "db_write"}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
@dataclass
class SecurityFinding:
    """A single security finding."""

    code: str
    message: str
    severity: str = Severity.ERROR
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
class SecurityReport:
    """The outcome of a security analysis run."""

    filename: Optional[str] = None
    findings: List[SecurityFinding] = field(default_factory=list)

    # -- queries --------------------------------------------------------
    @property
    def errors(self) -> List[SecurityFinding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> List[SecurityFinding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def blocking(self) -> List[SecurityFinding]:
        return self.errors

    @property
    def ok(self) -> bool:
        return not self.errors

    def by_code(self, code: str) -> List[SecurityFinding]:
        return [f for f in self.findings if f.code == code]

    def codes(self) -> List[str]:
        return sorted({f.code for f in self.findings})

    # -- rendering ------------------------------------------------------
    def format(self) -> str:
        if not self.findings:
            return "security: no findings"
        return "\n\n".join(f.render() for f in self.sorted())

    def sorted(self) -> List[SecurityFinding]:
        return sorted(
            self.findings,
            key=lambda f: (
                f.location.line if f.location else 0,
                f.location.column if f.location else 0,
                f.code,
            ),
        )

    def summary(self) -> str:
        return (
            f"security: {len(self.findings)} findings "
            f"({len(self.errors)} blocking, {len(self.warnings)} warnings)"
        )

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.format()


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class SecurityAnalyzer:
    """The rule engine.  Stateless; safe to reuse across candidates."""

    def __init__(self, strict: bool = True) -> None:
        #: When True, warnings about dynamic IO are promoted to errors.
        self.strict = strict

    # -- public API -----------------------------------------------------
    def analyze(
        self,
        source_or_module: Any,
        filename: Optional[str] = None,
        source: Optional[str] = None,
    ) -> SecurityReport:
        """Analyze Happy source, an AST, an analysis result or an IR module."""
        module, src = self._as_module(source_or_module, filename, source)
        report = SecurityReport(filename=filename)

        if module is None:
            # Could not lower (e.g. parse error) — fall back to a source scan.
            if src:
                self._scan_source(src, filename, report)
            return report

        self._check_secret_exposure(module, src, filename, report)
        self._check_payments(module, src, filename, report)
        self._check_escalation(module, src, filename, report)
        self._check_unsafe_io(module, src, filename, report)
        self._check_capability_bypass(module, src, filename, report)
        if src:
            self._scan_source(src, filename, report)
            self._scan_source_extended(src, filename, report)
        return report

    # ------------------------------------------------------------------
    # SEC011 — capability bypass
    # ------------------------------------------------------------------
    def _check_capability_bypass(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        """Flag sensitive operations that run *outside* any capability scope.

        The reported exploit: a ``write_file`` / ``http_get`` placed directly in
        an ``app`` body executes with no agent scope active, so nothing checks
        it.  The runtime denies such operations by default; this static rule
        surfaces the same defect before the program is ever run.

        Scope-less code is the ``app`` body **plus every plain (non-agent)
        function reachable from it**: such functions only get a capability
        scope if an agent happens to be on the call stack, which the app
        cannot guarantee.  A second rule (SEC012) catches sensitive built-ins
        that are aliased or passed as values, since ``let w = write_file;
        w(...)`` hides the call from name matching.
        """
        from ..compiler.permissions import AGENT_REQUIRED_ACTIONS, ENFORCEMENT_MAP

        plain_fns = {fn.name: fn for fn in module.functions}
        reported: Set[int] = set()

        def sensitive(callee: Optional[str]) -> Optional[str]:
            if not callee:
                return None
            action = ENFORCEMENT_MAP.get(callee)
            if action is None or action not in AGENT_REQUIRED_ACTIONS:
                return None
            return action

        for app in module.apps:
            if app.body is None:
                continue
            # Breadth-first over plain functions reachable from the app body.
            scopes: List[Tuple[str, Optional[IRBlock], str]] = [
                (f"the '{app.name}' app body", app.body, app.name)
            ]
            seen_fns: Set[str] = set()
            idx = 0
            while idx < len(scopes):
                where, block, _owner = scopes[idx]
                idx += 1
                for expr in self._walk_block(block):
                    if not isinstance(expr, IRCall):
                        continue
                    callee = _callee_name(expr)
                    callee_is_name = isinstance(expr.callee, IRName)
                    if callee_is_name and callee in plain_fns and callee not in seen_fns:
                        seen_fns.add(callee)  # type: ignore[arg-type]
                        scopes.append(
                            (f"plain function '{callee}' (reachable from the "
                             f"'{app.name}' app)", plain_fns[callee].body, app.name)  # type: ignore[index]
                        )
                    action = sensitive(callee)
                    if action is None or id(expr) in reported:
                        continue
                    reported.add(id(expr))
                    self._finding(
                        report,
                        "SEC011",
                        f"sensitive operation '{callee}' runs in {where}, "
                        f"outside any agent, so no capability ('{action}') guards it",
                        node=expr,
                        suggestion=(
                            "move the operation into an agent that holds a capability "
                            f"granting '{action}', or remove it"
                        ),
                        rule="capability_bypass",
                        source=source,
                        filename=filename,
                    )

        self._check_indirect_references(module, source, filename, report)

    def _check_indirect_references(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        """SEC012 — sensitive built-ins used as values instead of being called."""
        from ..compiler.permissions import AGENT_REQUIRED_ACTIONS, ENFORCEMENT_MAP

        sensitive_names = {
            n for n, a in ENFORCEMENT_MAP.items() if a is not None and a in AGENT_REQUIRED_ACTIONS
        } | {"eval", "exec"}
        module_level = {f.name for f in module.functions} | {
            c.name for c in getattr(module, "constants", [])
        }

        bodies: List[Tuple[Optional[IRBlock], Set[str]]] = []
        for fn, _owner in self._iter_functions(module):
            bodies.append((fn.body, {p.name for p in fn.params}))
        for app in module.apps:
            bodies.append((app.body, set()))

        for block, bound in bodies:
            if block is None:
                continue
            nodes = list(self._walk_block(block))
            locals_ = set(bound) | module_level
            for node in nodes:
                if isinstance(node, IRLet):
                    locals_.add(node.name)
                elif isinstance(node, IRFor):
                    locals_.add(node.variable)
            callee_ids = {id(n.callee) for n in nodes if isinstance(n, IRCall)}
            for node in nodes:
                if (
                    isinstance(node, IRName)
                    and node.role in ("value", "callee")
                    and node.name in sensitive_names
                    and node.name not in locals_
                    and id(node) not in callee_ids
                ):
                    self._finding(
                        report,
                        "SEC012",
                        f"sensitive built-in '{node.name}' is used as a value "
                        "(aliased or passed around), which hides the call from "
                        "static capability checks",
                        node=node,
                        suggestion="call the operation directly inside an agent "
                        "that holds the matching capability",
                        rule="capability_bypass",
                        source=source,
                        filename=filename,
                    )

    # -- module coercion ------------------------------------------------
    def _as_module(
        self, source_or_module: Any, filename: Optional[str], source: Optional[str]
    ) -> Tuple[Optional[IRModule], Optional[str]]:
        if isinstance(source_or_module, IRModule):
            return source_or_module, source
        if isinstance(source_or_module, str):
            src = source_or_module
            try:
                program = parse(src, filename=filename)
                analysis = analyze(program, filename=filename)
                return lower(analysis, source=src, filename=filename), src
            except Exception:  # noqa: BLE001 - unparseable -> source scan only
                return None, src
        # AST Program or AnalysisResult
        try:
            return lower(source_or_module, source=source, filename=filename), source
        except Exception:  # noqa: BLE001
            return None, source

    # -- helpers --------------------------------------------------------
    def _finding(
        self,
        report: SecurityReport,
        code: str,
        message: str,
        node: Any = None,
        severity: str = Severity.ERROR,
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
            SecurityFinding(
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

    def _iter_functions(self, module: IRModule) -> Iterable[Tuple[IRFunction, Optional[str]]]:
        """Yield every function with its owning agent/ai name (or None)."""
        for fn in module.functions:
            yield fn, None
        for agent in module.agents:
            for fn in agent.functions:
                yield fn, agent.name
        for ai in module.ai_blocks:
            for fn in _functions_in_block(ai.body):
                yield fn, ai.name
        for app in module.apps:
            for fn in _functions_in_block(app.body):
                yield fn, app.name

    def _secret_names(self, module: IRModule) -> Set[str]:
        """Names of struct fields declared ``secret``."""
        names: Set[str] = set()
        for type_decl in module.types:
            for fld in type_decl.fields:
                if getattr(fld, "secret", False):
                    names.add(fld.name)
        return names

    def _walk_expr(self, expr: Optional[IRExpr]) -> Iterable[IRExpr]:
        if expr is None:
            return
        yield expr
        for child in expr.children():
            if isinstance(child, IRExpr):
                yield from self._walk_expr(child)

    def _walk_block(self, block: Optional[IRBlock]) -> Iterable[Any]:
        if block is None:
            return
        for stmt in block.statements:
            yield stmt
            for child in stmt.children():
                yield from self._walk_block(child) if isinstance(child, IRBlock) else ()
                if isinstance(child, IRExpr):
                    yield from self._walk_expr(child)

    # ------------------------------------------------------------------
    # SEC001 — secret exposure
    # ------------------------------------------------------------------
    def _check_secret_exposure(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        secret_fields = self._secret_names(module)
        if not secret_fields:
            return

        for fn, owner in self._iter_functions(module):
            # Taint: local names bound to a secret value.
            tainted: Set[str] = set()
            for stmt in self._walk_block(fn.body):
                if isinstance(stmt, IRLet) and stmt.name:
                    if self._expr_touches_secret(stmt.value, secret_fields, tainted):
                        tainted.add(stmt.name)
                if isinstance(stmt, IRAssign) and isinstance(stmt.target, IRName):
                    if self._expr_touches_secret(stmt.value, secret_fields, tainted):
                        tainted.add(stmt.target.name)

            for expr in self._walk_block(fn.body) if fn.body else ():
                if not isinstance(expr, IRCall):
                    continue
                callee = _callee_name(expr)
                if callee not in SECRET_SINKS:
                    continue
                for arg in expr.args:
                    if self._expr_touches_secret(arg, secret_fields, tainted):
                        self._finding(
                            report,
                            "SEC001",
                            f"secret value passed to '{callee}' — it will leak into "
                            "output/logs",
                            node=expr,
                            suggestion="call reveal(secret) only where disclosure is intended, "
                            "or remove the secret from the sink",
                            rule="secret_exposure",
                            source=source,
                            filename=filename,
                        )
                        break

    def _expr_touches_secret(
        self, expr: Optional[IRExpr], secret_fields: Set[str], tainted: Set[str]
    ) -> bool:
        if expr is None:
            return False
        for node in self._walk_expr(expr):
            if isinstance(node, IRMember) and node.name in secret_fields:
                return True
            if isinstance(node, IRName) and node.name in tainted:
                return True
            if isinstance(node, IRCall) and _callee_name(node) == "secret":
                return True
        return False

    # ------------------------------------------------------------------
    # SEC002 — unverified payment execution
    # ------------------------------------------------------------------
    def _check_payments(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        rule_names = {r.name for r in module.rules}
        for fn, owner in self._iter_functions(module):
            has_contract = bool(fn.contracts)
            for expr in self._walk_block(fn.body) if fn.body else ():
                if not isinstance(expr, IRCall):
                    continue
                callee = _callee_name(expr)
                if not callee or not _is_payment(callee):
                    continue
                # Guarded by a contract on the enclosing function?
                guarded = has_contract
                # Guarded by a rule that mentions the callee?
                if not guarded:
                    for rule in module.rules:
                        if callee in _rule_text(rule):
                            guarded = True
                            break
                # Guarded by a payments capability on the owning agent?
                if not guarded and owner:
                    agent = _find_agent(module, owner)
                    if agent is not None:
                        granted = _agent_actions(module, agent)
                        if "payments" in granted:
                            guarded = True
                if not guarded:
                    self._finding(
                        report,
                        "SEC002",
                        f"payment operation '{callee}' executes without a contract, "
                        "rule or capability guarding it",
                        node=expr,
                        suggestion="add a 'requires' contract, a rule, or grant the "
                        "'payments' capability to the enclosing agent",
                        rule="unverified_payment",
                        source=source,
                        filename=filename,
                    )

    # ------------------------------------------------------------------
    # SEC003 — permission escalation
    # ------------------------------------------------------------------
    def _check_escalation(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        cap_actions: Dict[str, Set[str]] = {
            c.name: {_normalise_action(g) for g in c.grants} for c in module.capabilities
        }
        perm_cannot: Dict[str, Set[str]] = {
            p.name: {_normalise_action(a) for a in p.cannot} for p in module.permissions
        }
        perm_can: Dict[str, Set[str]] = {
            p.name: {_normalise_action(a) for a in p.can} for p in module.permissions
        }

        for agent in module.agents:
            granted: Set[str] = set()
            for cname in agent.capabilities:
                granted |= cap_actions.get(cname, set())
            denied: Set[str] = set()
            allowed_by_perm: Set[str] = set()
            for pname in agent.permissions:
                denied |= perm_cannot.get(pname, set())
                allowed_by_perm |= perm_can.get(pname, set())

            # (a) a capability grants an action a permission explicitly forbids.
            for action in sorted(granted & denied):
                self._finding(
                    report,
                    "SEC003",
                    f"agent '{agent.name}' wields capability granting '{action}' "
                    "while a permission explicitly forbids it",
                    node=agent,
                    suggestion="remove the conflicting capability or relax the permission",
                    rule="permission_escalation",
                    source=source,
                    filename=filename,
                )

            # (b) a high-risk action is granted but no permission authorises it.
            for action in sorted(granted & HIGH_RISK_ACTIONS):
                if agent.permissions and action not in allowed_by_perm:
                    self._finding(
                        report,
                        "SEC003",
                        f"agent '{agent.name}' grants high-risk action '{action}' "
                        "not covered by any declared permission",
                        node=agent,
                        severity=Severity.WARNING,
                        suggestion=f"declare a permission that 'can {action}' or drop the grant",
                        rule="permission_escalation",
                        source=source,
                        filename=filename,
                    )

            # (c) an operation performed inside the agent is covered by no capability.
            for fn in agent.functions:
                for expr in self._walk_block(fn.body) if fn.body else ():
                    if not isinstance(expr, IRCall):
                        continue
                    callee = _callee_name(expr)
                    action = ENFORCEMENT_MAP.get(callee) if callee else None
                    if action is None:
                        continue
                    if _normalise_action(action) not in granted:
                        self._finding(
                            report,
                            "SEC003",
                            f"agent '{agent.name}' performs '{callee}' requiring "
                            f"'{action}' but no capability grants it",
                            node=expr,
                            suggestion=f"grant a capability that covers '{action}'",
                            rule="permission_escalation",
                            source=source,
                            filename=filename,
                        )

    # ------------------------------------------------------------------
    # SEC004 — unsafe IO
    # ------------------------------------------------------------------
    def _check_unsafe_io(
        self, module: IRModule, source: Optional[str], filename: Optional[str], report: SecurityReport
    ) -> None:
        rule_names = {r.name for r in module.rules}
        sanitized = any("sanitiz" in r.lower() for r in rule_names)
        for fn, owner in self._iter_functions(module):
            for expr in self._walk_block(fn.body) if fn.body else ():
                if not isinstance(expr, IRCall):
                    continue
                callee = _callee_name(expr)
                if callee not in UNSAFE_IO_OPS:
                    continue
                # (a) dynamic target: first argument is not a string literal.
                # A dynamic target is a *warning* by default (it is a risk, not
                # a proven defect); ``strict`` promotes it to a blocking error.
                if expr.args and not _is_literal_string(expr.args[0]):
                    self._finding(
                        report,
                        "SEC004",
                        f"'{callee}' called with a dynamic (non-literal) target — "
                        "path/URL injection risk",
                        node=expr,
                        severity=Severity.ERROR if self.strict else Severity.WARNING,
                        suggestion="validate the target against an allow-list before use",
                        rule="unsafe_io",
                        source=source,
                        filename=filename,
                    )
                # (b) write / network without an input-sanitisation rule.
                if callee in {"write_file", "append_file", "http_post"} and not sanitized:
                    self._finding(
                        report,
                        "SEC004",
                        f"'{callee}' performs a write/network call with no "
                        "input-sanitisation rule in scope",
                        node=expr,
                        severity=Severity.WARNING,
                        suggestion="add a 'sanitized_input' rule covering this operation",
                        rule="unsafe_io",
                        source=source,
                        filename=filename,
                    )
                # (c) absolute path literal outside the project.
                if callee in {"read_file", "write_file", "append_file"} and expr.args:
                    first = expr.args[0]
                    if isinstance(first, IRLiteral) and isinstance(first.value, str):
                        if first.value.startswith("/") and not first.value.startswith("/tmp"):
                            self._finding(
                                report,
                                "SEC004",
                                f"'{callee}' targets absolute path '{first.value}'",
                                node=expr,
                                severity=Severity.WARNING,
                                suggestion="use a path relative to the sandbox root",
                                rule="unsafe_io",
                                source=source,
                                filename=filename,
                            )

    # ------------------------------------------------------------------
    # Source-level fallback scan
    # ------------------------------------------------------------------
    #: SEC005 — an HTTP call whose URL is not a plain string literal (SSRF).
    _SSRF_RE = re.compile(
        r"\b(http_get|http_post|http_request|download|fetch|urlopen)\s*\(\s*[^\"']"
    )
    #: SEC006 — a file operation whose path contains a traversal segment.
    _TRAVERSAL_RE = re.compile(
        r"\b(read_file|write_file|append_file|open|remove_file|remove_dir|"
        r"copy_file|move_file|make_dir)\s*\([^)]*\"[^\"]*\.\.[^\"]*\""
    )
    #: SEC007 — deserialisation of untrusted data.
    _INSECURE_DESER_RE = re.compile(
        r"\b(pickle\.loads|pickle\.load|yaml\.load|marshal\.loads|"
        r"json_decode|parse_json|from_json)\s*\("
    )
    #: SEC008 — a weak/broken cryptographic primitive.
    _WEAK_CRYPTO_RE = re.compile(
        r"\b(md5|sha1|sha_1|des|rc4|ecb)\b", re.IGNORECASE
    )
    #: SEC009 — a shell command assembled from non-literal parts.
    _CMD_INJECTION_RE = re.compile(
        r"\b(exec|system|shell|subprocess|process\.run|run_command)\s*\("
        r"[^)]*(\+|\{[^}]*\}|format)"
    )
    #: SEC010 — a literal assigned to a secret-looking name.
    _HARDCODED_SECRET_RE = re.compile(
        r"\b(?:let|var|const)\s+(\w*(?:password|passwd|secret|token|api_key|"
        r"apikey|private_key|access_key)\w*)\s*(?::[^=]+)?=\s*[\"']([^\"']{6,})[\"']",
        re.IGNORECASE,
    )

    #: Placeholder values that are not real secrets (avoid false positives).
    _PLACEHOLDER_SECRET_VALUES = {
        "changeme",
        "example",
        "placeholder",
        "your-api-key",
        "xxx",
        "todo",
    }

    def _scan_source_extended(
        self, source: str, filename: Optional[str], report: SecurityReport
    ) -> None:
        """Scan for SSRF, traversal, unsafe deserialisation, weak crypto,
        command injection and hardcoded secrets."""
        covered = {
            (f.code, f.location.line)
            for f in report.findings
            if f.location is not None
        }
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            def add(code, message, sev, suggestion, rule):
                if (code, lineno) in covered:
                    return
                report.findings.append(
                    SecurityFinding(
                        code=code,
                        message=message,
                        severity=sev,
                        location=SourceLocation(line=lineno, column=1),
                        suggestion=suggestion,
                        rule=rule,
                        filename=filename,
                        source=source,
                    )
                )
                covered.add((code, lineno))

            if self._SSRF_RE.search(line):
                add(
                    "SEC005",
                    "HTTP request with a non-literal URL (server-side request "
                    "forgery risk)",
                    Severity.WARNING,
                    "validate/allow-list outbound hosts before requesting",
                    "ssrf",
                )
            if self._TRAVERSAL_RE.search(line):
                add(
                    "SEC006",
                    "file path contains '..' (directory traversal risk)",
                    Severity.ERROR,
                    "resolve and confine paths to the sandbox root",
                    "path_traversal",
                )
            if self._INSECURE_DESER_RE.search(line):
                add(
                    "SEC007",
                    "deserialising untrusted data is unsafe",
                    Severity.WARNING,
                    "validate the payload schema before decoding",
                    "insecure_deserialization",
                )
            if self._WEAK_CRYPTO_RE.search(line):
                add(
                    "SEC008",
                    "weak cryptographic primitive (md5/sha1/des/rc4/ecb)",
                    Severity.WARNING,
                    "use a modern primitive (SHA-256+, AES-GCM, ChaCha20)",
                    "weak_crypto",
                )
            if self._CMD_INJECTION_RE.search(line):
                add(
                    "SEC009",
                    "shell command built from non-literal parts (command injection)",
                    Severity.ERROR,
                    "pass an argv list and never interpolate into a shell string",
                    "command_injection",
                )
            m = self._HARDCODED_SECRET_RE.search(line)
            if m:
                value = m.group(2).strip().lower()
                if value not in self._PLACEHOLDER_SECRET_VALUES:
                    add(
                        "SEC010",
                        f"hardcoded secret in declaration '{m.group(1)}'",
                        Severity.ERROR,
                        "read the value from the environment at runtime",
                        "hardcoded_secret",
                    )

    _SECRET_PRINT_RE = re.compile(
        r"\b(print|println|eprint|log)\s*\([^)]*\b(secret|pin|password|token|api_key)\b",
        re.IGNORECASE,
    )
    _EVAL_RE = re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE)

    def _scan_source(
        self, source: str, filename: Optional[str], report: SecurityReport
    ) -> None:
        """A conservative textual scan for patterns the IR may not surface."""
        # Lines already reported by the IR passes (avoid duplicate findings).
        covered = {
            (f.code, f.location.line)
            for f in report.findings
            if f.location is not None
        }
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if self._SECRET_PRINT_RE.search(line) and ("SEC001", lineno) not in covered:
                report.findings.append(
                    SecurityFinding(
                        code="SEC001",
                        message="possible secret value printed/logged",
                        severity=Severity.WARNING,
                        location=SourceLocation(line=lineno, column=1),
                        suggestion="never log secrets; use reveal() only where intended",
                        rule="secret_exposure",
                        filename=filename,
                        source=source,
                    )
                )
            if self._EVAL_RE.search(line):
                report.findings.append(
                    SecurityFinding(
                        code="SEC004",
                        message="use of eval/exec is unsafe for AI-generated code",
                        severity=Severity.ERROR,
                        location=SourceLocation(line=lineno, column=1),
                        suggestion="replace eval/exec with an explicit, validated dispatch",
                        rule="unsafe_io",
                        filename=filename,
                        source=source,
                    )
                )


# ---------------------------------------------------------------------------
# IR helpers
# ---------------------------------------------------------------------------
def _callee_name(call: IRCall) -> Optional[str]:
    callee = call.callee
    if isinstance(callee, IRName):
        return callee.name
    if isinstance(callee, IRMember):
        return callee.name
    return None


def _is_literal_string(expr: Optional[IRExpr]) -> bool:
    return isinstance(expr, IRLiteral) and isinstance(expr.value, str)


def _is_payment(name: str) -> bool:
    low = name.lower()
    return any(pat in low for pat in PAYMENT_PATTERNS)


def _rule_text(rule: Any) -> str:
    parts: List[str] = [getattr(rule, "name", "") or ""]
    cond = getattr(rule, "condition", None)
    if cond is not None:
        for node in _walk_any(cond):
            name = getattr(node, "name", None)
            if isinstance(name, str):
                parts.append(name)
    return " ".join(parts)


def _walk_any(node: Any) -> Iterable[Any]:
    if node is None:
        return
    yield node
    children = getattr(node, "children", None)
    if callable(children):
        for child in children():
            yield from _walk_any(child)


def _functions_in_block(block: Optional[IRBlock]) -> List[IRFunction]:
    """Return any functions nested in a block (rare, but supported)."""
    out: List[IRFunction] = []
    if block is None:
        return out
    for stmt in block.statements:
        if isinstance(stmt, IRFunction):
            out.append(stmt)
    return out


def _find_agent(module: IRModule, name: str) -> Optional[IRAgent]:
    for agent in module.agents:
        if agent.name == name:
            return agent
    return None


def _agent_actions(module: IRModule, agent: IRAgent) -> Set[str]:
    cap_actions = {
        c.name: {_normalise_action(g) for g in c.grants} for c in module.capabilities
    }
    out: Set[str] = set()
    for cname in agent.capabilities:
        out |= cap_actions.get(cname, set())
    return out


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def analyze_security(
    source_or_module: Any,
    filename: Optional[str] = None,
    strict: bool = True,
) -> SecurityReport:
    """One-call security analysis (see :class:`SecurityAnalyzer`)."""
    return SecurityAnalyzer(strict=strict).analyze(source_or_module, filename=filename)


def aggregate_reports(
    reports: Iterable[SecurityReport], filename: Optional[str] = None
) -> SecurityReport:
    """Merge several :class:`SecurityReport` objects into one.

    Findings keep their own locations and filenames; the merged report's
    :meth:`SecurityReport.sorted` interleaves them by location.
    """
    merged = SecurityReport(filename=filename)
    for report in reports:
        for finding in report.findings:
            if finding.filename is None:
                finding.filename = report.filename
            merged.findings.append(finding)
    return merged


def audit_project(
    entry_path: str,
    search_paths: Optional[Iterable[str]] = None,
    strict: bool = True,
) -> SecurityReport:
    """Run the security analyzer across every file of a Happy project."""
    from ..compiler.modules import ModuleLoader

    loader = ModuleLoader(search_paths=list(search_paths or []))
    project = loader.load_project(entry_path)
    analyzer = SecurityAnalyzer(strict=strict)
    reports = []
    for module in project.modules:
        try:
            with open(module.path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:  # pragma: no cover - defensive
            continue
        reports.append(analyzer.analyze(text, filename=module.path))
    return aggregate_reports(reports, filename=entry_path)


__all__ = [
    "Severity",
    "SecurityFinding",
    "SecurityReport",
    "SecurityAnalyzer",
    "analyze_security",
    "aggregate_reports",
    "audit_project",
]
