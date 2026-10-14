"""Rule verification and capability enforcement for the Happy language.

Happy makes **security posture** part of the type system.  Two mechanisms carry
the weight:

* **Rules** — named, checkable policies such as ``must_never_be_exposed`` or
  ``authentication_required``.  Some rule names are *built-in*: the verifier
  knows their meaning and can sanity-check their shape (arity, Bool-typed
  condition) and, where possible, whether the code appears to satisfy them.
  Other names are user-defined policies and are simply recorded.

* **Capabilities** — grantable authority tokens (``capability DatabaseRead``,
  ``capability PaymentAccess``).  An ``agent`` declares the permissions and
  capabilities it wields, and every *sensitive operation* performed inside that
  agent's methods must be covered by one of the agent's capabilities.  This
  module builds the **enforcement map**: which capability authorises which
  action, and which enforcement points in the code are (un)covered.

The verifier never invents results: it reports exactly what it can see in the
typed :mod:`happy.compiler.ir`, with precise line/column diagnostics.

Entry point::

    from happy.compiler import parse, analyze, lower
    from happy.compiler.permissions import PermissionEngine

    module = lower(analyze(parse(source)))
    report = PermissionEngine(source=source, filename="demo.hpy").verify(module)
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
    IRAssign,
    IRAi,
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
    IRMember,
    IRModule,
    IRPermission,
    IRCapability,
    IRReturn,
    IRRule,
    IRStmt,
    IRWhile,
)

__all__ = [
    "RuleKind",
    "KNOWN_RULES",
    "ENFORCEMENT_MAP",
    "CAPABILITY_ACTIONS",
    "RuleCheck",
    "PermissionInfo",
    "CapabilityInfo",
    "EnforcementPoint",
    "PermissionReport",
    "PermissionOptions",
    "PermissionEngine",
    "verify_permissions",
    "check_permissions",
    # codes
    "CODE_PERMISSION_OVERLAP",
    "CODE_CAPABILITY_CONFLICT",
    "CODE_UNENFORCED_CAPABILITY",
    "CODE_EMPTY_CAPABILITY",
    "CODE_EMPTY_PERMISSION",
    "CODE_UNKNOWN_ATTRIBUTION",
    "W_UNKNOWN_RULE",
    "W_RULE_NO_PREDICATE",
    "W_RULE_BAD_ARITY",
    "W_UNUSED_CAPABILITY",
    "N_ENFORCED",
]


# ---------------------------------------------------------------------------
# Diagnostic codes (Step 3 uses the 6xxx band)
# ---------------------------------------------------------------------------
CODE_PERMISSION_OVERLAP = "E6001"
CODE_CAPABILITY_CONFLICT = "E6002"
CODE_UNENFORCED_CAPABILITY = "E6003"
CODE_EMPTY_CAPABILITY = "E6004"
CODE_EMPTY_PERMISSION = "E6005"
CODE_DUPLICATE_CAPABILITY = "E6006"
CODE_DUPLICATE_PERMISSION = "E6007"
CODE_UNKNOWN_ATTRIBUTION = "E6008"

W_UNKNOWN_RULE = "W6011"
W_RULE_NO_PREDICATE = "W6012"
W_RULE_BAD_ARITY = "W6013"
W_RULE_NOT_BOOL = "W6014"
W_UNUSED_CAPABILITY = "W6015"
W_UNCOVERED_ACTION = "W6016"

N_ENFORCED = "N6001"


# ---------------------------------------------------------------------------
# Rule catalog
# ---------------------------------------------------------------------------
class RuleKind:
    """Canonical rule names the verifier understands."""

    MUST_NEVER_BE_EXPOSED = "must_never_be_exposed"
    AUTHENTICATION_REQUIRED = "authentication_required"
    AUTHORIZATION_REQUIRED = "authorization_required"
    READ_ONLY = "read_only"
    WRITE_ONLY = "write_only"
    OWNER_ONLY = "owner_only"
    AUDIT_REQUIRED = "audit_required"
    RATE_LIMITED = "rate_limited"
    SANITIZED_INPUT = "sanitized_input"
    ENCRYPTED_AT_REST = "encrypted_at_rest"
    NO_PII_LEAK = "no_pii_leak"
    CUSTOM = "custom"


#: ``name -> (kind, minimum arity, description)`` for the built-in rules.
KNOWN_RULES: Dict[str, Tuple[str, int, str]] = {
    RuleKind.MUST_NEVER_BE_EXPOSED: (
        RuleKind.MUST_NEVER_BE_EXPOSED, 1,
        "requires a Bool predicate such as 'secret == false' or 'field != null'",
    ),
    RuleKind.AUTHENTICATION_REQUIRED: (
        RuleKind.AUTHENTICATION_REQUIRED, 1,
        "requires a Bool 'authenticated' / 'session' predicate",
    ),
    RuleKind.AUTHORIZATION_REQUIRED: (
        RuleKind.AUTHORIZATION_REQUIRED, 1,
        "requires a Bool predicate over the caller's role / permission",
    ),
    RuleKind.READ_ONLY: (
        RuleKind.READ_ONLY, 1, "requires a Bool predicate that no write occurs",
    ),
    RuleKind.WRITE_ONLY: (
        RuleKind.WRITE_ONLY, 1, "requires a Bool predicate that no read occurs",
    ),
    RuleKind.OWNER_ONLY: (
        RuleKind.OWNER_ONLY, 1, "requires a Bool 'owner == caller' predicate",
    ),
    RuleKind.AUDIT_REQUIRED: (
        RuleKind.AUDIT_REQUIRED, 1, "requires a Bool predicate that auditing runs",
    ),
    RuleKind.RATE_LIMITED: (
        RuleKind.RATE_LIMITED, 1, "requires a Bool predicate over the rate budget",
    ),
    RuleKind.SANITIZED_INPUT: (
        RuleKind.SANITIZED_INPUT, 1, "requires a Bool predicate that input is clean",
    ),
    RuleKind.ENCRYPTED_AT_REST: (
        RuleKind.ENCRYPTED_AT_REST, 1, "requires a Bool predicate over encryption",
    ),
    RuleKind.NO_PII_LEAK: (
        RuleKind.NO_PII_LEAK, 1, "requires a Bool predicate that no PII escapes",
    ),
}


# ---------------------------------------------------------------------------
# Enforcement model
# ---------------------------------------------------------------------------
#: Which abstract action a builtin / sensitive operation requires.
#: ``None`` marks a *pure* builtin that needs no capability.
ENFORCEMENT_MAP: Dict[str, Optional[str]] = {
    "read_file": "file_read",
    "write_file": "file_write",
    "append_file": "file_write",
    "file_exists": "file_read",
    "http_get": "net",
    "http_post": "net",
    "http_request": "net",
    "download": "net",
    "tcp_connect": "net",
    "tcp_send": "net",
    # std.fs operations
    "list_dir": "file_read",
    "make_dir": "file_write",
    "remove_file": "file_write",
    "remove_dir": "file_write",
    "copy_file": "file_write",
    "move_file": "file_write",
    "exists": "file_read",
    "is_dir": "file_read",
    "is_file": "file_read",
    "size": "file_read",
    # std.process operations
    "process": "process",
    "exec": "process",
    "run": "process",
    "spawn_process": "process",
    "shell": "process",
    # std.env operations
    "env": "env",
    "getenv": "env",
    "setenv": "env",
    "get": "env",
    "get_or": "env",
    "has": "env",
    "set_var": "env",
    "unset": "env",
    "all_vars": "env",
    # free / pure operations
    "json_parse": None,
    "print": None,
    "println": None,
    "len": None,
    "str": None,
    "int": None,
    "float": None,
    "now": None,
    "rand": None,
}

#: Actions that only make sense *inside* an agent scope.  Performed outside
#: any agent (a plain script or an ``app`` body) they are denied at runtime and
#: reported by the security analyzer — this is the "capability bypass" the
#: independent review flagged.  Host-service actions (``env``, ``ai``, ``random``,
#: ``time`` …) are deliberately *not* here: they do not touch the host's
#: filesystem, network or process table, so they remain available outside agents.
AGENT_REQUIRED_ACTIONS: Set[str] = {
    "file_read",
    "file_write",
    "net",
    "process",
    "env",
    "database_read",
    "database_write",
    "admin",
}


#: Aliases so that a capability granted as e.g. ``db_read`` matches ``database_read``.
CAPABILITY_ACTIONS: Dict[str, str] = {
    "db_read": "database_read",
    "db_write": "database_write",
    "read_db": "database_read",
    "write_db": "database_write",
    "network": "net",
    "http": "net",
    "file_read": "file_read",
    "file_write": "file_write",
    "fileread": "file_read",
    "filewrite": "file_write",
    "payment": "payments",
    "payments": "payments",
    "pay": "payments",
    "secrets": "secrets",
    "secret": "secrets",
    "ai": "ai",
    "model": "ai",
    "env": "env",
    "environment": "env",
    "getenv": "env",
    "setenv": "env",
}


def _normalise_action(name: str) -> str:
    key = name.strip().lower()
    return CAPABILITY_ACTIONS.get(key, key)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class RuleCheck:
    """A verified ``rule`` declaration."""

    name: str
    kind: str
    params: Tuple[str, ...] = ()
    is_known: bool = False
    arity_ok: bool = True
    has_predicate: bool = False
    predicate_is_bool: Optional[bool] = None
    loc: Optional[SourceLocation] = None
    description: str = ""

    @property
    def satisfied_hint(self) -> Optional[bool]:
        """A conservative hint (``None`` when undecidable statically)."""
        if not self.has_predicate:
            return False
        if self.predicate_is_bool is False:
            return False
        return None


@dataclass
class PermissionInfo:
    """A verified ``permission`` declaration."""

    name: str
    can: Tuple[str, ...] = ()
    cannot: Tuple[str, ...] = ()
    holders: Tuple[str, ...] = ()
    loc: Optional[SourceLocation] = None

    @property
    def conflicts(self) -> Tuple[str, ...]:
        return tuple(sorted(set(self.can) & set(self.cannot)))


@dataclass
class CapabilityInfo:
    """A verified ``capability`` declaration."""

    name: str
    grants: Tuple[str, ...] = ()
    holders: Tuple[str, ...] = ()
    loc: Optional[SourceLocation] = None

    @property
    def actions(self) -> Tuple[str, ...]:
        return tuple(_normalise_action(g) for g in self.grants)


@dataclass
class EnforcementPoint:
    """A place where a sensitive operation must be authorised."""

    agent: Optional[str]
    function: str
    operation: str
    action: Optional[str]
    loc: Optional[SourceLocation] = None
    enforced: bool = False
    covering_capability: Optional[str] = None
    reason: str = ""


@dataclass
class PermissionOptions:
    """Tunable behaviour of the permission engine."""

    #: Verify built-in rule shape (arity, Bool predicate).
    verify_rules: bool = True
    #: Require every sensitive operation in an *agent* method to be covered.
    enforce_capabilities: bool = True
    #: Report capabilities that no agent holds.
    report_unused_capabilities: bool = True
    #: Emit informational notes for satisfied enforcement points.
    note_enforced: bool = True
    #: Emit a note when a sensitive operation appears outside any agent
    #: (governed by effects rather than capabilities).
    note_unattributed: bool = False


@dataclass
class PermissionReport:
    """The outcome of a permission/capability verification run."""

    module_name: Optional[str] = None
    permissions: List[PermissionInfo] = field(default_factory=list)
    capabilities: List[CapabilityInfo] = field(default_factory=list)
    rules: List[RuleCheck] = field(default_factory=list)
    enforcement_points: List[EnforcementPoint] = field(default_factory=list)
    diagnostics: List["PermissionDiagnostic"] = field(default_factory=list)

    # -- queries --------------------------------------------------------
    @property
    def errors(self):
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self):
        return [d for d in self.diagnostics if d.severity == "warning"]

    @property
    def notes(self):
        return [d for d in self.diagnostics if d.severity == "note"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def enforced(self) -> List[EnforcementPoint]:
        return [p for p in self.enforcement_points if p.enforced]

    @property
    def unenforced(self) -> List[EnforcementPoint]:
        return [p for p in self.enforcement_points if not p.enforced]

    def rule(self, name: str) -> Optional[RuleCheck]:
        for r in self.rules:
            if r.name == name:
                return r
        return None

    def capability(self, name: str) -> Optional[CapabilityInfo]:
        for c in self.capabilities:
            if c.name == name:
                return c
        return None

    def permission(self, name: str) -> Optional[PermissionInfo]:
        for p in self.permissions:
            if p.name == name:
                return p
        return None

    def summary(self) -> str:
        return (
            f"{len(self.permissions)} permission(s), "
            f"{len(self.capabilities)} capability(ies), "
            f"{len(self.rules)} rule(s), "
            f"{len(self.enforcement_points)} enforcement point(s) "
            f"({len(self.enforced)} covered / {len(self.unenforced)} uncovered), "
            f"{len(self.errors)} error(s), {len(self.warnings)} warning(s), "
            f"{len(self.notes)} note(s)"
        )

    def sorted(self):
        return sorted(self.diagnostics, key=lambda d: (d.line, d.column, d.code))

    def format(self) -> str:
        if not self.diagnostics:
            return "(no permission diagnostics)"
        return "\n\n".join(d.render() for d in self.sorted())


@dataclass
class PermissionDiagnostic:
    """A single permission/capability diagnostic."""

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


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class PermissionEngine:
    """Verifies rules, permissions and capability enforcement over IR."""

    def __init__(
        self,
        source: Optional[str] = None,
        filename: Optional[str] = None,
        options: Optional[PermissionOptions] = None,
    ) -> None:
        self.source = source
        self.filename = filename
        self.options = options or PermissionOptions()
        self.diagnostics: List[PermissionDiagnostic] = []

    # -- diagnostics ----------------------------------------------------
    def _emit(self, code, message, loc, suggestion=None, severity="error"):
        self.diagnostics.append(
            PermissionDiagnostic(
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
    def verify(self, module: IRModule) -> PermissionReport:
        perms = self._collect_permissions(module)
        caps = self._collect_capabilities(module)
        cap_by_name = {c.name: c for c in caps}

        # usage: which agents hold which capability/permission
        cap_holders: Dict[str, List[str]] = {c.name: [] for c in caps}
        perm_holders: Dict[str, List[str]] = {p.name: [] for p in perms}
        for agent in module.agents:
            for cname in agent.capabilities:
                if cname in cap_holders:
                    cap_holders[cname].append(agent.name)
                else:
                    self._emit(
                        CODE_UNKNOWN_ATTRIBUTION,
                        f"agent '{agent.name}' declares unknown capability "
                        f"'{cname}'",
                        agent.loc,
                        "declare it with 'capability <name> { grants ... }'",
                    )
            for pname in agent.permissions:
                if pname in perm_holders:
                    perm_holders[pname].append(agent.name)
                else:
                    self._emit(
                        CODE_UNKNOWN_ATTRIBUTION,
                        f"agent '{agent.name}' declares unknown permission "
                        f"'{pname}'",
                        agent.loc,
                        "declare it with 'permission <name> { can ... cannot ... }'",
                    )

        # attach holders
        for p in perms:
            p.holders = tuple(sorted(set(perm_holders.get(p.name, []))))
        for c in caps:
            c.holders = tuple(sorted(set(cap_holders.get(c.name, []))))

        # rule verification
        rules = self._verify_rules(module)

        # enforcement points
        points: List[EnforcementPoint] = []
        if self.options.enforce_capabilities:
            points = self._collect_enforcement_points(module, cap_by_name)

        # cross checks
        self._check_agent_capability_conflicts(module, perms, caps)
        if self.options.report_unused_capabilities:
            self._report_unused_capabilities(caps)
        for p in perms:
            if not p.can and not p.cannot:
                self._emit(
                    CODE_EMPTY_PERMISSION,
                    f"permission '{p.name}' grants and denies nothing",
                    p.loc,
                    "add 'can <action>' / 'cannot <action>' entries",
                )
            for action in p.conflicts:
                self._emit(
                    CODE_PERMISSION_OVERLAP,
                    f"permission '{p.name}' both permits and denies '{action}'",
                    p.loc,
                    "an action cannot be simultaneously allowed and denied; "
                    "remove it from one side",
                )

        # enforcement reporting
        for point in points:
            if point.enforced:
                if self.options.note_enforced:
                    self._emit(
                        N_ENFORCED,
                        f"'{point.operation}' in '{point.function}' is covered by "
                        f"capability '{point.covering_capability}'",
                        point.loc,
                        severity="note",
                    )
            else:
                if point.agent is None:
                    if self.options.note_unattributed:
                        self._emit(
                            W_UNCOVERED_ACTION,
                            f"'{point.operation}' in '{point.function}' performs a "
                            "sensitive action outside any agent "
                            "(governed by effects, not capabilities)",
                            point.loc,
                            "move it into a capability-scoped agent, or "
                            "declare the required effect",
                            severity="note",
                        )
                else:
                    self._emit(
                        CODE_UNENFORCED_CAPABILITY,
                        f"'{point.operation}' in agent '{point.agent}' method "
                        f"'{point.function}' requires capability "
                        f"'{point.action}' which the agent does not hold",
                        point.loc,
                        f"add 'capability [<Name>]' granting '{point.action}' "
                        "to the agent, or remove the operation",
                    )

        return PermissionReport(
            module_name=module.name,
            permissions=perms,
            capabilities=caps,
            rules=rules,
            enforcement_points=points,
            diagnostics=sorted(
                self.diagnostics, key=lambda d: (d.line, d.column, d.code)
            ),
        )

    # -- collection -----------------------------------------------------
    def _collect_permissions(self, module: IRModule) -> List[PermissionInfo]:
        seen: Set[str] = set()
        out: List[PermissionInfo] = []
        for decl in module.permissions:
            if decl.name in seen:
                self._emit(
                    CODE_DUPLICATE_PERMISSION,
                    f"duplicate permission '{decl.name}'",
                    decl.loc,
                    "remove or rename one of the declarations",
                )
                continue
            seen.add(decl.name)
            out.append(
                PermissionInfo(
                    name=decl.name,
                    can=tuple(decl.can),
                    cannot=tuple(decl.cannot),
                    loc=decl.loc,
                )
            )
        return out

    def _collect_capabilities(self, module: IRModule) -> List[CapabilityInfo]:
        seen: Set[str] = set()
        out: List[CapabilityInfo] = []
        for decl in module.capabilities:
            if decl.name in seen:
                self._emit(
                    CODE_DUPLICATE_CAPABILITY,
                    f"duplicate capability '{decl.name}'",
                    decl.loc,
                    "remove or rename one of the declarations",
                )
                continue
            seen.add(decl.name)
            if not decl.grants:
                self._emit(
                    CODE_EMPTY_CAPABILITY,
                    f"capability '{decl.name}' grants nothing",
                    decl.loc,
                    "add 'grants <action>' entries, or remove the capability",
                )
            out.append(
                CapabilityInfo(
                    name=decl.name,
                    grants=tuple(decl.grants),
                    loc=decl.loc,
                )
            )
        return out

    # -- rules ----------------------------------------------------------
    def _verify_rules(self, module: IRModule) -> List[RuleCheck]:
        out: List[RuleCheck] = []
        for rule in module.rules:
            out.append(self._verify_rule(rule))
        return out

    def _verify_rule(self, rule: IRRule) -> RuleCheck:
        name = rule.name
        known = KNOWN_RULES.get(name)
        check = RuleCheck(
            name=name,
            kind=known[0] if known else RuleKind.CUSTOM,
            params=tuple(p.name for p in rule.params),
            is_known=known is not None,
            has_predicate=rule.condition is not None or rule.body is not None,
            loc=rule.loc,
            description=known[2] if known else "user-defined policy",
        )

        if known is not None and self.options.verify_rules:
            min_arity = known[1]
            if len(rule.params) < min_arity:
                check.arity_ok = False
                self._emit(
                    W_RULE_BAD_ARITY,
                    f"rule '{name}' expects at least {min_arity} parameter(s), "
                    f"got {len(rule.params)}",
                    rule.loc,
                    f"built-in rule '{name}': {known[2]}",
                    severity="warning",
                )
        elif known is None:
            self._emit(
                W_UNKNOWN_RULE,
                f"rule '{name}' is not a built-in policy; recorded as custom",
                rule.loc,
                "built-in rules include: "
                + ", ".join(sorted(KNOWN_RULES)[:5])
                + ", …",
                severity="note",
            )

        if rule.condition is None and rule.body is None:
            self._emit(
                W_RULE_NO_PREDICATE,
                f"rule '{name}' has neither a condition nor a body",
                rule.loc,
                "declare a predicate, e.g. 'rule "
                f"{name}(x: Int): x >= 0'",
                severity="warning",
            )
            check.predicate_is_bool = False
        elif rule.condition is not None:
            # Reuse the contract predicate classifier (syntactic).
            from .contracts import _predicate_is_bool

            check.predicate_is_bool = _predicate_is_bool(rule.condition)
            if check.predicate_is_bool is False:
                self._emit(
                    W_RULE_NOT_BOOL,
                    f"rule '{name}' predicate is not Bool",
                    rule.condition.loc or rule.loc,
                    "rules must state a Bool condition",
                    severity="warning",
                )
        return check

    # -- enforcement ----------------------------------------------------
    def _collect_enforcement_points(
        self,
        module: IRModule,
        cap_by_name: Dict[str, CapabilityInfo],
    ) -> List[EnforcementPoint]:
        points: List[EnforcementPoint] = []

        def point_for(
            agent: Optional[IRAgent],
            fn: IRFunction,
            operation: str,
            loc: Optional[SourceLocation],
        ) -> EnforcementPoint:
            action = ENFORCEMENT_MAP.get(operation)
            p = EnforcementPoint(
                agent=agent.name if agent else None,
                function=fn.name,
                operation=operation,
                action=action,
                loc=loc,
            )
            if action is None:
                p.enforced = True
                p.reason = "pure operation (no capability required)"
                return p
            if agent is None:
                p.enforced = False
                p.reason = "sensitive operation outside any agent"
                return p
            for cname in agent.capabilities:
                cap = cap_by_name.get(cname)
                if cap is None:
                    continue
                if action in cap.actions:
                    p.enforced = True
                    p.covering_capability = cname
                    p.reason = f"covered by capability '{cname}'"
                    return p
            p.enforced = False
            p.reason = f"no held capability grants '{action}'"
            return p

        # agent methods
        for agent in module.agents:
            for fn in agent.functions:
                for operation, loc in _sensitive_calls_in_block(fn.body):
                    points.append(point_for(agent, fn, operation, loc))
        return points

    def _check_agent_capability_conflicts(
        self,
        module: IRModule,
        perms: List[PermissionInfo],
        caps: List[CapabilityInfo],
    ) -> None:
        perm_by_name = {p.name: p for p in perms}
        cap_by_name = {c.name: c for c in caps}
        for agent in module.agents:
            denied: Set[str] = set()
            for pname in agent.permissions:
                perm = perm_by_name.get(pname)
                if perm is not None:
                    denied.update(_normalise_action(a) for a in perm.cannot)
            for cname in agent.capabilities:
                cap = cap_by_name.get(cname)
                if cap is None:
                    continue
                for action in cap.actions:
                    if action in denied:
                        self._emit(
                            CODE_CAPABILITY_CONFLICT,
                            f"agent '{agent.name}' holds capability '{cname}' "
                            f"granting '{action}', but its permission(s) deny it",
                            agent.loc,
                            "remove the capability, or drop the 'cannot "
                            f"{action}' rule from the agent's permissions",
                        )

    def _report_unused_capabilities(self, caps: List[CapabilityInfo]) -> None:
        for cap in caps:
            if not cap.holders:
                self._emit(
                    W_UNUSED_CAPABILITY,
                    f"capability '{cap.name}' is declared but no agent holds it",
                    cap.loc,
                    "remove it, or grant it to an agent with "
                    "'capability [<Name>]'",
                    severity="warning",
                )


# ---------------------------------------------------------------------------
# Statement walking helpers
# ---------------------------------------------------------------------------
def _sensitive_calls_in_block(
    block: Optional[IRBlock],
) -> List[Tuple[str, Optional[SourceLocation]]]:
    """Return ``(operation, loc)`` for every call found in ``block``."""
    if block is None:
        return []
    out: List[Tuple[str, Optional[SourceLocation]]] = []
    _walk_stmts(block.statements, out)
    return out


def _walk_stmts(
    stmts: Sequence[IRStmt], out: List[Tuple[str, Optional[SourceLocation]]]
) -> None:
    for stmt in stmts:
        if isinstance(stmt, IRLet):
            _walk_expr(stmt.value, out)
        elif isinstance(stmt, IRAssign):
            _walk_expr(stmt.target, out)
            _walk_expr(stmt.value, out)
        elif isinstance(stmt, IRExprStmt):
            _walk_expr(stmt.expr, out)
        elif isinstance(stmt, IRIf):
            _walk_expr(stmt.condition, out)
            if stmt.then_branch is not None:
                _walk_stmts(stmt.then_branch.statements, out)
            if isinstance(stmt.else_branch, IRBlock):
                _walk_stmts(stmt.else_branch.statements, out)
            elif isinstance(stmt.else_branch, IRIf):
                _walk_stmts([stmt.else_branch], out)
        elif isinstance(stmt, IRWhile):
            _walk_expr(stmt.condition, out)
            if stmt.body is not None:
                _walk_stmts(stmt.body.statements, out)
        elif isinstance(stmt, IRFor):
            _walk_expr(stmt.iterable, out)
            if stmt.body is not None:
                _walk_stmts(stmt.body.statements, out)
        elif isinstance(stmt, IRReturn):
            _walk_expr(stmt.value, out)
        elif isinstance(stmt, (IRBreak, IRContinue)):
            continue
        elif isinstance(stmt, IRFunction):
            continue  # nested functions handled separately


def _walk_expr(
    expr: Optional[IRExpr], out: List[Tuple[str, Optional[SourceLocation]]]
) -> None:
    if expr is None:
        return
    if isinstance(expr, IRAwait):
        _walk_expr(expr.operand, out)
        return
    if isinstance(expr, IRCall):
        name = _callee_name(expr)
        if name is not None and name in ENFORCEMENT_MAP:
            out.append((name, expr.loc))
        for arg in expr.args:
            _walk_expr(arg, out)
        if expr.callee is not None:
            _walk_expr(expr.callee, out)
        return
    for child in expr.children():
        _walk_expr(child, out)


def _callee_name(call: IRCall) -> Optional[str]:
    callee = call.callee
    if callee is None:
        return None
    if type(callee).__name__ == "IRName":
        return getattr(callee, "name", None)
    if isinstance(callee, IRMember):
        return callee.name
    return None


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def verify_permissions(
    source_or_module,
    filename: Optional[str] = None,
    options: Optional[PermissionOptions] = None,
    source: Optional[str] = None,
) -> PermissionReport:
    """Verify rules / permissions / capabilities of a module or raw source."""
    module = _as_module(source_or_module, filename)
    src = source if source is not None else (
        source_or_module if isinstance(source_or_module, str) else None
    )
    return PermissionEngine(
        source=src, filename=filename, options=options
    ).verify(module)


#: Alias matching the module name used in the task description.
check_permissions = verify_permissions


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
    # AnalysisResult
    return lower(source_or_module)
