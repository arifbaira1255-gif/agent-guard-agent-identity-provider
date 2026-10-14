"""Happy IR — an explicit, typed Intermediate Representation.

This module lowers the :mod:`happy.compiler.ast` produced by the parser and the
:mod:`happy.compiler.types` produced by the semantic analyzer into a clean,
explicit **Happy IR** that later stages (contracts, permissions, effects, and
ultimately code generation) consume.

Design goals
------------
* **Explicit** — every value carries its ``Type``, every call site lists its
  target and arguments, every declaration becomes a node with a stable ID.
* **Deterministic** — node IDs are assigned by a pre-order traversal seeded at
  ``0`` and advanced monotonically.  Lowering never depends on dictionary
  ordering or hashing: identical input always yields a byte-for-byte identical
  IR (see :meth:`IRModule.fingerprint`).
* **Faithful** — side-effects, contracts, rules, permissions, capabilities and
  AI extensions are represented as first-class IR nodes rather than bolted on.

The entry point is :func:`lower`::

    from happy.compiler import parse, analyze, lower

    program = parse(source)
    analysis = analyze(program)
    module = lower(analysis)          # -> IRModule
    print(module.fingerprint())

Node IDs
--------
Every :class:`IRNode` exposes :attr:`IRNode.id` (an ``"n12"`` string) and
:attr:`IRNode.loc`.  The :class:`IRBuilder` allocates them in a deterministic
pre-order walk; a fresh builder is used for every :func:`lower` call so repeated
lowering of the same program is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import ast
from .errors import SourceLocation
from .types import (
    ANY,
    NEVER,
    UNIT,
    UNKNOWN,
    FunctionType,
    Type,
    apply_substitution,
    Substitution,
)

__all__ = [
    "IRNode",
    "IRModule",
    "IRImport",
    "IRTypeDecl",
    "IRField",
    "IREnumDecl",
    "IRVariant",
    "IRFunction",
    "IRParam",
    "IRRule",
    "IRPermission",
    "IRCapability",
    "IRAgent",
    "IRAi",
    "IRApp",
    "IRTrait",
    "IRTraitMethod",
    "IRImpl",
    "IRConst",
    "IRMatch",
    "IRMatchArm",
    "IRPattern",
    "IRBlock",
    "IRAssert",
    "IRStmt",
    "IRLet",
    "IRAssign",
    "IRExprStmt",
    "IRIf",
    "IRWhile",
    "IRFor",
    "IRReturn",
    "IRBreak",
    "IRContinue",
    "IRExpr",
    "IRLiteral",
    "IRName",
    "IRUnary",
    "IRBinary",
    "IRCall",
    "IRMember",
    "IRIndex",
    "IRList",
    "IRStruct",
    "IRAwait",
    "IRAiExpr",
    "IRContract",
    "IREffect",
    "EFFECT_MAP",
    "canonical_effect",
    "IRBuilder",
    "IRLoweringError",
    "lower",
]


# ---------------------------------------------------------------------------
# Canonical effect model
# ---------------------------------------------------------------------------
#: Source-level effect keyword -> canonical :class:`EffectKind` value.
EFFECT_MAP: Dict[str, str] = {
    "io": "IO",
    "net": "Network",
    "network": "Network",
    "fs": "FileSystem",
    "db": "DatabaseRead",
    "dbread": "DatabaseRead",
    "dbwrite": "DatabaseWrite",
    "database_read": "DatabaseRead",
    "database_write": "DatabaseWrite",
    "log": "Log",
    "logging": "Log",
    "time": "Time",
    "rand": "Random",
    "random": "Random",
    "state": "State",
    "ai": "AI",
    "gpu": "GPU",
    "env": "Env",
    "proc": "Process",
    "process": "Process",
    "secret": "Secrets",
    "secrets": "Secrets",
    "payment": "Payments",
    "payments": "Payments",
}


def canonical_effect(name: str) -> str:
    """Return the canonical effect kind for a source-level effect ``name``.

    Unknown names are passed through unchanged so that the effect tracker can
    still reason about them (and report them) rather than silently dropping
    information.
    """
    key = name.strip().lower()
    return EFFECT_MAP.get(key, name)


def canonical_effects(names: Sequence[str]) -> Tuple[str, ...]:
    """Canonicalise a list of effect names, preserving first-seen order."""
    seen: List[str] = []
    for n in names:
        c = canonical_effect(n)
        if c not in seen:
            seen.append(c)
    return tuple(seen)


class IRLoweringError(Exception):
    """Raised when the AST cannot be lowered (a genuine compiler bug)."""

    def __init__(self, message: str, loc: Optional[SourceLocation] = None) -> None:
        super().__init__(message)
        self.message = message
        self.loc = loc


# ---------------------------------------------------------------------------
# Base node
# ---------------------------------------------------------------------------
@dataclass
class IRNode:
    """Base class for every IR node."""

    loc: Optional[SourceLocation] = field(default=None, kw_only=True)
    id: str = field(default="", kw_only=True)

    def kind_name(self) -> str:
        """A short symbolic name for this node (used by dumps and tests).

        Named ``kind_name`` rather than ``kind`` because several IR nodes
        (e.g. :class:`IRContract`) legitimately expose a ``kind`` data field.
        """
        return type(self).__name__

    def children(self) -> List["IRNode"]:
        """Return ordered direct child nodes (deterministic traversal)."""
        out: List[IRNode] = []
        for value in vars(self).values():
            if isinstance(value, IRNode):
                out.append(value)
            elif isinstance(value, (list, tuple)):
                out.extend(v for v in value if isinstance(v, IRNode))
        return out

    def walk(self) -> List["IRNode"]:
        """Return this node and all descendants in a deterministic pre-order.

        Shared references (e.g. an agent's nested function, reachable both via
        its body block and via ``IRAgent.functions``) are visited exactly once,
        so the traversal is a proper walk of the node graph rather than a
        duplicated tree expansion.
        """
        seen: set = set()
        result: List[IRNode] = []

        def rec(node: "IRNode") -> None:
            key = id(node)
            if key in seen:
                return
            seen.add(key)
            result.append(node)
            for child in node.children():
                rec(child)

        rec(self)
        return result


# ---------------------------------------------------------------------------
# Module level
# ---------------------------------------------------------------------------
@dataclass
class IRImport(IRNode):
    """A lowered ``import``."""

    module: str = ""
    alias: Optional[str] = None
    symbols: List[str] = field(default_factory=list)

    @property
    def local_names(self) -> List[str]:
        if self.symbols:
            return list(self.symbols)
        return [self.alias or self.module.split(".")[0]]


@dataclass
class IRField(IRNode):
    name: str = ""
    type: Optional[Type] = None
    default: Optional["IRExpr"] = None
    secret: bool = False


@dataclass
class IRTypeDecl(IRNode):
    """A lowered ``type`` (struct) declaration."""

    name: str = ""
    fields: List[IRField] = field(default_factory=list)
    generics: List[str] = field(default_factory=list)
    invariants: List["IRContract"] = field(default_factory=list)
    resource: Optional[Type] = None
    implements: List[str] = field(default_factory=list)

    def field(self, name: str) -> Optional[IRField]:
        for f in self.fields:
            if f.name == name:
                return f
        return None


@dataclass
class IRVariant(IRNode):
    name: str = ""
    payload: List[Type] = field(default_factory=list)


@dataclass
class IREnumDecl(IRNode):
    name: str = ""
    variants: List[IRVariant] = field(default_factory=list)
    resource: Optional[Type] = None

    def variant(self, name: str) -> Optional[IRVariant]:
        for v in self.variants:
            if v.name == name:
                return v
        return None


# ---------------------------------------------------------------------------
# Expressions (typed)
# ---------------------------------------------------------------------------
@dataclass
class IRExpr(IRNode):
    """Base class for typed IR expressions."""

    type: Optional[Type] = None


@dataclass
class IRLiteral(IRExpr):
    value: object = None
    literal_kind: str = ""  # "int" | "float" | "string" | "char" | "bool" | "null"


@dataclass
class IRName(IRExpr):
    name: str = ""
    role: str = "value"  # "value" | "type" | "variant" | "callee"


@dataclass
class IRUnary(IRExpr):
    op: str = ""
    operand: Optional[IRExpr] = None


@dataclass
class IRBinary(IRExpr):
    op: str = ""
    left: Optional[IRExpr] = None
    right: Optional[IRExpr] = None


@dataclass
class IRCall(IRExpr):
    callee: Optional[IRExpr] = None
    args: List[IRExpr] = field(default_factory=list)
    is_async: bool = False


@dataclass
class IRMember(IRExpr):
    obj: Optional[IRExpr] = None
    name: str = ""


@dataclass
class IRIndex(IRExpr):
    obj: Optional[IRExpr] = None
    index: Optional[IRExpr] = None


@dataclass
class IRList(IRExpr):
    elements: List[IRExpr] = field(default_factory=list)


@dataclass
class IRStruct(IRExpr):
    type_name: str = ""
    fields: List[Tuple[str, IRExpr]] = field(default_factory=list)


@dataclass
class IRAwait(IRExpr):
    operand: Optional[IRExpr] = None


@dataclass
class IRAiExpr(IRExpr):
    prompt: Optional[IRExpr] = None
    body: Optional["IRBlock"] = None


# ---------------------------------------------------------------------------
# Statements (typed)
# ---------------------------------------------------------------------------
@dataclass
class IRStmt(IRNode):
    """Base class for IR statements."""


@dataclass
class IRLet(IRStmt):
    name: str = ""
    type: Optional[Type] = None
    value: Optional[IRExpr] = None
    mutable: bool = False


@dataclass
class IRConst(IRNode):
    """A module-level ``let``/``var`` constant (Step 7)."""

    name: str = ""
    type: Optional[Type] = None
    value: Optional[IRExpr] = None
    mutable: bool = False


@dataclass
class IRAssign(IRStmt):
    target: Optional[IRExpr] = None
    op: str = "="
    value: Optional[IRExpr] = None


@dataclass
class IRExprStmt(IRStmt):
    expr: Optional[IRExpr] = None


@dataclass
class IRIf(IRStmt):
    condition: Optional[IRExpr] = None
    then_branch: Optional["IRBlock"] = None
    else_branch: object = None  # IRBlock | IRIf | None


@dataclass
class IRWhile(IRStmt):
    condition: Optional[IRExpr] = None
    body: Optional["IRBlock"] = None


@dataclass
class IRFor(IRStmt):
    variable: str = ""
    iterable: Optional[IRExpr] = None
    element_type: Optional[Type] = None
    body: Optional["IRBlock"] = None


@dataclass
class IRReturn(IRStmt):
    value: Optional[IRExpr] = None


@dataclass
class IRBreak(IRStmt):
    pass


@dataclass
class IRContinue(IRStmt):
    pass


@dataclass
class IRAssert(IRStmt):
    """A runtime assertion lowered from a contract clause.

    Produced by :mod:`happy.compiler.contracts` when contracts are lowered to
    executable IR: a precondition is asserted on function entry, a
    postcondition before every ``return``, and an invariant at the boundaries
    of the owning type's methods.
    """

    kind: str = ""  # requires | ensures | invariant | rule
    predicate: Optional[IRExpr] = None
    message: Optional[str] = None
    owner: Optional[str] = None


@dataclass
class IRBlock(IRNode):
    statements: List[IRStmt] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Contracts, permissions, effects
# ---------------------------------------------------------------------------
@dataclass
class IRContract(IRNode):
    """A lowered ``requires`` / ``ensures`` / ``invariant`` clause."""

    kind: str = ""  # requires | ensures | invariant
    condition: Optional[IRExpr] = None
    message: Optional[str] = None
    attach_to: Optional[str] = None  # owning struct name for invariants
    refers_to_result: bool = False
    refers_to_old: bool = False


@dataclass
class IREffect(IRNode):
    """A single side-effect annotation with its canonical kind and origin."""

    name: str = ""
    canonical: str = ""
    origin: str = ""  # "annotation" | "body"


@dataclass
class IRParam(IRNode):
    name: str = ""
    type: Optional[Type] = None
    default: Optional[IRExpr] = None


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------
@dataclass
class IRFunction(IRNode):
    name: str = ""
    params: List[IRParam] = field(default_factory=list)
    returns: Optional[Type] = None
    body: Optional[IRBlock] = None
    contracts: List[IRContract] = field(default_factory=list)
    declared_effects: List[IREffect] = field(default_factory=list)
    inferred_effects: List[str] = field(default_factory=list)
    is_async: bool = False
    generics: List[str] = field(default_factory=list)
    owner: Optional[str] = None  # enclosing agent/ai name, if any
    #: True when the source carried an explicit ``effects [...]`` annotation
    #: (``effects []`` meaning "pure" counts as present; bare functions do not).
    has_effect_annotation: bool = False

    @property
    def signature(self) -> FunctionType:
        return FunctionType(
            [p.type or UNKNOWN for p in self.params],
            self.returns or UNIT,
            is_async=self.is_async,
        )

    def contract(self, kind: str) -> List[IRContract]:
        return [c for c in self.contracts if c.kind == kind]


@dataclass
class IRRule(IRNode):
    name: str = ""
    params: List[IRParam] = field(default_factory=list)
    condition: Optional[IRExpr] = None
    body: Optional[IRBlock] = None
    contracts: List[IRContract] = field(default_factory=list)


@dataclass
class IRPermission(IRNode):
    name: str = ""
    can: List[str] = field(default_factory=list)
    cannot: List[str] = field(default_factory=list)
    body: Optional[IRBlock] = None

    @property
    def conflicts(self) -> List[str]:
        return sorted(set(self.can) & set(self.cannot))


@dataclass
class IRCapability(IRNode):
    name: str = ""
    grants: List[str] = field(default_factory=list)
    body: Optional[IRBlock] = None


@dataclass
class IRAgent(IRNode):
    name: str = ""
    goal: Optional[IRExpr] = None
    permissions: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    declared_effects: List[IREffect] = field(default_factory=list)
    functions: List[IRFunction] = field(default_factory=list)
    body: Optional[IRBlock] = None
    contracts: List[IRContract] = field(default_factory=list)


@dataclass
class IRAi(IRNode):
    name: str = ""
    prompt: Optional[IRExpr] = None
    goal: Optional[IRExpr] = None
    body: Optional[IRBlock] = None
    contracts: List[IRContract] = field(default_factory=list)


@dataclass
class IRApp(IRNode):
    name: str = ""
    body: Optional[IRBlock] = None
    contracts: List[IRContract] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Traits / interfaces and pattern matching (Step 7)
# ---------------------------------------------------------------------------
@dataclass
class IRTraitMethod(IRNode):
    """A method signature (or default body) declared in a ``trait``."""

    name: str = ""
    params: List["IRParam"] = field(default_factory=list)
    returns: Optional[Type] = None
    contracts: List["IRContract"] = field(default_factory=list)
    body: Optional["IRBlock"] = None

    @property
    def arity(self) -> int:
        return len(self.params)


@dataclass
class IRTrait(IRNode):
    """A lowered ``trait`` (interface) declaration."""

    name: str = ""
    methods: List[IRTraitMethod] = field(default_factory=list)

    def method(self, name: str) -> Optional[IRTraitMethod]:
        for m in self.methods:
            if m.name == name:
                return m
        return None


@dataclass
class IRImpl(IRNode):
    """A lowered ``impl Trait for Type { ... }`` block."""

    trait: str = ""
    for_type: str = ""
    methods: List[IRFunction] = field(default_factory=list)

    def method(self, name: str) -> Optional[IRFunction]:
        for m in self.methods:
            if m.name == name:
                return m
        return None


@dataclass
class IRPattern(IRNode):
    """A lowered match pattern.

    ``kind`` is ``wildcard`` | ``binding`` | ``variant`` | ``literal`` |
    ``struct`` | ``or``.
    """

    kind: str = ""
    name: Optional[str] = None
    bindings: List[str] = field(default_factory=list)
    value: Optional["IRExpr"] = None
    patterns: List["IRPattern"] = field(default_factory=list)
    variant_enum: Optional[str] = None


@dataclass
class IRMatchArm(IRNode):
    pattern: Optional[IRPattern] = None
    body: Optional["IRBlock"] = None
    bare_expr: bool = False


@dataclass
class IRMatch(IRStmt):
    """``match subject { pattern -> ... }`` lowered to an explicit node."""

    subject: Optional["IRExpr"] = None
    arms: List[IRMatchArm] = field(default_factory=list)

    @property
    def exhaustive(self) -> bool:
        return any(
            a.pattern is not None and a.pattern.kind == "wildcard" for a in self.arms
        )


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------
@dataclass
class IRModule(IRNode):
    """The root IR node: a lowered Happy module."""

    name: Optional[str] = None
    imports: List[IRImport] = field(default_factory=list)
    types: List[IRTypeDecl] = field(default_factory=list)
    enums: List[IREnumDecl] = field(default_factory=list)
    traits: List[IRTrait] = field(default_factory=list)
    impls: List[IRImpl] = field(default_factory=list)
    constants: List[IRConst] = field(default_factory=list)
    functions: List[IRFunction] = field(default_factory=list)
    rules: List[IRRule] = field(default_factory=list)
    permissions: List[IRPermission] = field(default_factory=list)
    capabilities: List[IRCapability] = field(default_factory=list)
    agents: List[IRAgent] = field(default_factory=list)
    ai_blocks: List[IRAi] = field(default_factory=list)
    apps: List[IRApp] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    diagnostics: List[object] = field(default_factory=list)

    # -- ordered view ---------------------------------------------------
    def declarations(self) -> List[IRNode]:
        """All top-level declarations in deterministic lowering order."""
        return (
            list(self.imports)
            + list(self.types)
            + list(self.enums)
            + list(self.traits)
            + list(self.impls)
            + list(self.constants)
            + list(self.functions)
            + list(self.rules)
            + list(self.permissions)
            + list(self.capabilities)
            + list(self.agents)
            + list(self.ai_blocks)
            + list(self.apps)
        )

    def function(self, name: str) -> Optional[IRFunction]:
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def type_decl(self, name: str) -> Optional[IRTypeDecl]:
        for t in self.types:
            if t.name == name:
                return t
        return None

    def enum_decl(self, name: str) -> Optional[IREnumDecl]:
        for e in self.enums:
            if e.name == name:
                return e
        return None

    def diagnostics_by_severity(self, severity: str) -> List[object]:
        return [d for d in self.diagnostics if getattr(d, "severity", None) == severity]

    # -- determinism ----------------------------------------------------
    def fingerprint(self) -> str:
        """A stable content hash of the IR tree (for determinism tests)."""
        import hashlib

        h = hashlib.sha256()
        for node in self.walk():
            h.update(node.kind_name().encode("utf-8"))
            h.update(b"|")
            h.update(_node_label(node).encode("utf-8"))
            h.update(b";")
        return h.hexdigest()


def _node_label(node: IRNode) -> str:
    """A small, stable label used by :meth:`IRModule.fingerprint`."""
    for attr in ("name", "op", "value", "literal_kind", "kind"):
        val = getattr(node, attr, None)
        if isinstance(val, (str, int, float, bool)) and val != "":
            return f"{attr}={val}"
    if isinstance(node, IRExpr) and node.type is not None:
        return f"type={node.type.display()}"
    return ""


# ---------------------------------------------------------------------------
# Builder: assigns deterministic IDs and lower-level helpers
# ---------------------------------------------------------------------------
class IRBuilder:
    """Assigns deterministic node IDs during a single lowering pass."""

    def __init__(self) -> None:
        self._counter = 0

    def node_id(self) -> str:
        self._counter += 1
        return f"n{self._counter - 1}"

    def attach(self, node: IRNode) -> IRNode:
        """Give ``node`` its ID if it does not already have one."""
        if not node.id:
            object.__setattr__(node, "id", self.node_id())
        return node


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
_PRIMITIVE_TYPES = {"Int", "Float", "String", "Bool", "Byte", "Char", "Unit"}


def _resolve_type_node(
    node: Optional[ast.TypeNode],
    resource: Optional[Type],
    type_names: Dict[str, Type],
    type_params: Sequence[str] = (),
) -> Type:
    """Resolve an AST type node to a semantic ``Type`` without the analyzer.

    The IR stage prefers types attached by the semantic analyzer (via the
    ``resource`` argument), but falls back to a local resolution so the IR is
    still well-formed when no analysis result is supplied.
    """
    if node is None:
        return UNKNOWN
    if isinstance(node, ast.PrimitiveType):
        if node.name in _PRIMITIVE_TYPES:
            from .types import PrimitiveType

            return PrimitiveType(node.name)
        return UNKNOWN
    if isinstance(node, ast.NamedType):
        if node.name in type_params:
            from .types import TypeVar

            return TypeVar(node.name)
        return type_names.get(node.name, UNKNOWN)
    if isinstance(node, ast.GenericType):
        from .types import (
            ListType,
            MapType,
            OptionType,
            ResultType,
            SetType,
            GenericInstance,
        )

        args = [
            _resolve_type_node(a, None, type_names, type_params) for a in node.args
        ]
        builtin = {
            "List": lambda a: ListType(a[0]),
            "Set": lambda a: SetType(a[0]),
            "Option": lambda a: OptionType(a[0]),
            "Map": lambda a: MapType(a[0], a[1]),
            "Result": lambda a: ResultType(a[0], a[1]),
            "Future": lambda a: GenericInstance("Future", tuple(a)),
        }
        if node.name in builtin and len(args) == (
            2 if node.name in ("Map", "Result") else 1
        ):
            return builtin[node.name](args)
        return GenericInstance(node.name, tuple(args))
    if isinstance(node, ast.OptionalType):
        from .types import OptionType

        return OptionType(
            _resolve_type_node(node.inner, None, type_names, type_params)
        )
    if isinstance(node, ast.FunctionType):
        return FunctionType(
            [
                _resolve_type_node(p, None, type_names, type_params)
                for p in node.params
            ],
            _resolve_type_node(node.returns, None, type_names, type_params),
        )
    if isinstance(node, ast.TupleType):
        from .types import TupleType

        return TupleType(
            [
                _resolve_type_node(e, None, type_names, type_params)
                for e in node.elements
            ]
        )
    return UNKNOWN


# ---------------------------------------------------------------------------
# Lowering
# ---------------------------------------------------------------------------
class _Lowerer:
    """A single, stateful lowering pass over one analyzed program."""

    def __init__(
        self,
        analysis,
        source: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> None:
        self.analysis = analysis
        self.program: Optional[ast.Program] = (
            analysis.program if analysis is not None else None
        )
        self.source = source
        self.filename = filename
        self.builder = IRBuilder()
        self.type_names: Dict[str, Type] = dict(
            getattr(analysis, "types", {}) or {}
        )
        self.functions: Dict[str, FunctionType] = dict(
            getattr(analysis, "functions", {}) or {}
        )
        #: fallback type resolution for struct/enum literals & fields
        self._struct_decls: Dict[str, ast.StructDecl] = {}
        self._variant_enum: Dict[str, str] = {}
        self._enum_decls: Dict[str, ast.EnumDecl] = {}
        self._active_owner: Optional[str] = None
        self._active_returns: Type = UNIT
        self._active_type_params: Sequence[str] = ()

    # -- entry ----------------------------------------------------------
    def run(self) -> IRModule:
        program = self.program
        module = self._n(IRModule(id=""))  # root id fixed for determinism
        if program is None:
            return module
        module.name = program.module.name if program.module else None
        self._index_declarations(program)
        self._build_variant_index(program)
        module.imports = [self._lower_import(i) for i in program.imports]
        for decl in program.declarations:
            self._lower_decl(decl, module)
        module.exports = sorted(
            set(getattr(self.analysis, "exports", set()) or set())
        )
        module.diagnostics = list(
            getattr(self.analysis, "diagnostics", []) or []
        )
        return module

    def _index_declarations(self, program: ast.Program) -> None:
        for decl in program.declarations:
            if isinstance(decl, ast.StructDecl):
                self._struct_decls[decl.name] = decl
                self.type_names.setdefault(
                    decl.name,
                    _resolve_type_node(None, None, self.type_names),
                )
            elif isinstance(decl, ast.EnumDecl):
                self._enum_decls[decl.name] = decl
            elif isinstance(decl, ast.FunctionDecl):
                if decl.name not in self.functions:
                    self.functions[decl.name] = FunctionType(
                        [UNKNOWN for _ in decl.params],
                        UNKNOWN,
                        is_async=decl.is_async,
                    )

    # -- node helper ----------------------------------------------------
    def _n(self, node):
        """Assign an ID to ``node`` and return it."""
        self.builder.attach(node)
        return node

    # -- module members -------------------------------------------------
    def _lower_import(self, imp: ast.ImportDecl) -> IRImport:
        return self._n(
            IRImport(
                loc=imp.loc,
                module=imp.name,
                alias=imp.alias,
                symbols=list(imp.symbols),
            )
        )

    def _lower_decl(self, decl: ast.Decl, module: IRModule) -> None:
        if isinstance(decl, ast.StructDecl):
            module.types.append(self._lower_struct(decl))
        elif isinstance(decl, ast.EnumDecl):
            module.enums.append(self._lower_enum(decl))
        elif isinstance(decl, ast.FunctionDecl):
            module.functions.append(self._lower_function(decl))
        elif isinstance(decl, ast.RuleDecl):
            module.rules.append(self._lower_rule(decl))
        elif isinstance(decl, ast.PermissionDecl):
            module.permissions.append(self._lower_permission(decl))
        elif isinstance(decl, ast.CapabilityDecl):
            module.capabilities.append(self._lower_capability(decl))
        elif isinstance(decl, ast.AgentDecl):
            module.agents.append(self._lower_agent(decl))
        elif isinstance(decl, ast.AiDecl):
            module.ai_blocks.append(self._lower_ai(decl))
        elif isinstance(decl, ast.AppDecl):
            module.apps.append(self._lower_app(decl))
        elif isinstance(decl, ast.TraitDecl):
            module.traits.append(self._lower_trait(decl))
        elif isinstance(decl, ast.ImplDecl):
            module.impls.append(self._lower_impl(decl))
        elif isinstance(decl, ast.ConstDecl):
            module.constants.append(self._lower_const(decl))

    # -- types ----------------------------------------------------------
    def _lower_struct(self, decl: ast.StructDecl) -> IRTypeDecl:
        saved_params = self._active_type_params
        self._active_type_params = tuple(decl.generics)
        node = self._n(
            IRTypeDecl(
                loc=decl.loc,
                name=decl.name,
                generics=list(decl.generics),
                resource=self.type_names.get(decl.name),
                implements=list(getattr(decl, "implements", []) or []),
            )
        )
        for f in decl.fields:
            node.fields.append(
                self._n(
                    IRField(
                        loc=f.loc,
                        name=f.name,
                        type=_resolve_type_node(
                            f.type_annotation,
                            None,
                            self.type_names,
                            self._active_type_params,
                        ),
                        default=self._lower_expr(f.default) if f.default else None,
                        secret=f.secret,
                    )
                )
            )
        for inv in decl.invariants:
            node.invariants.append(self._lower_contract(inv, attach_to=decl.name))
        self._active_type_params = saved_params
        return node

    def _lower_enum(self, decl: ast.EnumDecl) -> IREnumDecl:
        node = self._n(
            IREnumDecl(
                loc=decl.loc,
                name=decl.name,
                resource=self.type_names.get(decl.name),
            )
        )
        for v in decl.variants:
            node.variants.append(
                self._n(
                    IRVariant(
                        loc=v.loc,
                        name=v.name,
                        payload=[
                            _resolve_type_node(p, None, self.type_names)
                            for p in v.payload
                        ],
                    )
                )
            )
        return node

    # -- functions & rules ---------------------------------------------
    def _lower_function(
        self, decl: ast.FunctionDecl, owner: Optional[str] = None
    ) -> IRFunction:
        saved_owner = self._active_owner
        saved_returns = self._active_returns
        saved_params = self._active_type_params
        self._active_owner = owner
        self._active_type_params = tuple(decl.generics)

        ret = _resolve_type_node(
            decl.returns, None, self.type_names, self._active_type_params
        )
        self._active_returns = ret
        node = self._n(
            IRFunction(
                loc=decl.loc,
                name=decl.name,
                is_async=decl.is_async,
                generics=list(decl.generics),
                owner=owner,
                returns=ret,
            )
        )
        for p in decl.params:
            node.params.append(
                self._n(
                    IRParam(
                        loc=p.loc,
                        name=p.name,
                        type=_resolve_type_node(
                            p.type_annotation,
                            None,
                            self.type_names,
                            self._active_type_params,
                        ),
                        default=self._lower_expr(p.default) if p.default else None,
                    )
                )
            )
        for c in decl.contracts:
            node.contracts.append(self._lower_contract(c))
        node.has_effect_annotation = decl.effects is not None
        node.declared_effects = self._lower_effects(decl.effects)
        if decl.body is not None:
            node.body = self._lower_block(decl.body)

        self._active_owner = saved_owner
        self._active_returns = saved_returns
        self._active_type_params = saved_params
        return node

    def _lower_rule(self, decl: ast.RuleDecl) -> IRRule:
        node = self._n(IRRule(loc=decl.loc, name=decl.name))
        for p in decl.params:
            node.params.append(
                self._n(
                    IRParam(
                        loc=p.loc,
                        name=p.name,
                        type=_resolve_type_node(p.type_annotation, None, self.type_names),
                        default=self._lower_expr(p.default) if p.default else None,
                    )
                )
            )
        for c in decl.contracts:
            node.contracts.append(self._lower_contract(c))
        node.condition = self._lower_expr(decl.condition) if decl.condition else None
        if decl.body is not None:
            node.body = self._lower_block(decl.body)
        return node

    # -- permissions & capabilities ------------------------------------
    def _lower_permission(self, decl: ast.PermissionDecl) -> IRPermission:
        return self._n(
            IRPermission(
                loc=decl.loc,
                name=decl.name,
                can=list(decl.can),
                cannot=list(decl.cannot),
                body=self._lower_block(decl.body) if decl.body else None,
            )
        )

    def _lower_capability(self, decl: ast.CapabilityDecl) -> IRCapability:
        return self._n(
            IRCapability(
                loc=decl.loc,
                name=decl.name,
                grants=list(decl.grants),
                body=self._lower_block(decl.body) if decl.body else None,
            )
        )

    # -- agents / ai / app ---------------------------------------------
    def _lower_agent(self, decl: ast.AgentDecl) -> IRAgent:
        node = self._n(
            IRAgent(
                loc=decl.loc,
                name=decl.name,
                permissions=list(decl.permissions),
                capabilities=list(decl.capabilities),
            )
        )
        node.goal = self._lower_expr(decl.goal) if decl.goal else None
        node.declared_effects = self._lower_effects(decl.effects)
        for c in decl.contracts:
            node.contracts.append(self._lower_contract(c))
        if decl.body is not None:
            node.body = self._lower_block(decl.body, owner=decl.name)
            node.functions = [
                s for s in node.body.statements if isinstance(s, IRFunction)
            ]
        return node

    def _lower_ai(self, decl: ast.AiDecl) -> IRAi:
        node = self._n(IRAi(loc=decl.loc, name=decl.name))
        node.prompt = self._lower_expr(decl.prompt) if decl.prompt else None
        node.goal = self._lower_expr(decl.goal) if decl.goal else None
        for c in decl.contracts:
            node.contracts.append(self._lower_contract(c))
        if decl.body is not None:
            node.body = self._lower_block(decl.body, owner=decl.name)
        return node

    def _lower_app(self, decl: ast.AppDecl) -> IRApp:
        node = self._n(IRApp(loc=decl.loc, name=decl.name))
        for c in decl.contracts:
            node.contracts.append(self._lower_contract(c))
        if decl.body is not None:
            node.body = self._lower_block(decl.body)
        return node

    def _lower_const(self, decl: ast.ConstDecl) -> IRConst:
        return self._n(
            IRConst(
                loc=decl.loc,
                name=decl.name,
                type=_resolve_type_node(decl.type_annotation, None, self.type_names)
                if decl.type_annotation
                else None,
                value=self._lower_expr(decl.value) if decl.value else None,
                mutable=decl.mutable,
            )
        )

    # -- traits, impls, pattern matching (Step 7) ----------------------
    def _lower_trait(self, decl: ast.TraitDecl) -> IRTrait:
        node = self._n(IRTrait(loc=decl.loc, name=decl.name))
        for m in decl.methods:
            mnode = self._n(
                IRTraitMethod(
                    loc=m.loc,
                    name=m.name,
                    params=[
                        self._n(
                            IRParam(
                                loc=p.loc,
                                name=p.name,
                                type=_resolve_type_node(
                                    p.type_annotation, None, self.type_names
                                ),
                            )
                        )
                        for p in m.params
                    ],
                    returns=_resolve_type_node(m.returns, None, self.type_names),
                )
            )
            for c in m.contracts:
                mnode.contracts.append(self._lower_contract(c, attach_to=decl.name))
            if m.body is not None:
                mnode.body = self._lower_block(m.body, owner=decl.name)
            node.methods.append(mnode)
        return node

    def _lower_impl(self, decl: ast.ImplDecl) -> IRImpl:
        node = self._n(IRImpl(loc=decl.loc, trait=decl.name, for_type=decl.for_type))
        for m in decl.methods:
            synthetic = ast.FunctionDecl(
                name=m.name,
                params=m.params,
                returns=m.returns,
                body=m.body,
                contracts=m.contracts,
                effects=m.effects,
                is_async=m.is_async,
                loc=m.loc,
            )
            fn = self._lower_function(synthetic, owner=decl.for_type)
            node.methods.append(fn)
        return node

    def _lower_match(self, stmt: ast.MatchStmt) -> IRMatch:
        node = self._n(
            IRMatch(
                loc=stmt.loc,
                subject=self._lower_expr(stmt.subject) if stmt.subject else None,
            )
        )
        for arm in stmt.arms:
            anode = self._n(
                IRMatchArm(
                    loc=arm.loc,
                    pattern=self._lower_pattern(arm.pattern) if arm.pattern else None,
                    body=self._lower_block(arm.body) if arm.body else None,
                    bare_expr=getattr(arm, "bare_expr", False),
                )
            )
            node.arms.append(anode)
        return node

    def _lower_pattern(self, pattern: ast.MatchPattern) -> IRPattern:
        node = self._n(
            IRPattern(
                loc=pattern.loc,
                kind=pattern.kind,
                name=pattern.name,
                bindings=list(pattern.bindings),
                value=self._lower_expr(pattern.value) if pattern.value else None,
            )
        )
        for sub in pattern.patterns:
            node.patterns.append(self._lower_pattern(sub))
        # Resolve which enum a bare variant belongs to (for codegen dispatch).
        if pattern.kind == "variant" and pattern.name:
            node.variant_enum = self._variant_enum.get(pattern.name)
        return node

    def _build_variant_index(self, program: ast.Program) -> None:
        self._variant_enum = {}
        for decl in program.declarations:
            if isinstance(decl, ast.EnumDecl):
                for v in decl.variants:
                    self._variant_enum.setdefault(v.name, decl.name)

    # -- contracts & effects -------------------------------------------
    def _lower_contract(
        self, clause: ast.ContractClause, attach_to: Optional[str] = None
    ) -> IRContract:
        cond = self._lower_expr(clause.condition) if clause.condition else None
        node = self._n(
            IRContract(
                loc=clause.loc,
                kind=clause.kind,
                condition=cond,
                message=clause.message,
                attach_to=attach_to,
            )
        )
        node.refers_to_result = _contains_name(cond, "result")
        node.refers_to_old = _contains_name(cond, "old") or _contains_name(
            cond, "pre"
        )
        return node

    def _lower_effects(self, spec: Optional[ast.EffectSpec]) -> List[IREffect]:
        if spec is None:
            return []
        out: List[IREffect] = []
        for name in spec.effects:
            out.append(
                self._n(
                    IREffect(
                        loc=spec.loc,
                        name=name,
                        canonical=canonical_effect(name),
                        origin="annotation",
                    )
                )
            )
        return out

    # -- statements -----------------------------------------------------
    def _lower_block(self, block: ast.Block, owner: Optional[str] = None) -> IRBlock:
        node = self._n(IRBlock(loc=block.loc))
        for stmt in block.statements:
            if isinstance(stmt, ast.FunctionDecl):
                node.statements.append(
                    self._lower_function(stmt, owner=owner or self._active_owner)
                )
            else:
                node.statements.append(self._lower_stmt(stmt))
        return node

    def _lower_stmt(self, stmt: ast.Stmt) -> IRStmt:
        if isinstance(stmt, ast.LetStmt):
            return self._n(
                IRLet(
                    loc=stmt.loc,
                    name=stmt.name,
                    type=_resolve_type_node(
                        stmt.type_annotation, None, self.type_names
                    ),
                    value=self._lower_expr(stmt.value) if stmt.value else None,
                    mutable=stmt.mutable,
                )
            )
        if isinstance(stmt, ast.AssignStmt):
            return self._n(
                IRAssign(
                    loc=stmt.loc,
                    target=self._lower_expr(stmt.target) if stmt.target else None,
                    op=stmt.op,
                    value=self._lower_expr(stmt.value) if stmt.value else None,
                )
            )
        if isinstance(stmt, ast.ExprStmt):
            return self._n(
                IRExprStmt(
                    loc=stmt.loc,
                    expr=self._lower_expr(stmt.expr) if stmt.expr else None,
                )
            )
        if isinstance(stmt, ast.IfStmt):
            node = self._n(
                IRIf(
                    loc=stmt.loc,
                    condition=self._lower_expr(stmt.condition)
                    if stmt.condition
                    else None,
                    then_branch=self._lower_block(stmt.then_branch)
                    if stmt.then_branch
                    else None,
                )
            )
            if isinstance(stmt.else_branch, ast.Block):
                node.else_branch = self._lower_block(stmt.else_branch)
            elif isinstance(stmt.else_branch, ast.IfStmt):
                node.else_branch = self._lower_stmt(stmt.else_branch)
            return node
        if isinstance(stmt, ast.WhileStmt):
            return self._n(
                IRWhile(
                    loc=stmt.loc,
                    condition=self._lower_expr(stmt.condition)
                    if stmt.condition
                    else None,
                    body=self._lower_block(stmt.body) if stmt.body else None,
                )
            )
        if isinstance(stmt, ast.ForStmt):
            return self._n(
                IRFor(
                    loc=stmt.loc,
                    variable=stmt.variable,
                    iterable=self._lower_expr(stmt.iterable)
                    if stmt.iterable
                    else None,
                    body=self._lower_block(stmt.body) if stmt.body else None,
                )
            )
        if isinstance(stmt, ast.ReturnStmt):
            return self._n(
                IRReturn(
                    loc=stmt.loc,
                    value=self._lower_expr(stmt.value) if stmt.value else None,
                )
            )
        if isinstance(stmt, ast.BreakStmt):
            return self._n(IRBreak(loc=stmt.loc))
        if isinstance(stmt, ast.ContinueStmt):
            return self._n(IRContinue(loc=stmt.loc))
        if isinstance(stmt, ast.MatchStmt):
            return self._lower_match(stmt)
        raise IRLoweringError(
            f"cannot lower statement of type {type(stmt).__name__}", stmt.loc
        )

    # -- expressions ----------------------------------------------------
    def _lower_expr(self, expr: Optional[ast.Expr]) -> Optional[IRExpr]:
        if expr is None:
            return None
        if isinstance(expr, ast.IntLiteral):
            return self._n(
                IRLiteral(loc=expr.loc, value=expr.value, literal_kind="int",
                          type=_prim("Int"))
            )
        if isinstance(expr, ast.FloatLiteral):
            return self._n(
                IRLiteral(loc=expr.loc, value=expr.value, literal_kind="float",
                          type=_prim("Float"))
            )
        if isinstance(expr, ast.StringLiteral):
            return self._n(
                IRLiteral(loc=expr.loc, value=expr.value, literal_kind="string",
                          type=_prim("String"))
            )
        if isinstance(expr, ast.CharLiteral):
            return self._n(
                IRLiteral(loc=expr.loc, value=expr.value, literal_kind="char",
                          type=_prim("Char"))
            )
        if isinstance(expr, ast.BoolLiteral):
            return self._n(
                IRLiteral(loc=expr.loc, value=expr.value, literal_kind="bool",
                          type=_prim("Bool"))
            )
        if isinstance(expr, ast.NullLiteral):
            from .types import OptionType

            return self._n(
                IRLiteral(loc=expr.loc, value=None, literal_kind="null",
                          type=OptionType(NEVER))
            )
        if isinstance(expr, ast.Identifier):
            return self._n(
                IRName(loc=expr.loc, name=expr.name, role="value",
                       type=self._lookup_name_type(expr.name))
            )
        if isinstance(expr, ast.UnaryOp):
            return self._n(
                IRUnary(
                    loc=expr.loc,
                    op=expr.op,
                    operand=self._lower_expr(expr.operand),
                    type=self._expr_type(expr),
                )
            )
        if isinstance(expr, ast.BinaryOp):
            return self._n(
                IRBinary(
                    loc=expr.loc,
                    op=expr.op,
                    left=self._lower_expr(expr.left),
                    right=self._lower_expr(expr.right),
                    type=self._binary_type(expr),
                )
            )
        if isinstance(expr, ast.CallExpr):
            callee = expr.callee
            is_async = False
            if isinstance(callee, ast.Identifier):
                sig = self.functions.get(callee.name)
                if sig is not None:
                    is_async = getattr(sig, "is_async", False)
            return self._n(
                IRCall(
                    loc=expr.loc,
                    callee=self._lower_expr(callee),
                    args=[e for e in (self._lower_expr(a) for a in expr.args) if e],
                    is_async=is_async,
                    type=self._expr_type(expr),
                )
            )
        if isinstance(expr, ast.MemberExpr):
            return self._n(
                IRMember(
                    loc=expr.loc,
                    obj=self._lower_expr(expr.obj),
                    name=expr.name,
                    type=self._expr_type(expr),
                )
            )
        if isinstance(expr, ast.IndexExpr):
            return self._n(
                IRIndex(
                    loc=expr.loc,
                    obj=self._lower_expr(expr.obj),
                    index=self._lower_expr(expr.index),
                    type=self._expr_type(expr),
                )
            )
        if isinstance(expr, ast.ListLiteral):
            elements = [e for e in (self._lower_expr(x) for x in expr.elements) if e]
            return self._n(IRList(loc=expr.loc, elements=elements,
                                  type=self._expr_type(expr)))
        if isinstance(expr, ast.StructLiteral):
            fields: List[Tuple[str, IRExpr]] = []
            for fi in expr.fields:
                val = self._lower_expr(fi.value)
                if val is not None:
                    fields.append((fi.name, val))
            return self._n(
                IRStruct(
                    loc=expr.loc,
                    type_name=expr.type_name,
                    fields=fields,
                    type=self.type_names.get(expr.type_name, UNKNOWN),
                )
            )
        if isinstance(expr, ast.AwaitExpr):
            return self._n(
                IRAwait(
                    loc=expr.loc,
                    operand=self._lower_expr(expr.operand),
                    type=self._await_type(expr),
                )
            )
        if isinstance(expr, ast.AiExpr):
            node = self._n(IRAiExpr(loc=expr.loc, type=ANY))
            node.prompt = self._lower_expr(expr.prompt) if expr.prompt else None
            node.body = self._lower_block(expr.body) if expr.body else None
            return node
        raise IRLoweringError(
            f"cannot lower expression of type {type(expr).__name__}", expr.loc
        )

    # -- type helpers ---------------------------------------------------
    def _lookup_name_type(self, name: str) -> Type:
        sig = self.functions.get(name)
        if sig is not None:
            return sig
        if name in self.type_names:
            return self.type_names[name]
        return UNKNOWN

    def _expr_type(self, expr: ast.Expr) -> Type:
        """Best-effort type for an expression the analyzer did not annotate."""
        # The semantic analyzer stores inferred types on its own maps; here we
        # only reproduce the cheap, local cases.  Where unavailable we return
        # ``UNKNOWN`` and downstream stages remain permissive.
        if isinstance(expr, ast.MemberExpr):
            base = self._expr_type(expr.obj) if expr.obj else UNKNOWN
            struct = self._struct_decl_for(base)
            if struct is not None:
                for f in struct.fields:
                    if f.name == expr.name:
                        return _resolve_type_node(f.type_annotation, None, self.type_names)
            return UNKNOWN
        if isinstance(expr, ast.CallExpr):
            if isinstance(expr.callee, ast.Identifier):
                sig = self.functions.get(expr.callee.name)
                if sig is not None:
                    from .types import GenericInstance

                    ret = sig.returns
                    if getattr(sig, "is_async", False):
                        return GenericInstance("Future", (ret,))
                    return ret
            return ANY
        if isinstance(expr, ast.ListLiteral):
            from .types import ListType

            elem = UNKNOWN
            if expr.elements:
                elem = self._expr_type(expr.elements[0])
            return ListType(elem)
        if isinstance(expr, ast.Identifier):
            return self._lookup_name_type(expr.name)
        if isinstance(expr, ast.StructLiteral):
            return self.type_names.get(expr.type_name, UNKNOWN)
        return UNKNOWN

    def _struct_decl_for(self, type_: Type):
        name = getattr(type_, "name", None)
        if isinstance(name, str) and name in self._struct_decls:
            return self._struct_decls[name]
        return None

    def _await_type(self, expr: ast.AwaitExpr) -> Type:
        inner = self._expr_type(expr.operand) if expr.operand else UNKNOWN
        elem = getattr(inner, "inner", None)
        if callable(elem):
            return elem()
        return ANY

    def _binary_type(self, expr: ast.BinaryOp) -> Type:
        op = expr.op
        if op in ("==", "!=", "<", "<=", ">", ">=", "&&", "||"):
            return _prim("Bool")
        lt = self._expr_type(expr.left) if expr.left else UNKNOWN
        rt = self._expr_type(expr.right) if expr.right else UNKNOWN
        # numeric join
        names = {getattr(lt, "name", None), getattr(rt, "name", None)}
        if "Float" in names:
            return _prim("Float")
        if "Int" in names:
            return _prim("Int")
        if "String" in names and op == "+":
            return _prim("String")
        return ANY


def _prim(name: str):
    from .types import PrimitiveType

    return PrimitiveType(name)


def _contains_name(expr: Optional[IRExpr], name: str) -> bool:
    if expr is None:
        return False
    for node in expr.walk():
        if isinstance(node, IRName) and node.name == name:
            return True
    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def lower(
    analysis_or_program,
    source: Optional[str] = None,
    filename: Optional[str] = None,
) -> IRModule:
    """Lower an analyzed Happy program into :class:`IRModule`.

    ``analysis_or_program`` may be:

    * an :class:`~happy.compiler.semantic.AnalysisResult` (preferred — carries
      inferred types, signatures and diagnostics), or
    * a raw :class:`~happy.compiler.ast.Program` (types resolved locally; the IR
      is still well-formed but less precise).
    """
    from . import ast as _ast

    if isinstance(analysis_or_program, _ast.Program):
        program = analysis_or_program
        analysis = _AnalysisShim(program)
    else:
        analysis = analysis_or_program

    if analysis is None or getattr(analysis, "program", None) is None:
        raise IRLoweringError("no program to lower (analysis has no AST)")

    return _Lowerer(analysis, source=source, filename=filename).run()


class _AnalysisShim:
    """Adapts a bare :class:`ast.Program` to the ``AnalysisResult`` shape.

    Only the attributes the lowerer actually reads are provided; everything
    else resolves to an empty mapping so that lowering of an unanalyzed
    program degrades gracefully instead of raising.
    """

    def __init__(self, program: ast.Program) -> None:
        self.program = program
        self.types: Dict[str, Type] = {}
        self.functions: Dict[str, FunctionType] = {}
        self.diagnostics: List[object] = []
        self.exports = set()
        self.module_name = program.module.name if program.module else None
