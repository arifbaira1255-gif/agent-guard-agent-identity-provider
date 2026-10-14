"""Abstract Syntax Tree (AST) node definitions for the Happy language.

The AST is a plain, immutable-ish tree of dataclasses.  Every node carries a
:class:`~happy.compiler.errors.SourceLocation` so that later compiler stages can
report precise diagnostics.

Node families
-------------
* Expressions  : literals, identifiers, binary/unary ops, calls, member access,
  indexing, ``await``, ``ai`` expressions.
* Types        : primitive, named, generic, function, tuple, optional.
* Statements   : ``let``/``var``, assignment, expression statements, ``if``,
  ``while``, ``for``, ``return``, ``break``, ``continue``, blocks.
* Declarations : ``module``, ``import``, ``type`` (struct), ``enum``,
  ``function``, ``rule``, ``permission``, ``capability``, ``agent``, ``ai``.
* Contracts    : ``requires`` / ``ensures`` / ``invariant`` clauses.
* Effects      : ``effects`` annotations on functions and agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union

from .errors import SourceLocation

__all__ = [
    "Node",
    "Program",
    # types
    "TypeNode",
    "PrimitiveType",
    "NamedType",
    "GenericType",
    "FunctionType",
    "TupleType",
    "OptionalType",
    # expressions
    "Expr",
    "IntLiteral",
    "FloatLiteral",
    "StringLiteral",
    "CharLiteral",
    "BoolLiteral",
    "NullLiteral",
    "Identifier",
    "BinaryOp",
    "UnaryOp",
    "CallExpr",
    "MemberExpr",
    "IndexExpr",
    "ListLiteral",
    "StructLiteral",
    "FieldInit",
    "AwaitExpr",
    "AiExpr",
    # statements
    "Stmt",
    "LetStmt",
    "AssignStmt",
    "ExprStmt",
    "IfStmt",
    "WhileStmt",
    "ForStmt",
    "ReturnStmt",
    "BreakStmt",
    "ContinueStmt",
    "Block",
    # contracts / effects
    "ContractClause",
    "EffectSpec",
    # declarations
    "Decl",
    "ModuleDecl",
    "ImportDecl",
    "Param",
    "FieldDecl",
    "StructDecl",
    "EnumVariant",
    "EnumDecl",
    "FunctionDecl",
    "RuleDecl",
    "PermissionDecl",
    "CapabilityDecl",
    "AgentDecl",
    "AiDecl",
    "AppDecl",
    "TraitDecl",
    "ImplDecl",
    "ExportDecl",
    "ConstDecl",
    "MatchStmt",
    "MatchArm",
    "MatchPattern",
]


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
@dataclass
class Node:
    """Base class for every AST node."""

    loc: Optional[SourceLocation] = field(default=None, kw_only=True)

    def children(self) -> List["Node"]:
        """Return direct child nodes (used by tests and tree walkers)."""
        out: List[Node] = []
        for value in vars(self).values():
            if isinstance(value, Node):
                out.append(value)
            elif isinstance(value, (list, tuple)):
                out.extend(v for v in value if isinstance(v, Node))
        return out


@dataclass
class Program(Node):
    """The root node: a module plus its top-level declarations."""

    module: Optional["ModuleDecl"] = None
    imports: List["ImportDecl"] = field(default_factory=list)
    declarations: List["Decl"] = field(default_factory=list)

    def find(self, name: str) -> Optional["Decl"]:
        """Return the first top-level declaration with the given name."""
        for decl in self.declarations:
            if getattr(decl, "name", None) == name:
                return decl
        return None

    def of_kind(self, cls) -> List["Decl"]:
        """Return all top-level declarations that are instances of ``cls``."""
        return [d for d in self.declarations if isinstance(d, cls)]


# ---------------------------------------------------------------------------
# Type nodes
# ---------------------------------------------------------------------------
@dataclass
class TypeNode(Node):
    """Base class for type expressions."""


@dataclass
class PrimitiveType(TypeNode):
    name: str = ""


@dataclass
class NamedType(TypeNode):
    name: str = ""
    module: Optional[str] = None


@dataclass
class GenericType(TypeNode):
    name: str = ""
    args: List[TypeNode] = field(default_factory=list)


@dataclass
class FunctionType(TypeNode):
    params: List[TypeNode] = field(default_factory=list)
    returns: Optional[TypeNode] = None


@dataclass
class TupleType(TypeNode):
    elements: List[TypeNode] = field(default_factory=list)


@dataclass
class OptionalType(TypeNode):
    inner: Optional[TypeNode] = None


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------
@dataclass
class Expr(Node):
    """Base class for expressions."""


@dataclass
class IntLiteral(Expr):
    value: int = 0


@dataclass
class FloatLiteral(Expr):
    value: float = 0.0


@dataclass
class StringLiteral(Expr):
    value: str = ""


@dataclass
class CharLiteral(Expr):
    value: str = ""


@dataclass
class BoolLiteral(Expr):
    value: bool = False


@dataclass
class NullLiteral(Expr):
    pass


@dataclass
class Identifier(Expr):
    name: str = ""


@dataclass
class BinaryOp(Expr):
    op: str = ""
    left: Optional[Expr] = None
    right: Optional[Expr] = None


@dataclass
class UnaryOp(Expr):
    op: str = ""
    operand: Optional[Expr] = None


@dataclass
class CallExpr(Expr):
    callee: Optional[Expr] = None
    args: List[Expr] = field(default_factory=list)


@dataclass
class MemberExpr(Expr):
    obj: Optional[Expr] = None
    name: str = ""


@dataclass
class IndexExpr(Expr):
    obj: Optional[Expr] = None
    index: Optional[Expr] = None


@dataclass
class ListLiteral(Expr):
    elements: List[Expr] = field(default_factory=list)


@dataclass
class FieldInit(Node):
    """A single ``name: value`` entry inside a struct literal."""

    name: str = ""
    value: Optional[Expr] = None


@dataclass
class StructLiteral(Expr):
    """A struct construction expression, e.g. ``Account { id: 1 }``."""

    type_name: str = ""
    fields: List[FieldInit] = field(default_factory=list)


@dataclass
class AwaitExpr(Expr):
    """``await <expr>`` — suspends until an async operation completes."""

    operand: Optional[Expr] = None


@dataclass
class AiExpr(Expr):
    """``ai { ... }`` used as an expression (e.g. inline model call)."""

    prompt: Optional[Expr] = None
    body: Optional["Block"] = None


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------
@dataclass
class Stmt(Node):
    """Base class for statements."""


@dataclass
class LetStmt(Stmt):
    name: str = ""
    type_annotation: Optional[TypeNode] = None
    value: Optional[Expr] = None
    mutable: bool = False  # True for ``var``, False for ``let``


@dataclass
class AssignStmt(Stmt):
    target: Optional[Expr] = None
    op: str = "="
    value: Optional[Expr] = None


@dataclass
class ExprStmt(Stmt):
    expr: Optional[Expr] = None


@dataclass
class IfStmt(Stmt):
    condition: Optional[Expr] = None
    then_branch: Optional["Block"] = None
    else_branch: Optional[Union["Block", "IfStmt"]] = None


@dataclass
class WhileStmt(Stmt):
    condition: Optional[Expr] = None
    body: Optional["Block"] = None


@dataclass
class ForStmt(Stmt):
    variable: str = ""
    iterable: Optional[Expr] = None
    body: Optional["Block"] = None


@dataclass
class ReturnStmt(Stmt):
    value: Optional[Expr] = None


@dataclass
class BreakStmt(Stmt):
    pass


@dataclass
class ContinueStmt(Stmt):
    pass


@dataclass
class Block(Node):
    statements: List[Stmt] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Contracts & effects
# ---------------------------------------------------------------------------
@dataclass
class ContractClause(Node):
    """A single ``requires`` / ``ensures`` / ``invariant`` clause."""

    kind: str = ""  # "requires" | "ensures" | "invariant"
    condition: Optional[Expr] = None
    message: Optional[str] = None  # optional human-readable message


@dataclass
class EffectSpec(Node):
    """An ``effects`` annotation, e.g. ``effects [io, net]``."""

    effects: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------
@dataclass
class Decl(Node):
    """Base class for top-level declarations."""

    name: str = ""


@dataclass
class ModuleDecl(Decl):
    name: str = ""
    doc: Optional[str] = None


@dataclass
class ImportDecl(Decl):
    name: str = ""  # imported module path
    alias: Optional[str] = None
    symbols: List[str] = field(default_factory=list)


@dataclass
class ExportDecl(Decl):
    """``export a, b, c`` \u2014 explicitly marks a module's public names."""

    names: List[str] = field(default_factory=list)


@dataclass
class ConstDecl(Decl):
    """A module-level ``let name = value`` binding."""

    name: str = ""
    type_annotation: Optional[TypeNode] = None
    value: Optional[Expr] = None
    mutable: bool = False


@dataclass
class Param(Node):
    name: str = ""
    type_annotation: Optional[TypeNode] = None
    default: Optional[Expr] = None


@dataclass
class FieldDecl(Node):
    name: str = ""
    type_annotation: Optional[TypeNode] = None
    default: Optional[Expr] = None
    secret: bool = False  # ``secret`` field modifier


@dataclass
class StructDecl(Decl):
    """A ``type Name { ... }`` struct declaration."""

    name: str = ""
    fields: List[FieldDecl] = field(default_factory=list)
    invariants: List[ContractClause] = field(default_factory=list)
    generics: List[str] = field(default_factory=list)
    implements: List[str] = field(default_factory=list)


@dataclass
class EnumVariant(Node):
    name: str = ""
    payload: List[TypeNode] = field(default_factory=list)


@dataclass
class EnumDecl(Decl):
    name: str = ""
    variants: List[EnumVariant] = field(default_factory=list)


@dataclass
class FunctionDecl(Decl):
    name: str = ""
    params: List[Param] = field(default_factory=list)
    returns: Optional[TypeNode] = None
    body: Optional[Block] = None
    contracts: List[ContractClause] = field(default_factory=list)
    effects: Optional[EffectSpec] = None
    is_async: bool = False
    generics: List[str] = field(default_factory=list)


@dataclass
class RuleDecl(Decl):
    """A ``rule`` declaration — a named, checkable policy."""

    name: str = ""
    params: List[Param] = field(default_factory=list)
    condition: Optional[Expr] = None
    body: Optional[Block] = None
    contracts: List[ContractClause] = field(default_factory=list)


@dataclass
class PermissionDecl(Decl):
    """A ``permission`` declaration, optionally with ``can``/``cannot`` rules."""

    name: str = ""
    can: List[str] = field(default_factory=list)
    cannot: List[str] = field(default_factory=list)
    body: Optional[Block] = None


@dataclass
class CapabilityDecl(Decl):
    """A ``capability`` declaration — a grantable authority token."""

    name: str = ""
    grants: List[str] = field(default_factory=list)
    body: Optional[Block] = None


@dataclass
class AgentDecl(Decl):
    """An ``agent`` declaration — an autonomous actor with goals and effects."""

    name: str = ""
    goal: Optional[Expr] = None
    permissions: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    effects: Optional[EffectSpec] = None
    body: Optional[Block] = None
    contracts: List[ContractClause] = field(default_factory=list)


@dataclass
class AiDecl(Decl):
    """An ``ai`` declaration — a model-backed behaviour block."""

    name: str = ""
    prompt: Optional[Expr] = None
    goal: Optional[Expr] = None
    body: Optional[Block] = None
    contracts: List[ContractClause] = field(default_factory=list)


@dataclass
class AppDecl(Decl):
    """An ``app`` declaration — the top-level application entry point."""

    name: str = ""
    body: Optional[Block] = None
    contracts: List[ContractClause] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Traits / interfaces (Step 7)
# ---------------------------------------------------------------------------
@dataclass
class TraitMethod(Node):
    """A method signature (or default body) declared inside a ``trait``."""

    name: str = ""
    params: List[Param] = field(default_factory=list)
    returns: Optional[TypeNode] = None
    contracts: List[ContractClause] = field(default_factory=list)
    generics: List[str] = field(default_factory=list)
    is_async: bool = False
    body: Optional[Block] = None


@dataclass
class TraitDecl(Decl):
    """A ``trait Name { function m(...) -> T ... }`` interface declaration."""

    name: str = ""
    methods: List[TraitMethod] = field(default_factory=list)


@dataclass
class ImplMethod(Node):
    """A method implementation inside an ``impl`` block."""

    name: str = ""
    params: List[Param] = field(default_factory=list)
    returns: Optional[TypeNode] = None
    contracts: List[ContractClause] = field(default_factory=list)
    effects: Optional[EffectSpec] = None
    generics: List[str] = field(default_factory=list)
    is_async: bool = False
    body: Optional[Block] = None


@dataclass
class ImplDecl(Decl):
    """``impl Trait for Type { ... }`` — a type's implementation of a trait."""

    name: str = ""              # trait name
    for_type: str = ""          # the implementing type
    methods: List[ImplMethod] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern matching (Step 7)
# ---------------------------------------------------------------------------
@dataclass
class MatchPattern(Node):
    """A single pattern in a ``match`` arm.

    ``kind`` is one of:

    * ``"wildcard"``     — ``_``
    * ``"binding"``      — a lowercase name binding the whole subject
    * ``"variant"``      — ``Variant`` / ``Variant(a, b)``
    * ``"literal"``      — an ``Int`` / ``Float`` / ``String`` / ``Bool`` / ``Char``
    * ``"struct"``       — ``Type { field, ... }``
    * ``"or"``           — ``p1 | p2``
    """

    kind: str = ""
    name: Optional[str] = None
    bindings: List[str] = field(default_factory=list)
    value: Optional[Expr] = None
    patterns: List["MatchPattern"] = field(default_factory=list)


@dataclass
class MatchArm(Node):
    """``pattern -> statement`` (or a block) inside a ``match``."""

    pattern: Optional[MatchPattern] = None
    body: Optional[Block] = None
    #: True for ``pattern -> expr`` (no braces).  Only such arms yield the
    #: enclosing function's result; a braced ``{ expr }`` arm is a statement.
    bare_expr: bool = False


@dataclass
class MatchStmt(Stmt):
    """``match subject { pattern -> ...  _ -> ... }``."""

    subject: Optional[Expr] = None
    arms: List[MatchArm] = field(default_factory=list)
