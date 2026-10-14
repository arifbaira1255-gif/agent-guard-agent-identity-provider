"""Lexical scoping and symbol tables for the Happy language.

The symbol table is the semantic analyzer's memory.  It models **lexical
scopes** (module, function, block, struct, enum, agent, ai) as a tree of linked
:class:`Scope` objects:

* :meth:`SymbolTable.lookup` walks outward through parent scopes, which gives
  classic lexical-scoping resolution;
* :meth:`Scope.define` detects **shadowing**;
* every :class:`Symbol` remembers whether it was declared with ``let`` or
  ``var``, so assignment to an immutable binding can be **rejected**;
* binding *use* is tracked so the analyzer can report **unused variables**.

Modules and imports
-------------------
A :class:`SymbolTable` also records what a module exports and what it imports,
so the analyzer can resolve `import a.b` / `import { X } from "m"` and flag
unknown or private symbols.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional

from .errors import HappyError, SourceLocation, format_diagnostic


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ScopeError(HappyError):
    """Base class for scope / binding errors (error code family ``E3xxx``)."""

    code = "E3001"

    def render(self) -> str:
        return format_diagnostic(
            f"[{self.code}] {self.message}",
            location=self.location,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )


class ImmutableBindingError(ScopeError):
    """Raised when assigning to a ``let`` binding."""

    code = "E3006"


class DuplicateDefinitionError(ScopeError):
    """Raised when the same name is defined twice in one scope."""

    code = "E3002"


class UnknownSymbolError(ScopeError):
    """Raised when a name cannot be resolved in any enclosing scope."""

    code = "E3001"


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------
class SymbolKind(Enum):
    """What a name refers to."""

    VARIABLE = "variable"
    PARAMETER = "parameter"
    CONSTANT = "constant"
    FUNCTION = "function"
    TYPE = "type"          # struct (``type``)
    ENUM = "enum"
    ENUM_VARIANT = "enum_variant"
    FIELD = "field"
    MODULE = "module"
    IMPORT = "import"
    PERMISSION = "permission"
    CAPABILITY = "capability"
    AGENT = "agent"
    AI = "ai"
    RULE = "rule"
    EFFECT = "effect"


#: Kinds whose name lives in the *value* namespace.
VALUE_KINDS = frozenset(
    {
        SymbolKind.VARIABLE,
        SymbolKind.PARAMETER,
        SymbolKind.CONSTANT,
        SymbolKind.FUNCTION,
    }
)

#: Kinds whose name lives in the *type* namespace.
TYPE_KINDS = frozenset(
    {SymbolKind.TYPE, SymbolKind.ENUM}
)


@dataclass
class Symbol:
    """A single named entity in a scope."""

    name: str
    kind: SymbolKind
    type: object = None  # happy.compiler.types.Type | None (set by analyzer)
    mutable: bool = False
    declared_at: Optional[SourceLocation] = None
    scope: Optional["Scope"] = None
    secret: bool = False
    exported: bool = False
    #: For imports: the module it originated from.
    origin: Optional[str] = None
    #: Book-keeping for "unused variable" analysis.
    used: bool = False
    #: Whether the symbol may legally be unused (params, public decls, ``_``).
    ignore_unused: bool = False
    detail: str = ""

    def mark_used(self) -> None:
        self.used = True

    @property
    def is_immutable(self) -> bool:
        return not self.mutable

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        t = f": {self.type}" if self.type is not None else ""
        mut = "var" if self.mutable else "let"
        return f"{self.kind.value} {self.name}{t} ({mut})"


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
@dataclass
class ImportedSymbol:
    """A symbol brought into a module through an ``import`` statement."""

    local_name: str
    origin_module: str
    original_name: Optional[str] = None  # None => whole-module import
    loc: Optional[SourceLocation] = None


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
class ScopeKind(Enum):
    MODULE = "module"
    FUNCTION = "function"
    BLOCK = "block"
    STRUCT = "struct"
    ENUM = "enum"
    AGENT = "agent"
    AI = "ai"
    LOOP = "loop"
    IMPORT = "import"


@dataclass
class Scope:
    """A lexical scope: a mapping of names to :class:`Symbol` objects."""

    kind: ScopeKind
    name: str = ""
    parent: Optional["Scope"] = None
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    children: List["Scope"] = field(default_factory=list)
    #: Set when the scope is a module; names exported from it.
    exports: set = field(default_factory=set)
    #: Imports declared in this scope (module scope only, normally).
    imports: Dict[str, ImportedSymbol] = field(default_factory=dict)
    scope_id: int = 0

    # -- definition ----------------------------------------------------
    def define(
        self,
        name: str,
        kind: SymbolKind,
        *,
        type: object = None,
        mutable: bool = False,
        loc: Optional[SourceLocation] = None,
        secret: bool = False,
        exported: bool = False,
        origin: Optional[str] = None,
        ignore_unused: bool = False,
        detail: str = "",
        allow_redefine: bool = False,
    ) -> Symbol:
        """Define ``name`` in this scope and return the created symbol.

        Redefining a name in the *same* scope is an error unless
        ``allow_redefine`` is set (used for forward references).  Shadowing a
        name from an *outer* scope is permitted and recorded via
        :attr:`Symbol.shadows`.
        """
        existing = self.symbols.get(name)
        if existing is not None and not allow_redefine:
            raise DuplicateDefinitionError(
                f"'{name}' is already defined in this scope "
                f"(as a {existing.kind.value})",
                location=loc,
                suggestion=(
                    "choose a different name, or remove the previous definition"
                ),
            )

        sym = Symbol(
            name=name,
            kind=kind,
            type=type,
            mutable=mutable,
            declared_at=loc,
            scope=self,
            secret=secret,
            exported=exported,
            origin=origin,
            ignore_unused=ignore_unused,
            detail=detail,
        )
        sym.shadows = self._find_outer(name)  # type: ignore[attr-defined]
        self.symbols[name] = sym
        return sym

    def _find_outer(self, name: str) -> Optional[Symbol]:
        outer = self.parent
        while outer is not None:
            if name in outer.symbols:
                return outer.symbols[name]
            outer = outer.parent
        return None

    # -- lookup --------------------------------------------------------
    def lookup_local(self, name: str) -> Optional[Symbol]:
        return self.symbols.get(name)

    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up ``name`` in this scope and every enclosing scope."""
        scope: Optional[Scope] = self
        while scope is not None:
            sym = scope.symbols.get(name)
            if sym is not None:
                return sym
            scope = scope.parent
        return None

    def require(self, name: str, loc: Optional[SourceLocation] = None) -> Symbol:
        """Return the symbol for ``name`` or raise :class:`UnknownSymbolError`."""
        sym = self.lookup(name)
        if sym is None:
            raise UnknownSymbolError(
                f"unknown name '{name}'",
                location=loc,
                suggestion="check the spelling or declare it before use",
            )
        return sym

    # -- introspection -------------------------------------------------
    def all_symbols(self, recursive: bool = False) -> Iterator[Symbol]:
        yield from self.symbols.values()
        if recursive:
            for child in self.children:
                yield from child.all_symbols(recursive=True)

    def local_names(self) -> List[str]:
        return list(self.symbols.keys())

    def depth(self) -> int:
        d = 0
        scope: Optional[Scope] = self.parent
        while scope is not None:
            d += 1
            scope = scope.parent
        return d

    def is_module_scope(self) -> bool:
        return self.kind is ScopeKind.MODULE

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scope {self.kind.value}{' ' + self.name if self.name else ''} @{self.scope_id}>"


# ---------------------------------------------------------------------------
# Symbol table
# ---------------------------------------------------------------------------
class SymbolTable:
    """Owns the scope tree and the operations the analyzer needs."""

    def __init__(self) -> None:
        self.module_scope = Scope(ScopeKind.MODULE, name="<module>", scope_id=0)
        self._scope = self.module_scope
        self._counter = 1
        self._current_function: Optional[Symbol] = None
        self._function_stack: List[Symbol] = []

    # -- scope stack ---------------------------------------------------
    @property
    def current_scope(self) -> Scope:
        return self._scope

    def push_scope(self, kind: ScopeKind, name: str = "") -> Scope:
        scope = Scope(kind, name=name, parent=self._scope, scope_id=self._counter)
        self._counter += 1
        self._scope.children.append(scope)
        self._scope = scope
        return scope

    def pop_scope(self) -> Scope:
        scope = self._scope
        if scope.parent is not None:
            self._scope = scope.parent
        return scope

    def at_module_scope(self) -> bool:
        return self._scope is self.module_scope

    # -- definition / lookup ------------------------------------------
    def define(self, name: str, kind: SymbolKind, **kwargs) -> Symbol:
        return self._scope.define(name, kind, **kwargs)

    def lookup(self, name: str) -> Optional[Symbol]:
        return self._scope.lookup(name)

    def lookup_local(self, name: str) -> Optional[Symbol]:
        return self._scope.lookup_local(name)

    def require(self, name: str, loc: Optional[SourceLocation] = None) -> Symbol:
        return self._scope.require(name, loc)

    # -- mutability enforcement ---------------------------------------
    def check_assignment(self, sym: Symbol, loc: Optional[SourceLocation] = None) -> None:
        """Reject assignment to an immutable (``let``) binding.

        Raises :class:`ImmutableBindingError` when ``sym`` was declared with
        ``let`` (or is otherwise immutable, e.g. a constant or a function).
        """
        if not sym.mutable:
            kind_word = "let" if sym.kind is SymbolKind.VARIABLE else sym.kind.value
            raise ImmutableBindingError(
                f"cannot assign to immutable binding '{sym.name}' "
                f"(declared with '{kind_word}')",
                location=loc,
                suggestion=(
                    f"declare it with 'var {sym.name} = ...' if it must be mutable"
                ),
            )

    # -- function context ---------------------------------------------
    def enter_function(self, sym: Symbol) -> None:
        self._function_stack.append(sym)
        self._current_function = sym

    def exit_function(self) -> None:
        if self._function_stack:
            self._function_stack.pop()
        self._current_function = self._function_stack[-1] if self._function_stack else None

    @property
    def current_function(self) -> Optional[Symbol]:
        return self._current_function

    # -- imports / exports --------------------------------------------
    def add_import(self, imported: ImportedSymbol) -> None:
        self.module_scope.imports[imported.local_name] = imported

    def lookup_import(self, name: str) -> Optional[ImportedSymbol]:
        return self.module_scope.imports.get(name)

    def mark_export(self, name: str) -> None:
        self.module_scope.exports.add(name)

    def is_exported(self, name: str) -> bool:
        return name in self.module_scope.exports

    # -- traversal helpers --------------------------------------------
    def all_symbols(self) -> Iterator[Symbol]:
        """Yield every symbol in the whole tree (module-first)."""
        yield from self.module_scope.all_symbols(recursive=True)

    def unused_symbols(self) -> List[Symbol]:
        """Return local variables/constants that were never read."""
        out: List[Symbol] = []
        for sym in self.all_symbols():
            if sym.kind not in (SymbolKind.VARIABLE, SymbolKind.CONSTANT):
                continue
            if sym.ignore_unused or sym.used or sym.name == "_":
                continue
            out.append(sym)
        return out

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SymbolTable scopes={self._counter}>"
