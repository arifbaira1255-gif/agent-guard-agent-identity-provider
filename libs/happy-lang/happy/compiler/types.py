"""Static type system for the Happy language.

This module models Happy's **strong, static** type universe and provides the
primitives the semantic analyzer needs:

* the seven built-in primitives (``Int``, ``Float``, ``String``, ``Bool``,
  ``Byte``, ``Char``, ``Unit``);
* built-in generic containers (``Option<T>``, ``Result<T, E>``, ``List<T>``,
  ``Map<K, V>``, ``Set<T>``) plus user-declared generic parameters;
* nominal user types built from ``type`` (structs) and ``enum`` declarations;
* operations for **equality**, **assignability** (with subtyping) and
  **unification** (with substitutions) used by inference.

The design is intentionally small but principled.  Every :class:`Type` knows how
to render itself as Happy source (``__str__``) and how to compare structurally
(``__eq__``) unless it is *nominal* (structs/enums/classes compare by name).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Union

__all__ = [
    "Type",
    "PrimitiveType",
    "UnitType",
    "NeverType",
    "AnyType",
    "UnknownType",
    "TypeVar",
    "GenericInstance",
    "ListType",
    "SetType",
    "MapType",
    "OptionType",
    "ResultType",
    "FutureType",
    "StructType",
    "EnumType",
    "FunctionType",
    "TupleType",
    "TypeScheme",
    "Substitution",
    "PRIMITIVES",
    "PRIMITIVE_RANK",
    "is_primitive",
    "fresh_type_var",
    "unify",
    "apply_substitution",
    "UnificationError",
    "assignable",
    "common_supertype",
]

# ---------------------------------------------------------------------------
# Primitive catalogue
# ---------------------------------------------------------------------------
#: Nominal ordering used for *numeric widening*: Int -> Float (Int is assignable
#: to Float, never the other way round).  Everything else has rank 0.
PRIMITIVE_RANK: Dict[str, int] = {
    "Int": 1,
    "Byte": 0,
    "Char": 0,
    "Float": 2,
    "Bool": 0,
    "String": 0,
    "Unit": 0,
}

PRIMITIVES = frozenset(PRIMITIVE_RANK)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class Type:
    """Base class for every Happy type.

    Types are immutable value objects; helpers return *new* types rather than
    mutating in place.
    """

    __slots__ = ()

    #: Human readable name used in diagnostics.
    def display(self) -> str:  # pragma: no cover - overridden
        return str(self)

    def free_vars(self) -> List["TypeVar"]:
        """Return the unbound type variables occurring in this type."""
        return []

    def is_ground(self) -> bool:
        """A ground type contains no unbound type variables."""
        return not self.free_vars()

    def __eq__(self, other: object) -> bool:  # pragma: no cover - overridden
        return self is other

    def __hash__(self) -> int:  # pragma: no cover - overridden
        return id(self)


@dataclass(frozen=True)
class PrimitiveType(Type):
    """One of the built-in scalar types, e.g. ``Int`` or ``String``."""

    name: str = "Unit"

    def display(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PrimitiveType) and other.name == self.name

    def __hash__(self) -> int:
        return hash(("prim", self.name))


#: The singleton ``Unit`` type (the type of statements with no value).
UNIT = PrimitiveType("Unit")


@dataclass(frozen=True)
class UnitType(PrimitiveType):
    """Convenience subclass so ``UnitType()`` reads naturally in call sites."""

    name: str = "Unit"


@dataclass(frozen=True)
class NeverType(Type):
    """The bottom type: the type of ``return``/``break``/``continue``.

    ``Never`` is assignable to every other type, which is what makes control
    flow analysis (unreachable code detection) sound.
    """

    def display(self) -> str:
        return "Never"

    def __str__(self) -> str:
        return "Never"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NeverType)

    def __hash__(self) -> int:
        return hash("never")


NEVER = NeverType()


@dataclass(frozen=True)
class AnyType(Type):
    """The dynamic boundary type (opaque/FFI values, untyped ``ai`` results).

    ``Any`` is assignable both to and from every type so that boundaries with
    the outside world stay ergonomic without weakening the rest of the checker.
    """

    def display(self) -> str:
        return "Any"

    def __str__(self) -> str:
        return "Any"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AnyType)

    def __hash__(self) -> int:
        return hash("any")


ANY = AnyType()


@dataclass(frozen=True)
class UnknownType(Type):
    """The *error* type produced when a sub-expression could not be typed.

    ``Unknown`` is silently compatible with everything, which suppresses
    cascading "type mismatch" noise after a first real error has been reported.
    """

    def display(self) -> str:
        return "Unknown"

    def __str__(self) -> str:
        return "Unknown"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UnknownType)

    def __hash__(self) -> int:
        return hash("unknown")


UNKNOWN = UnknownType()


def is_primitive(t: Type) -> bool:
    """Return True when ``t`` is a built-in scalar type."""
    return isinstance(t, PrimitiveType)


# ---------------------------------------------------------------------------
# Type variables & generics
# ---------------------------------------------------------------------------
_tyvar_counter = 0


def fresh_type_var(hint: str = "T") -> "TypeVar":
    """Create a globally-unique type variable (used by inference)."""
    global _tyvar_counter
    _tyvar_counter += 1
    return TypeVar(name=f"{hint}{_tyvar_counter}")


@dataclass(frozen=True)
class TypeVar(Type):
    """An unbound type variable / generic parameter."""

    name: str = "T"

    def display(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def free_vars(self) -> List["TypeVar"]:
        return [self]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TypeVar) and other.name == self.name

    def __hash__(self) -> int:
        return hash(("var", self.name))


@dataclass(frozen=True)
class GenericInstance(Type):
    """An applied generic type, e.g. ``Option<Int>`` or ``Map<String, Int>``.

    User-declared generics (``type Box<T> { ... }``) and the built-in
    containers are both represented by this node; the built-ins have dedicated
    subclasses for readability.
    """

    name: str = ""
    args: Tuple[Type, ...] = ()

    def __init__(self, name: str, args: Sequence[Type] = ()) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "args", tuple(args))

    def display(self) -> str:
        if not self.args:
            return self.name
        return f"{self.name}<" + ", ".join(a.display() for a in self.args) + ">"

    def __str__(self) -> str:
        return self.display()

    def free_vars(self) -> List["TypeVar"]:
        out: List[TypeVar] = []
        for a in self.args:
            out.extend(a.free_vars())
        return out

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, GenericInstance)
            and other.name == self.name
            and other.args == self.args
        )

    def __hash__(self) -> int:
        return hash(("generic", self.name, self.args))


class ListType(GenericInstance):
    """``List<T>`` — an ordered, homogeneous sequence."""

    def __init__(self, element: Type) -> None:
        super().__init__("List", (element,))

    @property
    def element(self) -> Type:
        return self.args[0]


class SetType(GenericInstance):
    """``Set<T>`` — an unordered collection of unique elements."""

    def __init__(self, element: Type) -> None:
        super().__init__("Set", (element,))

    @property
    def element(self) -> Type:
        return self.args[0]


class MapType(GenericInstance):
    """``Map<K, V>`` — an associative container."""

    def __init__(self, key: Type, value: Type) -> None:
        super().__init__("Map", (key, value))

    @property
    def key(self) -> Type:
        return self.args[0]

    @property
    def value(self) -> Type:
        return self.args[1]


class OptionType(GenericInstance):
    """``Option<T>`` — an optional value (``Some(T)`` / ``None``)."""

    def __init__(self, inner: Type) -> None:
        super().__init__("Option", (inner,))

    @property
    def inner(self) -> Type:
        return self.args[0]


class ResultType(GenericInstance):
    """``Result<T, E>`` — a success value ``Ok(T)`` or failure ``Err(E)``."""

    def __init__(self, ok: Type, err: Type) -> None:
        super().__init__("Result", (ok, err))

    @property
    def ok(self) -> Type:
        return self.args[0]

    @property
    def err(self) -> Type:
        return self.args[1]


class FutureType(GenericInstance):
    """``Future<T>`` — the type produced by an ``async`` function."""

    def __init__(self, inner: Type) -> None:
        super().__init__("Future", (inner,))

    @property
    def inner(self) -> Type:
        return self.args[0]


# ---------------------------------------------------------------------------
# Nominal user types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StructType(Type):
    """A nominal ``type`` (struct) declared by the user."""

    name: str = ""
    fields: Tuple[Tuple[str, Type], ...] = ()
    generics: Tuple[str, ...] = ()
    is_secret: bool = False
    #: Names of fields flagged ``secret`` (used by capability/effect checks).
    secret_fields: Tuple[str, ...] = ()

    def __init__(
        self,
        name: str,
        fields: Sequence[Tuple[str, Type]] = (),
        generics: Sequence[str] = (),
        secret_fields: Sequence[str] = (),
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "fields", tuple(fields))
        object.__setattr__(self, "generics", tuple(generics))
        object.__setattr__(self, "secret_fields", tuple(secret_fields))

    def field_map(self) -> Dict[str, Type]:
        return dict(self.fields)

    def field_type(self, name: str) -> Optional[Type]:
        for fname, ftype in self.fields:
            if fname == name:
                return ftype
        return None

    def display(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def free_vars(self) -> List["TypeVar"]:
        out: List[TypeVar] = []
        for _, ftype in self.fields:
            out.extend(ftype.free_vars())
        return out

    def __eq__(self, other: object) -> bool:
        # Nominal: identity by name (and generic arity), not structural.
        return (
            isinstance(other, StructType)
            and other.name == self.name
            and len(other.generics) == len(self.generics)
        )

    def __hash__(self) -> int:
        return hash(("struct", self.name))


@dataclass(frozen=True)
class EnumType(Type):
    """A nominal ``enum`` declared by the user."""

    name: str = ""
    #: Variant name -> tuple of payload types.
    variants: Tuple[Tuple[str, Tuple[Type, ...]], ...] = ()
    generics: Tuple[str, ...] = ()

    def __init__(
        self,
        name: str,
        variants: Sequence[Tuple[str, Sequence[Type]]] = (),
        generics: Sequence[str] = (),
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(
            self, "variants", tuple((v, tuple(p)) for v, p in variants)
        )
        object.__setattr__(self, "generics", tuple(generics))

    def variant_names(self) -> List[str]:
        return [v for v, _ in self.variants]

    def variant_payload(self, name: str) -> Optional[Tuple[Type, ...]]:
        for vname, payload in self.variants:
            if vname == name:
                return payload
        return None

    def display(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, EnumType)
            and other.name == self.name
            and len(other.generics) == len(self.generics)
        )

    def __hash__(self) -> int:
        return hash(("enum", self.name))


# ---------------------------------------------------------------------------
# Compound structural types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FunctionType(Type):
    """The type of a function value: ``(P1, P2, ...) -> R``."""

    params: Tuple[Type, ...] = ()
    returns: Type = UNIT
    is_async: bool = False
    generics: Tuple[str, ...] = ()

    def __init__(
        self,
        params: Sequence[Type] = (),
        returns: Type = UNIT,
        is_async: bool = False,
        generics: Sequence[str] = (),
    ) -> None:
        object.__setattr__(self, "params", tuple(params))
        object.__setattr__(self, "returns", returns)
        object.__setattr__(self, "is_async", is_async)
        object.__setattr__(self, "generics", tuple(generics))

    def display(self) -> str:
        inner = ", ".join(p.display() for p in self.params)
        prefix = "async " if self.is_async else ""
        return f"{prefix}({inner}) -> {self.returns.display()}"

    def __str__(self) -> str:
        return self.display()

    def free_vars(self) -> List["TypeVar"]:
        out: List[TypeVar] = []
        for p in self.params:
            out.extend(p.free_vars())
        out.extend(self.returns.free_vars())
        return out

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, FunctionType)
            and other.params == self.params
            and other.returns == self.returns
        )

    def __hash__(self) -> int:
        return hash(("fn", self.params, self.returns))


@dataclass(frozen=True)
class TupleType(Type):
    """A fixed-size heterogeneous tuple ``(T1, T2, ...)``."""

    elements: Tuple[Type, ...] = ()

    def __init__(self, elements: Sequence[Type] = ()) -> None:
        object.__setattr__(self, "elements", tuple(elements))

    def display(self) -> str:
        return "(" + ", ".join(e.display() for e in self.elements) + ")"

    def __str__(self) -> str:
        return self.display()

    def free_vars(self) -> List["TypeVar"]:
        out: List[TypeVar] = []
        for e in self.elements:
            out.extend(e.free_vars())
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TupleType) and other.elements == self.elements

    def __hash__(self) -> int:
        return hash(("tuple", self.elements))


@dataclass(frozen=True)
class TypeScheme(Type):
    """A polymorphic type: ``for <vars>. <body>`` (used for generic functions)."""

    variables: Tuple[str, ...] = ()
    body: Type = UNIT

    def __init__(self, variables: Sequence[str] = (), body: Type = UNIT) -> None:
        object.__setattr__(self, "variables", tuple(variables))
        object.__setattr__(self, "body", body)

    def display(self) -> str:
        if not self.variables:
            return self.body.display()
        return f"<{', '.join(self.variables)}> {self.body.display()}"

    def __str__(self) -> str:
        return self.display()

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, TypeScheme)
            and other.variables == self.variables
            and other.body == self.body
        )

    def __hash__(self) -> int:
        return hash(("scheme", self.variables, self.body))


# ---------------------------------------------------------------------------
# Substitution & unification
# ---------------------------------------------------------------------------
class Substitution(dict):
    """A mapping from :class:`TypeVar` names to concrete types."""

    def __init__(self, *args, **kwargs) -> None:  # pragma: no cover - passthrough
        super().__init__(*args, **kwargs)

    def compose_into(self, other: "Substitution") -> "Substitution":
        """Return a new substitution combining ``self`` then ``other``."""
        merged = Substitution(self)
        for key, value in other.items():
            merged[key] = apply_substitution(value, self)
        return merged


class UnificationError(Exception):
    """Raised by :func:`unify` when two types cannot be made equal."""

    def __init__(self, left: Type, right: Type, reason: str = "") -> None:
        self.left = left
        self.right = right
        self.reason = reason
        detail = f"cannot unify {left.display()} with {right.display()}"
        if reason:
            detail += f": {reason}"
        super().__init__(detail)


def apply_substitution(t: Type, subst: Substitution) -> Type:
    """Return ``t`` with every bound type variable replaced per ``subst``."""
    if isinstance(t, TypeVar):
        seen = set()
        cur: Type = t
        while isinstance(cur, TypeVar) and cur.name in subst:
            if cur.name in seen:  # defensive: avoid cycles
                break
            seen.add(cur.name)
            cur = subst[cur.name]
        return cur

    if isinstance(t, GenericInstance):
        new_args = tuple(apply_substitution(a, subst) for a in t.args)
        if new_args == t.args:
            return t
        return _rebuild_generic(t, new_args)

    if isinstance(t, StructType):
        return t  # nominal, no structural substitution at this level

    if isinstance(t, EnumType):
        return t

    if isinstance(t, FunctionType):
        return FunctionType(
            [apply_substitution(p, subst) for p in t.params],
            apply_substitution(t.returns, subst),
            is_async=t.is_async,
            generics=t.generics,
        )

    if isinstance(t, TupleType):
        return TupleType([apply_substitution(e, subst) for e in t.elements])

    if isinstance(t, TypeScheme):
        inner = Substitution(
            {k: v for k, v in subst.items() if k not in t.variables}
        )
        return TypeScheme(t.variables, apply_substitution(t.body, inner))

    return t


def _rebuild_generic(original: GenericInstance, args: Tuple[Type, ...]) -> GenericInstance:
    """Rebuild a generic instance preserving its concrete subclass."""
    if isinstance(original, ListType):
        return ListType(args[0])
    if isinstance(original, SetType):
        return SetType(args[0])
    if isinstance(original, MapType):
        return MapType(args[0], args[1])
    if isinstance(original, OptionType):
        return OptionType(args[0])
    if isinstance(original, ResultType):
        return ResultType(args[0], args[1])
    if isinstance(original, FutureType):
        return FutureType(args[0])
    return GenericInstance(original.name, args)


def _occurs(var: "TypeVar", t: Type) -> bool:
    """Occurs check: does ``var`` appear inside ``t``?"""
    if isinstance(t, TypeVar):
        return t.name == var.name
    return any(_occurs(var, child) for child in _children(t))


def _children(t: Type) -> List[Type]:
    if isinstance(t, GenericInstance):
        return list(t.args)
    if isinstance(t, FunctionType):
        return list(t.params) + [t.returns]
    if isinstance(t, TupleType):
        return list(t.elements)
    if isinstance(t, StructType):
        return [ft for _, ft in t.fields]
    if isinstance(t, EnumType):
        return [pt for _, payload in t.variants for pt in payload]
    if isinstance(t, TypeScheme):
        return [t.body]
    return []


def unify(a: Type, b: Type, subst: Optional[Substitution] = None) -> Substitution:
    """Unify ``a`` with ``b``, returning the accumulated substitution.

    Unification is the engine of type inference: it makes two types equal by
    binding type variables.  ``Never`` (bottom) unifies with anything, which
    models divergent expressions.
    """
    if subst is None:
        subst = Substitution()

    a = apply_substitution(a, subst)
    b = apply_substitution(b, subst)

    if a == b:
        return subst

    if isinstance(a, TypeVar):
        return _bind(a, b, subst, a.name)
    if isinstance(b, TypeVar):
        return _bind(b, a, subst, b.name)

    # Bottom / dynamic / error types unify with anything.
    if isinstance(a, (NeverType, AnyType, UnknownType)) or isinstance(
        b, (NeverType, AnyType, UnknownType)
    ):
        return subst

    if isinstance(a, GenericInstance) and isinstance(b, GenericInstance):
        if a.name != b.name or len(a.args) != len(b.args):
            raise UnificationError(a, b, "different generic constructors")
        for x, y in zip(a.args, b.args):
            subst = unify(x, y, subst)
        return subst

    if isinstance(a, FunctionType) and isinstance(b, FunctionType):
        if len(a.params) != len(b.params):
            raise UnificationError(a, b, "different parameter counts")
        for x, y in zip(a.params, b.params):
            subst = unify(x, y, subst)
        return unify(a.returns, b.returns, subst)

    if isinstance(a, TupleType) and isinstance(b, TupleType):
        if len(a.elements) != len(b.elements):
            raise UnificationError(a, b, "different tuple arities")
        for x, y in zip(a.elements, b.elements):
            subst = unify(x, y, subst)
        return subst

    # Numeric widening: Int/Byte unify *with* Float by promoting to Float.
    if _is_numeric(a) and _is_numeric(b):
        promoted = _numeric_join(a, b)
        if promoted is not None:
            return subst

    raise UnificationError(a, b)


def _bind(var: TypeVar, t: Type, subst: Substitution, name: str) -> Substitution:
    if isinstance(t, TypeVar) and t.name == name:
        return subst
    if _occurs(var, t):
        raise UnificationError(var, t, "infinite type (occurs check failed)")
    subst[name] = t
    return subst


def _is_numeric(t: Type) -> bool:
    return isinstance(t, PrimitiveType) and t.name in ("Int", "Float", "Byte")


def _numeric_join(a: Type, b: Type) -> Optional[str]:
    assert isinstance(a, PrimitiveType) and isinstance(b, PrimitiveType)
    if a.name == b.name:
        return a.name
    if "Float" in (a.name, b.name):
        return "Float"
    if {a.name, b.name} == {"Int", "Byte"}:
        return "Int"
    return None


# ---------------------------------------------------------------------------
# Assignability / subtyping
# ---------------------------------------------------------------------------
def assignable(source: Type, target: Type, subst: Optional[Substitution] = None) -> bool:
    """Return True if a value of type ``source`` may be used where ``target`` is expected.

    Rules
    -----
    * identical types are assignable;
    * ``Never`` is assignable to everything;
    * numeric widening ``Int -> Float`` (and ``Byte -> Int -> Float``) is allowed;
    * ``Option<Never>`` (i.e. ``None``) is assignable to any ``Option<T>``;
    * ``List<A>``/``Set<A>``/``Option<A>``/``Result<A, E>`` are *covariant* in
      their value position (``List<Int> -> List<Float>`` is fine);
    * ``FunctionType`` is contravariant in parameters, covariant in the result;
    * structs/enums are nominal: names must match exactly.
    """
    if subst is None:
        subst = Substitution()

    source = apply_substitution(source, subst)
    target = apply_substitution(target, subst)

    if source == target:
        return True

    if isinstance(source, (NeverType, AnyType, UnknownType)) or isinstance(
        target, (TypeVar, AnyType, UnknownType)
    ):
        return True
    if isinstance(source, TypeVar):
        # An unbound variable is assumed compatible (inference fills it in).
        return True

    if isinstance(source, PrimitiveType) and isinstance(target, PrimitiveType):
        if source.name == target.name:
            return True
        if target.name == "Float" and PRIMITIVE_RANK.get(source.name, 0) >= 1:
            return True  # Int/Byte widen to Float
        if target.name == "Int" and source.name == "Byte":
            return True  # Byte widens to Int
        return False

    if isinstance(source, GenericInstance) and isinstance(target, GenericInstance):
        if source.name != target.name or len(source.args) != len(target.args):
            return False
        if source.name in ("List", "Set", "Option", "Future"):
            return assignable(source.args[0], target.args[0], subst)
        if source.name == "Result":
            return assignable(source.args[0], target.args[0], subst) and assignable(
                source.args[1], target.args[1], subst
            )
        if source.name == "Map":
            # Maps are invariant in the key, covariant in the value.
            return source.args[0] == target.args[0] and assignable(
                source.args[1], target.args[1], subst
            )
        return source.args == target.args

    if isinstance(source, StructType) and isinstance(target, StructType):
        return source.name == target.name

    if isinstance(source, EnumType) and isinstance(target, EnumType):
        return source.name == target.name

    if isinstance(source, FunctionType) and isinstance(target, FunctionType):
        if len(source.params) != len(target.params):
            return False
        for sp, tp in zip(source.params, target.params):
            if not assignable(tp, sp, subst):  # contravariant parameters
                return False
        return assignable(source.returns, target.returns, subst)

    if isinstance(source, TupleType) and isinstance(target, TupleType):
        if len(source.elements) != len(target.elements):
            return False
        return all(
            assignable(s, t, subst) for s, t in zip(source.elements, target.elements)
        )

    return False


def common_supertype(a: Type, b: Type) -> Optional[Type]:
    """Return the least common supertype of ``a`` and ``b`` (or ``None``).

    Used for type inference of ``if``/``match`` branches and list literals.
    """
    if a == b:
        return a
    if isinstance(a, NeverType):
        return b
    if isinstance(b, NeverType):
        return a
    if isinstance(a, AnyType) or isinstance(b, AnyType):
        return ANY
    if isinstance(a, UnknownType) or isinstance(b, UnknownType):
        return UNKNOWN
    if isinstance(a, PrimitiveType) and isinstance(b, PrimitiveType):
        joined = _numeric_join(a, b)
        if joined:
            return PrimitiveType(joined)
        return None
    if isinstance(a, GenericInstance) and isinstance(b, GenericInstance):
        if a.name == b.name and len(a.args) == len(b.args):
            if a.name in ("List", "Set", "Option", "Future"):
                inner = common_supertype(a.args[0], b.args[0])
                if inner is None:
                    return None
                return _rebuild_generic(a, (inner,))
            if a.name == "Result":
                ok = common_supertype(a.args[0], b.args[0])
                err = common_supertype(a.args[1], b.args[1])
                if ok is None or err is None:
                    return None
                return ResultType(ok, err)
        return None
    if isinstance(a, StructType) and isinstance(b, StructType):
        return a if a.name == b.name else None
    if isinstance(a, EnumType) and isinstance(b, EnumType):
        return a if a.name == b.name else None
    # Anything joins with Unit only via widening in specific call sites.
    if assignable(a, b):
        return b
    if assignable(b, a):
        return a
    return None
