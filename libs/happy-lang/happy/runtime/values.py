"""The Happy runtime value model.

Happy's data model is deliberately small and maps cleanly onto Python:

======================  ==========================================
Happy type              Runtime representation
======================  ==========================================
``Int`` / ``Byte``      :class:`int`
``Float``               :class:`float`
``String``              :class:`str`
``Bool``                :class:`bool`
``Char``                :class:`str` (length 1)
``Unit``                :data:`UNIT` (``None``)
``List<T>``             :class:`list`
``Map<K, V>``           :class:`dict`
``Set<T>``              :class:`set`
``Option<T>``           :class:`Option`
``Result<T, E>``        :class:`Result`
``Future<T>``           :class:`~happy.runtime.async_runtime.Task`
enum ``E``              :class:`HappyEnumValue`
struct ``S``            generated :class:`HappyStruct` subclass
``secret`` field        :class:`~happy.runtime.secrets.Secret`
======================  ==========================================

Two functions here matter to code generation:

* :func:`to_display` — the runtime ``str()``: it renders values for humans and
  is **secret-aware**, so a :class:`~happy.runtime.secrets.Secret` is redacted
  (or refused) instead of printed.
* :func:`deep_redact` — replaces secrets anywhere inside a nested value, used
  by ``repr`` and by the JSON encoder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .secrets import REDACTED, Secret, is_secret

__all__ = [
    "UNIT",
    "HappyStruct",
    "HappyEnumValue",
    "VariantCtor",
    "Option",
    "Result",
    "Ok",
    "Err",
    "Some",
    "NONE",
    "to_display",
    "deep_redact",
    "struct_field_names",
    # traits / interfaces (Step 7)
    "Trait",
    "TraitNotImplemented",
    "Display",
    "Debug",
    "Eq",
    "Ord",
    "Hash",
    "Iterator",
    # pattern matching (Step 7)
    "match_or",
    "match_variant_ctor",
    "match_payload",
    "match_field",
]


# ---------------------------------------------------------------------------
# Traits / interfaces (Step 7)
# ---------------------------------------------------------------------------
class TraitNotImplemented(Exception):
    """Raised when an abstract trait method with no implementation is called."""

    def __init__(self, trait: str, method: str) -> None:
        super().__init__(
            f"trait '{trait}' method '{method}' is not implemented"
        )
        self.trait = trait
        self.method = method


class Trait:
    """Base class for every Happy ``trait`` (interface).

    Generated types that implement a trait inherit from its class, so
    ``isinstance`` checks and default methods work exactly as the type system
    describes.
    """

    __happy_trait__ = True


#: The traits provided by the Happy standard library.  A program may implement
#: these without declaring them.
class Display(Trait):
    pass


class Debug(Trait):
    pass


class Eq(Trait):
    pass


class Ord(Trait):
    pass


class Hash(Trait):
    pass


class Iterator(Trait):
    pass


# ---------------------------------------------------------------------------
# Pattern matching helpers (Step 7)
# ---------------------------------------------------------------------------
def match_or(pattern: Any, subject: Any) -> bool:
    """Equality / membership test used by literal and ``|`` patterns."""
    if isinstance(pattern, (list, tuple, set, frozenset)):
        return any(subject == p for p in pattern)
    return subject == pattern


def match_variant_ctor(subject: Any, ctor: Any) -> bool:
    """True when ``subject`` is a value of the variant ``ctor``.

    Understands user enums as well as the built-in ``Option`` / ``Result``
    variants (``Some`` / ``NONE`` / ``Ok`` / ``Err``).
    """

    if isinstance(ctor, VariantCtor):
        if isinstance(subject, VariantCtor):
            # A nullary variant used as a value matches its own constructor.
            return subject.variant == ctor.variant and subject.enum == ctor.enum
        return (
            isinstance(subject, HappyEnumValue)
            and subject.variant == ctor.variant
            and subject.enum == ctor.enum
        )
    # Built-in Option / Result constructors.
    name = getattr(ctor, "__name__", None)
    if name == "Some":
        return isinstance(subject, Option) and subject.present
    if name == "Ok":
        return isinstance(subject, Result) and subject.is_ok
    if name == "Err":
        return isinstance(subject, Result) and not subject.is_ok
    if isinstance(ctor, Option):  # the NONE singleton
        return isinstance(subject, Option) and subject.present == ctor.present
    # Tolerate a bare enum value used as a pattern.
    return isinstance(subject, HappyEnumValue) and subject.variant == ctor


def match_payload(subject: Any, index: int) -> Any:
    """Return payload slot ``index`` of an enum / Option / Result value."""
    if isinstance(subject, HappyEnumValue) and 0 <= index < len(subject.payload):
        return subject.payload[index]
    if isinstance(subject, Option):
        return subject.value if index == 0 else None
    if isinstance(subject, Result):
        if index == 0:
            return subject.value if subject.is_ok else subject.error
        return None
    return None


def match_field(subject: Any, name: str) -> Any:
    """Read a struct field for a struct pattern (secret-aware safe access)."""
    if isinstance(subject, HappyStruct):
        for field in getattr(subject, "_happy_field_order", ()):
            if field == name:
                return getattr(subject, field)
    return getattr(subject, name, None)

#: The single inhabitant of the ``Unit`` type.
UNIT = None


# ---------------------------------------------------------------------------
# Structs
# ---------------------------------------------------------------------------
class HappyStruct:
    """Base class for every generated Happy ``type``.

    Generated subclasses declare:

    * ``_happy_type_name`` — the Happy type name (used by ``str`` / JSON);
    * ``_happy_field_order`` — field order for deterministic rendering;
    * ``_happy_secret_fields`` — names of ``secret`` fields (auto-wrapped).

    Instances are ordinary mutable Python objects, so ``account.balance = 1.0``
    maps directly onto attribute assignment.
    """

    _happy_type_name: str = "Struct"
    _happy_field_order: Tuple[str, ...] = ()
    _happy_secret_fields: Tuple[str, ...] = ()
    _happy_float_fields: Tuple[str, ...] = ()

    # -- mutation -------------------------------------------------------
    def __setattr__(self, name: str, value: Any) -> None:
        cls = type(self)
        if name in cls._happy_float_fields:
            value = to_float(value)
        if name in cls._happy_secret_fields:
            from .secrets import Secret
            from .context import _bind_secret_guard

            if not isinstance(value, Secret):
                value = Secret(value, label=name, guard=_bind_secret_guard())
        state = self.__dict__
        check = getattr(self, "__happy_invariant__", None)
        if check is None or not state.get("_happy_ready") or name not in cls._happy_field_order:
            object.__setattr__(self, name, value)
            return
        # Re-check invariants after a field write; roll back a failed write.
        had = name in state
        old = state.get(name)
        object.__setattr__(self, name, value)
        try:
            check()
        except BaseException:
            if had:
                object.__setattr__(self, name, old)
            else:
                state.pop(name, None)
            raise

    # -- construction ---------------------------------------------------
    def __init__(self, **fields: Any) -> None:
        # Fields absent from ``fields`` are left to the subclass's class-level
        # defaults: the backend emits a declared default (``active: Bool = true``)
        # as a class attribute, so it applies without being passed here.
        for fn in self._happy_field_order:
            if fn in fields:
                setattr(self, fn, fields[fn])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HappyStruct):
            return NotImplemented
        if self._happy_type_name != other._happy_type_name:
            return False
        return all(
            getattr(self, f, None) == getattr(other, f, None)
            for f in self._happy_field_order
        )

    def __hash__(self) -> int:  # pragma: no cover - mutable value objects
        return hash(self._happy_type_name)

    # -- rendering ------------------------------------------------------
    def __str__(self) -> str:
        parts = []
        for f in self._happy_field_order:
            v = getattr(self, f, None)
            if f in self._happy_secret_fields:
                parts.append(f"{f}: {REDACTED}")
            else:
                parts.append(f"{f}: {to_display(v)}")
        return f"{self._happy_type_name} {{ " + ", ".join(parts) + " }"

    def __repr__(self) -> str:  # pragma: no cover - mirrors __str__
        return self.__str__()


def to_float(value: Any) -> Any:
    """Widen a Happy ``Int`` to ``Float`` (``2`` -> ``2.0``).

    Lives in this module so that ``int`` is Python's ``int``: inside generated
    code ``int`` is rebound to Happy's ``int_`` builtin, so the check cannot be
    written there.  ``bool`` is excluded (it is a distinct Happy type).
    """
    if type(value) is int:
        return float(value)
    return value


def struct_field_names(value: HappyStruct) -> Tuple[str, ...]:
    """Return the declared field order of a struct instance."""
    return tuple(getattr(value, "_happy_field_order", ()))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HappyEnumValue:
    """A constructed enum variant, optionally carrying a payload."""

    enum: str = ""
    variant: str = ""
    payload: Tuple[Any, ...] = ()

    def __str__(self) -> str:
        if self.payload:
            inner = ", ".join(to_display(p) for p in self.payload)
            return f"{self.variant}({inner})"
        return self.variant

    def __repr__(self) -> str:  # pragma: no cover - mirrors __str__
        return self.__str__()


@dataclass(frozen=True)
class VariantCtor:
    """A callable / comparable constructor for one enum variant.

    The generated module binds each variant name at module scope, so source
    such as ``A(1)`` (constructor) and ``k == A`` (comparison) both work.
    """

    enum: str = ""
    variant: str = ""
    arity: int = 0

    def __call__(self, *args: Any) -> HappyEnumValue:
        if self.arity and len(args) != self.arity:
            raise TypeError(
                f"variant '{self.enum}::{self.variant}' expects {self.arity} "
                f"argument(s), got {len(args)}"
            )
        return HappyEnumValue(enum=self.enum, variant=self.variant, payload=tuple(args))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, VariantCtor):
            return self.enum == other.enum and self.variant == other.variant
        if isinstance(other, HappyEnumValue):
            return self.enum == other.enum and self.variant == other.variant
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.enum, self.variant))

    def __str__(self) -> str:  # pragma: no cover - mirror enum value
        return self.variant


# ---------------------------------------------------------------------------
# Option / Result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Option:
    """``Option<T>``: ``Some(value)`` or ``None``."""

    value: Any = None
    present: bool = False

    @property
    def is_some(self) -> bool:
        return self.present

    @property
    def is_none(self) -> bool:
        return not self.present

    def unwrap(self) -> Any:
        if not self.present:
            from .errors import HappyRuntimeError

            raise HappyRuntimeError(
                message="called unwrap() on a None Option", code="R4101"
            )
        return self.value

    def unwrap_or(self, default: Any) -> Any:
        return self.value if self.present else default

    def __str__(self) -> str:
        return f"Some({to_display(self.value)})" if self.present else "None"

    def __bool__(self) -> bool:
        return self.present


@dataclass(frozen=True)
class Result:
    """``Result<T, E>``: ``Ok(value)`` or ``Err(error)``."""

    value: Any = None
    error: Any = None
    is_ok: bool = True

    def unwrap(self) -> Any:
        if not self.is_ok:
            from .errors import HappyRuntimeError

            raise HappyRuntimeError(
                message=f"called unwrap() on Err({to_display(self.error)})",
                code="R4102",
            )
        return self.value

    def unwrap_or(self, default: Any) -> Any:
        return self.value if self.is_ok else default

    def unwrap_err(self) -> Any:
        if self.is_ok:
            from .errors import HappyRuntimeError

            raise HappyRuntimeError(
                message="called unwrap_err() on Ok", code="R4103"
            )
        return self.error

    def __str__(self) -> str:
        if self.is_ok:
            return f"Ok({to_display(self.value)})"
        return f"Err({to_display(self.error)})"

    def __bool__(self) -> bool:
        return self.is_ok


#: The empty ``Option`` singleton.
NONE = Option(value=None, present=False)


def Some(value: Any) -> Option:
    return Option(value=value, present=True)


def Ok(value: Any) -> Result:
    return Result(value=value, is_ok=True)


def Err(error: Any) -> Result:
    return Result(error=error, is_ok=False)


# ---------------------------------------------------------------------------
# Rendering helpers (secret-aware)
# ---------------------------------------------------------------------------
def _display_float(value: float) -> str:
    # Happy prints whole floats without a trailing ".0" only when the value is
    # integral AND came from an Int; floats always keep a decimal point so
    # ``1.0`` never renders as ``1``.
    return repr(value)


def to_display(value: Any) -> str:
    """Render ``value`` as Happy's ``str()`` would — redacting secrets."""
    if value is None:
        return "Unit"
    if isinstance(value, Secret):
        # Raises in strict mode, returns the marker otherwise.
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return _display_float(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, HappyEnumValue):
        return str(value)
    if isinstance(value, VariantCtor):
        return str(value)
    if isinstance(value, HappyStruct):
        return str(value)
    if isinstance(value, (Option, Result)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(to_display(v) for v in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ", ".join(f"{to_display(k)}: {to_display(v)}" for k, v in value.items())
            + "}"
        )
    if isinstance(value, set):
        return "{" + ", ".join(to_display(v) for v in sorted(value, key=str)) + "}"
    from .async_runtime import Task

    if isinstance(value, Task):
        return f"<task {value.name}>"
    return repr(value)


def deep_redact(value: Any) -> Any:
    """Return a copy of ``value`` with every secret replaced by its marker."""
    if isinstance(value, Secret):
        return REDACTED
    if isinstance(value, HappyStruct):
        out: Dict[str, Any] = {}
        for f in value._happy_field_order:
            v = getattr(value, f, None)
            out[f] = REDACTED if f in value._happy_secret_fields else deep_redact(v)
        return {value._happy_type_name: out}
    if isinstance(value, HappyEnumValue):
        return {
            value.variant: [deep_redact(p) for p in value.payload]
            if value.payload
            else None
        }
    if isinstance(value, Option):
        return {"Some": deep_redact(value.value)} if value.present else {"None": None}
    if isinstance(value, Result):
        if value.is_ok:
            return {"Ok": deep_redact(value.value)}
        return {"Err": deep_redact(value.error)}
    if isinstance(value, dict):
        return {deep_redact(k): deep_redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [deep_redact(v) for v in value]
    if isinstance(value, set):
        return [deep_redact(v) for v in sorted(value, key=str)]
    if isinstance(value, float):
        return value
    if isinstance(value, (int, bool, str)) or value is None:
        return value
    return repr(value)
