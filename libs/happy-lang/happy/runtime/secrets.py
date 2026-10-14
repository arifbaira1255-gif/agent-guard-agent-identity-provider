"""Secret protection for the Happy runtime.

A ``secret`` field (``secret pin: Byte``) holds data that must never escape the
program: it may not be printed, concatenated into strings, serialized to JSON,
logged, or have its raw value appear in ``repr`` / ``str`` / f-strings.

The protection is implemented with :class:`Secret`, a *tainted box* around a
value:

* :meth:`Secret.__str__` / :meth:`__repr__` render ``<secret ***>``;
* string concatenation and interpolation produce a redacted string;
* **attribute access to the box's internals is refused** \u2014 ``u.pin._value``
  raises instead of handing back the raw value;
* **equality against a plaintext is refused** \u2014 ``u.pin == "1234"`` raises
  instead of acting as a one-bit oracle an attacker can use to guess the
  secret;
* :meth:`reveal` is the single, explicit, audited escape hatch \u2014 it records a
  reveal in the :class:`SecretGuard` so operators can see who unmasked what.

By default the runtime is *strict*: an attempt to format a secret into a plain
string raises :class:`~happy.runtime.errors.SecretLeakError`.  A program may
opt into redaction mode (``HAPPY_SECRET_MODE=redact``) in which secrets simply
render as ``***`` instead of aborting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, List, Optional

from .errors import SecretLeakError

__all__ = ["Secret", "SecretGuard", "is_secret", "secret", "reveal"]

#: The string a redacted secret renders as.
REDACTED = "<secret ***>"


def _strict_default() -> bool:
    mode = os.environ.get("HAPPY_SECRET_MODE", "strict").strip().lower()
    return mode != "redact"


@dataclass
class RevealRecord:
    """An audit entry recording that a secret was explicitly revealed."""

    label: str
    reason: Optional[str]
    location: Optional[object] = None


@dataclass
class SecretGuard:
    """Tracks secret handling policy and reveal audit records."""

    strict: bool = field(default_factory=_strict_default)
    records: List[RevealRecord] = field(default_factory=list)

    def on_leak(self, label: str, location: Optional[object] = None) -> str:
        """Called when a secret is about to leak into a plain string.

        In strict mode this raises :class:`SecretLeakError`; otherwise the
        redaction marker is returned so execution can continue.
        """
        if self.strict:
            raise SecretLeakError(
                message=(
                    f"secret '{label}' leaked into a string / log; "
                    "call reveal() to access its value explicitly"
                ),
                location=location,
                suggestion="wrap the value with reveal(secret) where disclosure is intended",
            )
        return REDACTED

    def on_reveal(
        self, label: str, reason: Optional[str] = None, location: Optional[object] = None
    ) -> None:
        self.records.append(RevealRecord(label=label, reason=reason, location=location))

    @property
    def reveal_count(self) -> int:
        return len(self.records)


class Secret:
    """A tainted wrapper around a sensitive value.

    The wrapped value is only obtainable through :meth:`reveal`, which records
    the access on the active :class:`SecretGuard`.  Every other route to the
    raw value \u2014 attribute access to the box's internals, equality against a
    plaintext, string formatting, pickling \u2014 is refused.
    """

    __slots__ = ("_value", "_label", "_guard")

    def __init__(
        self, value: Any, label: str = "secret", guard: Optional[SecretGuard] = None
    ) -> None:
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_guard", guard)

    # -- internals are not reachable from Happy code --------------------
    def __getattribute__(self, name: str) -> Any:
        # ``u.pin._value`` (and any other underscore-prefixed internal) must
        # not hand back the raw value.  Internal methods read their own slots
        # through ``object.__getattribute__`` so they are unaffected.
        if name.startswith("_"):
            raise SecretLeakError(
                message=(
                    "secret internals are not accessible; "
                    "call reveal(secret) to access the value explicitly"
                ),
                suggestion="use reveal(secret) where disclosure is intended",
            )
        return object.__getattribute__(self, name)

    # -- classification -------------------------------------------------
    def __bool__(self) -> bool:
        # Secrets may participate in boolean tests without unmasking.
        return bool(object.__getattribute__(self, "_value"))

    def __eq__(self, other: object) -> bool:
        # Comparing a secret to anything is a disclosure attempt: it lets an
        # attacker confirm a guess one bit at a time.  Refuse it.
        raise SecretLeakError(
            message=(
                "a secret cannot be compared with '=='; "
                "call reveal(secret) to compare its value explicitly"
            ),
            suggestion="reveal(secret) == expected, where disclosure is intended",
        )

    def __ne__(self, other: object) -> bool:
        raise SecretLeakError(
            message=(
                "a secret cannot be compared with '!='; "
                "call reveal(secret) to compare its value explicitly"
            ),
            suggestion="reveal(secret) != expected, where disclosure is intended",
        )

    def __hash__(self) -> int:
        return hash((object.__getattribute__(self, "_label"), id(self)))

    # -- the one escape hatch ------------------------------------------
    def reveal(self, reason: Optional[str] = None) -> Any:
        """Return the raw wrapped value, recording the reveal."""
        guard = object.__getattribute__(self, "_guard")
        if guard is not None:
            guard.on_reveal(object.__getattribute__(self, "_label"), reason=reason)
        return object.__getattribute__(self, "_value")

    # -- redaction ------------------------------------------------------
    def __str__(self) -> str:
        guard = object.__getattribute__(self, "_guard")
        if guard is not None:
            return guard.on_leak(object.__getattribute__(self, "_label"))
        return REDACTED

    def __repr__(self) -> str:
        return REDACTED

    def __format__(self, spec: str) -> str:
        # f-strings route through __format__ \u2014 redact (or raise) here too.
        return str(self)

    def __add__(self, other: Any) -> str:
        # ``"x" + secret`` / ``secret + "x"`` must not leak.
        return str(self) + str(other)

    def __radd__(self, other: Any) -> str:
        return str(other) + str(self)

    def __reduce__(self):  # defensive: refuse to pickle secrets
        raise SecretLeakError(
            message=f"secret '{object.__getattribute__(self, '_label')}' cannot be serialized",
            suggestion="call reveal(secret) before persisting the value",
        )


def is_secret(value: Any) -> bool:
    """Return True when ``value`` is a :class:`Secret` anywhere in its shape."""
    if isinstance(value, Secret):
        return True
    if isinstance(value, dict):
        return any(is_secret(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_secret(v) for v in value)
    return False


def secret(value: Any, label: str = "secret", guard: Optional[SecretGuard] = None) -> Secret:
    """Wrap ``value`` in a :class:`Secret` (the ``secret(...)`` builtin)."""
    return Secret(value, label=label, guard=guard)


def reveal(value: Any, reason: Optional[str] = None) -> Any:
    """Unmask a :class:`Secret`, or pass a non-secret through unchanged."""
    if isinstance(value, Secret):
        return value.reveal(reason=reason)
    return value
