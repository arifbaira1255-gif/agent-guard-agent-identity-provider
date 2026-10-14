"""Dynamic contract evaluation for the Happy runtime.

Contracts are checked while the program runs, not just statically.  The Python
backend lowers every ``requires`` / ``ensures`` / ``invariant`` clause into a
call against the active :class:`ContractChecker`:

* preconditions run on entry to a function (``check_requires``);
* postconditions run immediately before each ``return`` with ``result`` bound
  to the returned value (``check_ensures``);
* type invariants run on entry and exit of the owning type's methods
  (``check_invariant``);
* rules evaluate their Bool predicate over named arguments
  (``check_rule``).

When a clause fails the checker raises the matching
:class:`~happy.runtime.errors.ContractViolation` subclass, resolved to the
``.hpy`` source location via the backend sourcemap, with the predicate text and
the offending values:

    demo.hpy:8:5: error: [R1003] contract violated in 'deposit': requires amount > 0.0
      8 |     requires amount > 0.0
        |     ^
      help: precondition evaluated to false

A :class:`ContractPolicy` controls the verdict: ``enforce`` (raise, default),
``warn`` (record and continue) or ``off`` (skip evaluation entirely).  The three
modes let production run without contract overhead while tests stay strict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .errors import (
    ContractViolation,
    InvariantViolation,
    PostconditionViolation,
    PreconditionViolation,
    RuleViolation,
)

__all__ = [
    "ContractPolicy",
    "ContractRecord",
    "ContractChecker",
    "ContractViolationInfo",
]


@dataclass
class ContractPolicy:
    """How the runtime reacts to a violated contract.

    ``mode`` is one of:

    * ``"enforce"`` — raise the appropriate violation (default);
    * ``"warn"`` — append a record to :attr:`ContractChecker.violations` and
      let execution continue;
    * ``"off"`` — do not evaluate contracts at all.
    """

    mode: str = "enforce"
    #: Emit per-clause trace records for inspection (useful in tests).
    trace: bool = False

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    @property
    def enabled(self) -> bool:
        return self.mode != "off"


@dataclass
class ContractRecord:
    """A single evaluated (and possibly violated) clause."""

    kind: str  # requires | ensures | invariant | rule
    owner: str
    predicate_text: str
    ok: bool
    message: Optional[str] = None
    location: Optional[object] = None


@dataclass
class ContractViolationInfo:
    """A recorded violation when the policy is ``warn``."""

    kind: str
    owner: str
    predicate_text: str
    message: Optional[str] = None
    location: Optional[object] = None


class ContractChecker:
    """Evaluates contracts dynamically on behalf of generated code."""

    _KIND_MAP = {
        "requires": PreconditionViolation,
        "ensures": PostconditionViolation,
        "invariant": InvariantViolation,
        "rule": RuleViolation,
    }

    def __init__(
        self,
        policy: Optional[ContractPolicy] = None,
        filename: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        self.policy = policy or ContractPolicy()
        self.filename = filename
        self.source = source
        self.records: List[ContractRecord] = []
        self.violations: List[ContractViolationInfo] = []

    # -- helpers --------------------------------------------------------
    def _fail(
        self,
        kind: str,
        owner: str,
        predicate_text: str,
        message: Optional[str],
        location: Any,
    ) -> None:
        info = ContractViolationInfo(
            kind=kind,
            owner=owner,
            predicate_text=predicate_text,
            message=message,
            location=location,
        )
        if self.policy.enforcing:
            cls = self._KIND_MAP.get(kind, ContractViolation)
            suggestion = {
                "requires": "precondition evaluated to false",
                "ensures": "postcondition evaluated to false on exit",
                "invariant": "a type invariant was broken",
                "rule": "a declared rule was violated",
            }.get(kind, "the contract was not satisfied")
            raise cls(
                message=(
                    f"contract violated in '{owner}': {kind} {predicate_text}"
                    + (f" ({message})" if message else "")
                ),
                location=location,
                filename=self.filename,
                source=self.source,
                suggestion=suggestion,
            )
        self.violations.append(info)

    def _record(
        self, kind: str, owner: str, predicate_text: str, ok: bool,
        message: Optional[str], location: Any,
    ) -> None:
        if self.policy.trace:
            self.records.append(
                ContractRecord(
                    kind=kind,
                    owner=owner,
                    predicate_text=predicate_text,
                    ok=ok,
                    message=message,
                    location=location,
                )
            )

    def _eval(self, predicate: Any) -> bool:
        """Coerce a predicate result to Bool with Happy's truthiness rules."""
        if predicate is None:
            return False
        return bool(predicate)

    # -- public API (called by generated code) --------------------------
    def check_requires(
        self,
        owner: str,
        predicate: Any,
        predicate_text: str = "",
        message: Optional[str] = None,
        location: Any = None,
    ) -> bool:
        """Evaluate a ``requires`` clause on function entry."""
        if not self.policy.enabled:
            return True
        ok = self._eval(predicate)
        self._record("requires", owner, predicate_text, ok, message, location)
        if not ok:
            self._fail("requires", owner, predicate_text, message, location)
        return ok

    def check_ensures(
        self,
        owner: str,
        predicate: Any,
        predicate_text: str = "",
        message: Optional[str] = None,
        location: Any = None,
    ) -> bool:
        """Evaluate an ``ensures`` clause with ``result`` already bound."""
        if not self.policy.enabled:
            return True
        ok = self._eval(predicate)
        self._record("ensures", owner, predicate_text, ok, message, location)
        if not ok:
            self._fail("ensures", owner, predicate_text, message, location)
        return ok

    def check_invariant(
        self,
        owner: str,
        predicate: Any,
        predicate_text: str = "",
        message: Optional[str] = None,
        location: Any = None,
    ) -> bool:
        """Evaluate a type invariant."""
        if not self.policy.enabled:
            return True
        ok = self._eval(predicate)
        self._record("invariant", owner, predicate_text, ok, message, location)
        if not ok:
            self._fail("invariant", owner, predicate_text, message, location)
        return ok

    def check_rule(
        self,
        owner: str,
        predicate: Any,
        predicate_text: str = "",
        message: Optional[str] = None,
        location: Any = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate a ``rule`` predicate over ``args``."""
        if not self.policy.enabled:
            return True
        ok = self._eval(predicate)
        text = predicate_text
        if args:
            joined = ", ".join(f"{k}={args[k]!r}" for k in sorted(args))
            text = f"{predicate_text} [{joined}]"
        self._record("rule", owner, text, ok, message, location)
        if not ok:
            self._fail("rule", owner, text, message, location)
        return ok

    # -- convenience ----------------------------------------------------
    def assert_predicate(
        self, owner: str, predicate: Any, message: Optional[str] = None,
        location: Any = None,
    ) -> None:
        """Raise a bare :class:`ContractViolation` when ``predicate`` is false."""
        if not self.policy.enabled:
            return
        if not self._eval(predicate):
            self._fail("requires", owner, "<expr>", message, location)

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        return (
            f"{len(self.records)} clause(s) traced, "
            f"{len(self.violations)} violation(s) (mode={self.policy.mode})"
        )
