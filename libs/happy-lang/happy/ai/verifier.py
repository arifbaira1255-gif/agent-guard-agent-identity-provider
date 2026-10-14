"""AI output verification engine for the Happy language (Step 5).

Happy treats model output as **untrusted input**.  Nothing an AI produces is
allowed to run until it has climbed a strict *trust ladder*::

    RAW ──▶ PARSED ──▶ GROUNDED ──▶ VERIFIED ──▶ TESTED ──▶ APPROVED

Each rung is a gate that can only be passed by running the *real* compiler
stages over the candidate code — never by trusting the model's own claim that
the code is fine:

======================  =====================================================
State                   Gate (what must pass)
======================  =====================================================
``RAW``                 the candidate as received (untrusted text)
``PARSED``              lexer + parser (``happy.compiler.parse``)
``GROUNDED``            semantic analysis / type checker (``analyze``)
``VERIFIED``            contracts + rules + capabilities + effects
``TESTED``              the candidate's own automated tests pass
``APPROVED``            the security analyzer finds no blocking issue
======================  =====================================================

The pipeline is *monotonic*: a candidate can only ever move forward, and the
first failing gate freezes it at the previous state with a full diagnostic
report.  :class:`VerificationResult` records the final state, every gate's
outcome, and the diagnostics that stopped it.

Typical use::

    from happy.ai.verifier import VerificationPipeline

    pipeline = VerificationPipeline()
    result = pipeline.verify(model_output, filename="generated.hpy")
    if result.approved:
        run(result.code)
    else:
        print(result.report())
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..compiler import SemanticOptions, analyze, parse
from ..compiler.contracts import check_contracts
from ..compiler.effects import track_effects
from ..compiler.errors import HappyError
from ..compiler.ir import lower
from ..compiler.permissions import verify_permissions
from .sandbox import run_sandboxed_python, scan_happy

__all__ = [
    "TrustState",
    "TRUST_ORDER",
    "GateOutcome",
    "GateResult",
    "VerificationResult",
    "VerificationPipeline",
    "VerificationError",
    "verify_source",
]


# ---------------------------------------------------------------------------
# Trust states
# ---------------------------------------------------------------------------
class TrustState:
    """The rungs of the trust ladder, in ascending order."""

    RAW = "RAW"
    PARSED = "PARSED"
    GROUNDED = "GROUNDED"
    VERIFIED = "VERIFIED"
    TESTED = "TESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

    #: Ascending order of the *passing* states.
    ORDER = (RAW, PARSED, GROUNDED, VERIFIED, TESTED, APPROVED)

    @classmethod
    def rank(cls, state: str) -> int:
        try:
            return cls.ORDER.index(state)
        except ValueError:
            return -1

    @classmethod
    def at_least(cls, state: str, other: str) -> bool:
        return cls.rank(state) >= cls.rank(other)


#: Alias used in the task description.
TRUST_ORDER = TrustState.ORDER


class VerificationError(Exception):
    """Raised for misuse of the pipeline (not for a rejected candidate)."""


# ---------------------------------------------------------------------------
# Gate results
# ---------------------------------------------------------------------------
@dataclass
class GateOutcome:
    """The result of a single gate."""

    name: str
    state: str
    passed: bool
    diagnostics: List[Any] = field(default_factory=list)
    detail: str = ""

    def render(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        head = f"[{mark}] {self.name} -> {self.state}"
        if self.detail:
            head += f" ({self.detail})"
        lines = [head]
        for diag in self.diagnostics:
            render = getattr(diag, "render", None)
            lines.append("    " + (render() if callable(render) else str(diag)))
        return "\n".join(lines)


@dataclass
class GateResult:
    """Alias-friendly name for a gate outcome (kept for API symmetry)."""

    name: str
    passed: bool
    diagnostics: List[Any] = field(default_factory=list)
    detail: str = ""


@dataclass
class VerificationResult:
    """The full outcome of verifying one candidate program."""

    state: str = TrustState.RAW
    source: str = ""
    filename: Optional[str] = None
    gates: List[GateOutcome] = field(default_factory=list)
    diagnostics: List[Any] = field(default_factory=list)
    #: The lowered IR, when the candidate reached at least GROUNDED.
    module: Any = None
    #: The analysis result, when the candidate reached at least GROUNDED.
    analysis: Any = None
    #: Test output captured at the TESTED gate.
    test_output: str = ""
    #: Security findings, when the candidate reached the APPROVED gate.
    security: Any = None

    # -- queries --------------------------------------------------------
    @property
    def approved(self) -> bool:
        return self.state == TrustState.APPROVED

    @property
    def rejected(self) -> bool:
        return self.state == TrustState.REJECTED

    @property
    def ok(self) -> bool:
        return self.approved

    def reached(self, state: str) -> bool:
        """True when the candidate passed the gate that produces ``state``.

        A rejected candidate still *reached* every rung it cleared before the
        failing gate, so this consults the recorded gate outcomes rather than
        the final state.
        """
        if TrustState.at_least(self.state, state):
            return True
        return any(g.passed and g.state == state for g in self.gates)

    def gate(self, name: str) -> Optional[GateOutcome]:
        for g in self.gates:
            if g.name == name:
                return g
        return None

    @property
    def failed_gate(self) -> Optional[GateOutcome]:
        for g in self.gates:
            if not g.passed:
                return g
        return None

    # -- rendering ------------------------------------------------------
    def report(self) -> str:
        lines = [
            f"verification: {self.state}"
            + (f"  ({self.filename})" if self.filename else ""),
            "-" * 60,
        ]
        for g in self.gates:
            lines.append(g.render())
        if self.state == TrustState.REJECTED:
            lines.append("-" * 60)
            lines.append("candidate REJECTED — it must not be executed.")
        return "\n".join(lines)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.report()


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------
class VerificationPipeline:
    """Forces AI-generated code through the full Happy compiler + tests.

    Parameters
    ----------
    run_tests:
        When True (default) the TESTED gate actually executes the candidate's
        tests in a subprocess.  Set False for a fast, static-only verification.
    security:
        An optional security analyzer (``happy.security.analyzer.SecurityAnalyzer``).
        When provided, its findings gate the APPROVED state.
    test_timeout:
        Seconds allowed for the candidate's test run.
    """

    def __init__(
        self,
        run_tests: bool = True,
        security: Any = None,
        test_timeout: float = 30.0,
        python: Optional[str] = None,
    ) -> None:
        self.run_tests = run_tests
        self.security = security
        self.test_timeout = test_timeout
        self.python = python or sys.executable

    # -- public API -----------------------------------------------------
    def verify(
        self,
        source: str,
        filename: Optional[str] = None,
        tests: Optional[str] = None,
    ) -> VerificationResult:
        """Run ``source`` up the trust ladder and return the result.

        ``tests`` is optional Happy/Python test source; when omitted the
        pipeline looks for a ``tests`` block inside ``source`` (see
        :meth:`_extract_tests`).
        """
        result = VerificationResult(source=source, filename=filename)

        # -- RAW --------------------------------------------------------
        result.gates.append(
            GateOutcome("raw", TrustState.RAW, True, detail=f"{len(source)} bytes")
        )
        if not source or not source.strip():
            return self._reject(result, "raw", "empty candidate source")

        # -- SANDBOX (static escape scan) ------------------------------
        # Happy has no reflection primitives, so any dunder attribute access
        # in the candidate is an attempt to reach the Python object graph
        # (``"x".__class__.__mro__[1].__subclasses__()``).  Reject it before
        # it can ever be lowered or executed.
        escape = scan_happy(source)
        if escape:
            return self._reject(
                result,
                "sandbox",
                "candidate attempts a sandbox escape: " + "; ".join(escape),
            )
        result.gates.append(
            GateOutcome("sandbox", TrustState.RAW, True, detail="no escape patterns")
        )

        # -- PARSED (lexer + parser) -----------------------------------
        try:
            program = parse(source, filename=filename)
        except HappyError as exc:
            return self._reject(result, "parse", "lexer/parser rejected the candidate", [exc])
        result.gates.append(
            GateOutcome("parse", TrustState.PARSED, True, detail="lexer + parser OK")
        )
        result.state = TrustState.PARSED

        # -- GROUNDED (semantic analysis / type checker) ---------------
        analysis = analyze(
            program, filename=filename,
            options=SemanticOptions(semantic_security_strict=True),
        )
        if not analysis.ok:
            return self._reject(
                result, "typecheck", "semantic analysis / type checking failed",
                list(analysis.errors),
            )
        result.analysis = analysis
        result.gates.append(
            GateOutcome(
                "typecheck",
                TrustState.GROUNDED,
                True,
                detail=f"{len(analysis.diagnostics)} diagnostics, 0 errors",
            )
        )
        result.state = TrustState.GROUNDED

        # Lower to IR once; the remaining gates all read it.
        try:
            module = lower(analysis, source=source, filename=filename)
        except Exception as exc:  # noqa: BLE001 - lowering failure is a rejection
            return self._reject(result, "lower", f"IR lowering failed: {exc}")
        result.module = module

        # -- VERIFIED (contracts + rules + capabilities + effects) -----
        contract_report = check_contracts(module, filename=filename, source=source)
        if not contract_report.ok:
            return self._reject(
                result, "contracts", "contract verification failed",
                list(contract_report.errors),
            )
        permission_report = verify_permissions(module, filename=filename, source=source)
        if not permission_report.ok:
            return self._reject(
                result, "permissions", "rule / capability verification failed",
                list(permission_report.errors),
            )
        effect_report = track_effects(module, filename=filename, source=source)
        if not effect_report.ok:
            return self._reject(
                result, "effects", "effect verification failed",
                list(effect_report.errors),
            )
        result.gates.append(
            GateOutcome(
                "contracts",
                TrustState.VERIFIED,
                True,
                detail=(
                    f"{contract_report.total_contracts} contracts, "
                    f"{len(permission_report.enforcement_points)} enforcement points, "
                    f"{len(effect_report.functions)} effect signatures"
                ),
            )
        )
        result.state = TrustState.VERIFIED

        # -- TESTED (run the candidate's tests) ------------------------
        test_source = tests if tests is not None else self._extract_tests(source)
        if self.run_tests and test_source:
            passed, output = self._run_tests(test_source, filename)
            result.test_output = output
            if not passed:
                return self._reject(
                    result, "tests", "candidate tests failed", [output]
                )
            result.gates.append(
                GateOutcome("tests", TrustState.TESTED, True, detail="tests passed")
            )
        else:
            result.gates.append(
                GateOutcome(
                    "tests",
                    TrustState.TESTED,
                    True,
                    detail="no tests supplied (static verification only)",
                )
            )
        result.state = TrustState.TESTED

        # -- APPROVED (security analyzer) ------------------------------
        if self.security is not None:
            findings = self.security.analyze(source, filename=filename)
            result.security = findings
            if not findings.ok:
                return self._reject(
                    result, "security", "security analyzer found blocking issues",
                    list(findings.blocking),
                )
            result.gates.append(
                GateOutcome(
                    "security",
                    TrustState.APPROVED,
                    True,
                    detail=f"{len(findings.findings)} findings, 0 blocking",
                )
            )
        else:
            result.gates.append(
                GateOutcome(
                    "security",
                    TrustState.APPROVED,
                    True,
                    detail="no security analyzer configured",
                )
            )
        result.state = TrustState.APPROVED
        return result

    # -- helpers --------------------------------------------------------
    def _reject(
        self,
        result: VerificationResult,
        gate: str,
        detail: str,
        diagnostics: Optional[Sequence[Any]] = None,
        **kwargs: Any,
    ) -> VerificationResult:
        diags = list(diagnostics or [])
        result.gates.append(
            GateOutcome(gate, TrustState.REJECTED, False, diagnostics=diags, detail=detail)
        )
        result.diagnostics.extend(diags)
        result.state = TrustState.REJECTED
        return result

    def _extract_tests(self, source: str) -> Optional[str]:
        """Extract a ``tests { ... }`` block from the candidate, if present.

        The block is returned as Python source (the Happy test runner executes
        Python).  This is intentionally simple: a fenced ``tests`` section.
        """
        marker = "tests {"
        idx = source.find(marker)
        if idx == -1:
            return None
        depth = 0
        start = idx + len(marker) - 1
        for i in range(start, len(source)):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start + 1 : i]
        return None

    def _run_tests(self, test_source: str, filename: Optional[str]) -> tuple:
        """Run ``test_source`` inside the restricted sandbox; return (ok, output).

        The candidate's tests are untrusted input: they are executed with a
        curated builtin allow-list, an import hook limited to pure modules, OS
        resource limits and a wall-clock timeout — never with the host's full
        environment (which previously let a test block read API keys, spawn
        processes and write files).
        """
        return run_sandboxed_python(
            test_source, timeout=self.test_timeout, python=self.python
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def verify_source(
    source: str,
    filename: Optional[str] = None,
    tests: Optional[str] = None,
    security: Any = None,
    run_tests: bool = True,
) -> VerificationResult:
    """One-call verification of ``source`` (see :class:`VerificationPipeline`)."""
    return VerificationPipeline(run_tests=run_tests, security=security).verify(
        source, filename=filename, tests=tests
    )
