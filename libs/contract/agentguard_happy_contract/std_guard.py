"""Fail-closed capability guard for Happy LANG's ``std`` modules.

THE BYPASS THIS CLOSES
----------------------
Happy LANG's ``std`` modules gate sensitive operations through a module-level checker:

    def _authorize(operation, loc=None):
        if _CHECKER is None:
            return                      # <-- silently ALLOWS when no checker is installed
        _CHECKER.check_operation(operation, loc=loc)

``happy/std/fs.py``, ``net.py``, ``io.py`` and ``crypto.py`` all behave this way (``env.py`` is
already fail-closed).  So any code path that reaches ``std.fs.read_file`` *outside* a
``RuntimeContext`` -- a REPL, a helper, a future caller -- performs the operation with **no
check at all**.  That is the residual bypass the Step 1 audit flagged.

THE FIX (at the integration layer, never by editing Happy LANG)
--------------------------------------------------------------
:func:`install_std_guard` points every ``std`` module at a **deny-by-default** checker, so
``_CHECKER`` is never ``None`` while the integration is active and an unlisted operation is
*refused* rather than allowed.  :func:`uninstall_std_guard` restores the previous state, so the
integration can be switched off without leaving Happy LANG altered.

This is a *language-level* fence.  It is a correctness control, not a security boundary -- the
boundary is the OS jail in :mod:`agentguard_happy_contract.isolation`.  Both are applied.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

__all__ = [
    "DenyByDefaultChecker",
    "StaticAllowlistChecker",
    "install_std_guard",
    "uninstall_std_guard",
    "std_guard_installed",
    "STD_MODULES",
]

#: The ``happy.std`` submodules that expose a ``use_checker`` hook.
STD_MODULES = ("io", "fs", "net", "process", "env", "crypto")

_lock = threading.RLock()
_previous: Dict[str, Any] = {}
_installed = False


def _deny(operation: str) -> Exception:
    """Build the same error type Happy LANG's own checker raises (code ``R2001``)."""
    try:
        from happy.runtime.errors import HappyRuntimeError

        return HappyRuntimeError(
            message=(f"operation '{operation}' is not permitted: no capability was granted for it"),
            code="R2001",
            suggestion="declare the capability in the program and have AgentGuard authorize it")
    except Exception:                                           # noqa: BLE001 - Happy absent
        return PermissionError(f"operation '{operation}' is not permitted")


class DenyByDefaultChecker:
    """A checker that refuses **everything** unless the operation is explicitly allowed.

    Implements both hooks Happy LANG's ``std`` modules look for (``check_operation`` and
    ``require_action``), so it works whichever one a given module calls.
    """

    def __init__(self, allowed: Iterable[str] = ()) -> None:
        self.allowed: Set[str] = {str(a) for a in allowed}
        self.checks = 0
        self.denials = 0
        self._lock = threading.Lock()

    def allow(self, *operations: str) -> None:
        with self._lock:
            self.allowed.update(str(o) for o in operations)

    def _check(self, operation: str) -> None:
        with self._lock:
            self.checks += 1
            permitted = operation in self.allowed
            if not permitted:
                self.denials += 1
        if not permitted:
            raise _deny(operation)

    # Happy LANG's std modules call one of these two.
    def check_operation(self, operation: str, agent: Any = None, loc: Any = None) -> None:
        self._check(operation)

    def require_action(self, action: str, agent: Any = None, loc: Any = None) -> bool:
        self._check(action)
        return True

    @property
    def ok(self) -> bool:
        return self.denials == 0

    def summary(self) -> str:
        return f"deny-by-default: {self.checks} check(s), {self.denials} denial(s)"


class StaticAllowlistChecker(DenyByDefaultChecker):
    """A checker built from a pre-authorized operation list (used inside the jail).

    The control plane authorizes the declared resources *before* the program is jailed; the worker
    then enforces exactly that list locally.  The jail has no network, so it cannot consult
    AgentGuard -- and it must not need to: anything not pre-authorized is refused here.
    """

    def __init__(self, allowed: Iterable[str] = (), *, correlation_id: Optional[str] = None) -> None:
        super().__init__(allowed)
        self.correlation_id = correlation_id


def _std_modules() -> Tuple[Any, ...]:
    """Import and return the ``happy.std`` submodules that expose ``use_checker``.

    ``happy.std`` does not import its submodules eagerly, so they are imported explicitly here --
    otherwise the guard would silently cover nothing.
    """
    from importlib import import_module

    modules: List[Any] = []
    for name in STD_MODULES:
        try:
            modules.append(import_module(f"happy.std.{name}"))
        except Exception:                                       # noqa: BLE001 - module absent
            modules.append(None)
    return tuple(modules)


def install_std_guard(allowed: Iterable[str] = ()) -> DenyByDefaultChecker:
    """Install a deny-by-default checker into every ``happy.std`` module.

    Idempotent: calling it twice keeps the first checker (and its allowlist) rather than silently
    widening or narrowing the policy mid-run.
    """
    global _installed
    with _lock:
        if _installed:
            return _previous.get("__checker__")
        checker = DenyByDefaultChecker(allowed)
        for name, module in zip(STD_MODULES, _std_modules()):
            if module is None or not hasattr(module, "use_checker"):
                continue
            _previous[name] = getattr(module, "_CHECKER", None)
            module.use_checker(checker)
        _previous["__checker__"] = checker
        _installed = True
        return checker


def uninstall_std_guard() -> bool:
    """Restore the ``std`` modules' previous checkers (used when the integration is disabled)."""
    global _installed
    with _lock:
        if not _installed:
            return False
        for name, module in zip(STD_MODULES, _std_modules()):
            if module is None or not hasattr(module, "use_checker"):
                continue
            module.use_checker(_previous.get(name))
        _previous.clear()
        _installed = False
        return True


def std_guard_installed() -> bool:
    """True when a guard is currently installed (i.e. ``_CHECKER`` is never ``None``)."""
    with _lock:
        return _installed
