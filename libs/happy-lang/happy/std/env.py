"""``std.env`` — environment and process-argument access for Happy."""

from __future__ import annotations

import os
from typing import Any, Dict, List

from ..runtime.errors import HappyRuntimeError

__all__ = [
    "get",
    "get_or",
    "has",
    "set_var",
    "unset",
    "all_vars",
    "args",
    "platform",
    "use_checker",
    "PUBLIC",
]

PUBLIC = ["get", "get_or", "has", "set_var", "unset", "all_vars", "args", "platform"]

_CHECKER: Any = None


def use_checker(checker: Any) -> None:
    global _CHECKER
    _CHECKER = checker


def _authorize(operation: str, loc=None) -> None:
    """Authorise an environment operation against the active capability checker.

    Environment variables routinely hold API keys and other credentials, so
    reading or mutating them is a *sensitive* operation: it is gated exactly
    like file and process access.  The check is **fail-closed** — with no
    checker installed the operation is refused rather than silently allowed.
    """
    if _CHECKER is None:
        raise HappyRuntimeError(
            message=(
                f"environment operation '{operation}' is not permitted: no "
                "capability checker is active"
            ),
            code="R2001",
            suggestion=(
                "run the program through the Happy runtime, or grant an 'env' "
                "capability to the agent performing the operation"
            ),
        )
    require = getattr(_CHECKER, "require_action", None)
    if callable(require):
        require(operation, loc=loc)
    else:  # pragma: no cover - alternate checker
        _CHECKER.check_operation(operation, loc=loc)


def get(name: str) -> str:
    _authorize("env")
    value = os.environ.get(name)
    if value is None:
        raise HappyRuntimeError(
            message=f"environment variable '{name}' is not set", code="R5040"
        )
    return value


def get_or(name: str, default: str = "") -> str:
    _authorize("env")
    return os.environ.get(name, default)


def has(name: str) -> bool:
    _authorize("env")
    return name in os.environ


def set_var(name: str, value: str) -> None:
    _authorize("env")
    os.environ[name] = value


def unset(name: str) -> None:
    _authorize("env")
    os.environ.pop(name, None)


def all_vars() -> Dict[str, str]:
    _authorize("env")
    return dict(os.environ)


def args() -> List[str]:
    import sys

    return list(sys.argv[1:])


def platform() -> str:
    import sys

    return sys.platform
