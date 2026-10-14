"""``std.process`` — capability-gated subprocess execution for Happy.

Running external programs is the most sensitive operation in Happy; it is
gated behind the ``process`` capability and never enabled by default.
"""

from __future__ import annotations

import sys
from typing import Any, List, Optional

from ..runtime.errors import HappyRuntimeError

__all__ = ["run", "run_args", "which", "exit", "argv", "use_checker", "PUBLIC"]

PUBLIC = ["run", "run_args", "which", "exit", "argv"]

_CHECKER: Any = None


def use_checker(checker: Any) -> None:
    global _CHECKER
    _CHECKER = checker


def _authorize(operation: str, loc: Optional[object] = None) -> None:
    if _CHECKER is None:
        return
    require = getattr(_CHECKER, "require_action", None)
    if callable(require):
        require(operation, loc=loc)
    else:  # pragma: no cover - alternate checker
        _CHECKER.check_operation(operation, loc=loc)


def run(command: str, timeout: Optional[float] = None) -> str:
    """Run ``command`` through the shell and return its stdout."""
    _authorize("process")
    import subprocess

    try:
        proc = subprocess.run(  # noqa: S602
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing
        raise HappyRuntimeError(message="process timed out", code="R5030") from exc
    if proc.returncode != 0:
        raise HappyRuntimeError(
            message=f"process exited with {proc.returncode}: {proc.stderr.strip()}",
            code="R5031",
        )
    return proc.stdout


def run_args(argv: List[str], timeout: Optional[float] = None) -> str:
    _authorize("process")
    import subprocess

    try:
        proc = subprocess.run(  # noqa: S603
            list(argv), capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        raise HappyRuntimeError(
            message=f"process failed: {exc}", code="R5032"
        ) from exc
    if proc.returncode != 0:
        raise HappyRuntimeError(
            message=f"process exited with {proc.returncode}", code="R5031"
        )
    return proc.stdout


def which(program: str) -> str:
    import shutil

    return shutil.which(program) or ""


def exit(code: int = 0) -> None:
    raise SystemExit(int(code))


def argv() -> List[str]:
    return list(sys.argv)
