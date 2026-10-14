"""``std.fs`` — capability-gated filesystem operations for Happy.

Read-only inspection is gated by ``file_read``; anything that modifies the
filesystem requires ``file_write``.  Path manipulation helpers are pure.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, List, Optional

from ..runtime.errors import HappyRuntimeError

__all__ = [
    "list_dir",
    "make_dir",
    "remove_file",
    "remove_dir",
    "copy_file",
    "move_file",
    "exists",
    "is_dir",
    "is_file",
    "path_join",
    "basename",
    "dirname",
    "extension",
    "cwd",
    "abs_path",
    "size",
    "use_checker",
    "PUBLIC",
]

PUBLIC = [
    "list_dir",
    "make_dir",
    "remove_file",
    "remove_dir",
    "copy_file",
    "move_file",
    "exists",
    "is_dir",
    "is_file",
    "path_join",
    "basename",
    "dirname",
    "extension",
    "cwd",
    "abs_path",
    "size",
]

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


def list_dir(path: str = ".") -> List[str]:
    _authorize("file_read")
    try:
        return sorted(os.listdir(path))
    except OSError as exc:
        raise HappyRuntimeError(
            message=f"list_dir failed: {exc}", code="R5020"
        ) from exc


def make_dir(path: str, recursive: bool = True) -> str:
    _authorize("file_write")
    if recursive:
        os.makedirs(path, exist_ok=True)
    else:
        os.mkdir(path)
    return path


def remove_file(path: str) -> None:
    _authorize("file_write")
    os.remove(path)


def remove_dir(path: str, recursive: bool = False) -> None:
    _authorize("file_write")
    if recursive:
        shutil.rmtree(path)
    else:
        os.rmdir(path)


def copy_file(src: str, dst: str) -> str:
    _authorize("file_read")
    _authorize("file_write")
    shutil.copy2(src, dst)
    return dst


def move_file(src: str, dst: str) -> str:
    _authorize("file_read")
    _authorize("file_write")
    shutil.move(src, dst)
    return dst


def exists(path: str) -> bool:
    _authorize("file_read")
    return os.path.exists(path)


def is_dir(path: str) -> bool:
    _authorize("file_read")
    return os.path.isdir(path)


def is_file(path: str) -> bool:
    _authorize("file_read")
    return os.path.isfile(path)


def size(path: str) -> int:
    _authorize("file_read")
    return os.path.getsize(path)


# -- pure path helpers -------------------------------------------------
def path_join(*parts: str) -> str:
    return os.path.join(*parts)


def basename(path: str) -> str:
    return os.path.basename(path)


def dirname(path: str) -> str:
    return os.path.dirname(path)


def extension(path: str) -> str:
    return os.path.splitext(path)[1]


def cwd() -> str:
    return os.getcwd()


def abs_path(path: str) -> str:
    return os.path.abspath(path)
