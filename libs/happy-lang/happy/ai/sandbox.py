"""Sandboxed execution for untrusted AI-generated code and tests.

The verification pipeline treats model output as hostile input.  Two of its
gates used to run that input with the *full* host interpreter:

* the candidate source itself (a ``"x".__class__.__mro__[1].__subclasses__()``
  expression reached ``subprocess.Popen`` and still verified APPROVED), and
* the ``tests { ... }`` block, which was written to a file and executed as
  ordinary Python with the whole environment inherited.

This module closes both holes with a defence-in-depth sandbox:

1. **Static scan** (:func:`scan_python`, :func:`scan_happy`) rejects dunder
   attribute access (``__class__``, ``__subclasses__``, ``__globals__`` \u2026),
   dangerous builtins (``eval``, ``exec``, ``open``, ``getattr`` \u2026) and
   imports of host-touching modules (``os``, ``subprocess``, ``socket`` \u2026).
2. **Restricted subprocess** (:func:`run_sandboxed_python`) executes the code
   with a curated ``__builtins__`` allow-list, an import hook that only permits
   a small set of pure modules, OS resource limits (CPU / address space /
   process count) and a wall-clock timeout.

Nothing here is a substitute for the real compiler gates \u2014 it is the last line
of defence for the two gates that must *execute* untrusted text.
"""

from __future__ import annotations

import ast
import os
import signal
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:  # pragma: no cover
    from .isolation import IsolationPolicy

__all__ = [
    "SandboxViolation",
    "scan_python",
    "scan_happy",
    "run_sandboxed_python",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "FORBIDDEN_ATTRS",
    "FORBIDDEN_NAMES",
    "FORBIDDEN_MODULES",
    "ALLOWED_MODULES",
]


class SandboxViolation(Exception):
    """Raised when untrusted code attempts an operation the sandbox forbids."""


#: Attribute names that expose the Python object graph (the classic escape).
FORBIDDEN_ATTRS = frozenset(
    {
        "__class__",
        "__bases__",
        "__base__",
        "__subclasses__",
        "__mro__",
        "__globals__",
        "__code__",
        "__closure__",
        "__dict__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__reduce__",
        "__reduce_ex__",
        "__init_subclass__",
        "__subclasshook__",
        "__loader__",
        "__builtins__",
        "__import__",
        "__spec__",
        "__module__",
        "__qualname__",
        "__func__",
        "__self__",
        "__wrapped__",
        "__objclass__",
        "__init__",
        "__new__",
        "__call__",
        "__get__",
        "__set__",
        "__delete__",
        "__annotations__",
        "__defaults__",
        "__kwdefaults__",
        "__name__",
        "__doc__",
        "__file__",
        "__path__",
        "__cached__",
        "__package__",
    }
)

#: Builtin names that can be abused to reach the object graph or the host.
FORBIDDEN_NAMES = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "compile",
        "open",
        "input",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "dir",
        "breakpoint",
        "memoryview",
        "object",
        "type",
        "super",
        "__builtins__",
        "__loader__",
        "__spec__",
        "help",
        "exit",
        "quit",
    }
)

#: Module roots that touch the host (filesystem, network, processes, \u2026).
FORBIDDEN_MODULES = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "shutil",
        "socket",
        "socketserver",
        "ctypes",
        "importlib",
        "builtins",
        "pickle",
        "marshal",
        "multiprocessing",
        "threading",
        "signal",
        "resource",
        "pty",
        "fcntl",
        "posix",
        "nt",
        "platform",
        "pathlib",
        "glob",
        "tempfile",
        "io",
        "gc",
        "inspect",
        "types",
        "operator",
        "functools",
        "runpy",
        "pkgutil",
        "site",
        "sysconfig",
        "traceback",
        "warnings",
        "weakref",
        "atexit",
        "faulthandler",
        "pdb",
        "bdb",
        "cmd",
        "code",
        "codeop",
        "asyncio",
        "concurrent",
        "select",
        "selectors",
        "mmap",
        "sqlite3",
        "webbrowser",
        "http",
        "urllib",
        "requests",
        "ssl",
        "telnetlib",
        "smtplib",
        "ftplib",
        "poplib",
        "imaplib",
        "nntplib",
        "xmlrpc",
        "cgi",
        "cgitb",
        "wsgiref",
        "venv",
        "zipimport",
        "distutils",
        "setuptools",
        "pip",
        "ensurepip",
        "lib2to3",
        "test",
        "unittest",
        "doctest",
        "pydoc",
        "compileall",
        "py_compile",
        "dis",
        "symtable",
        "tokenize",
        "keyword",
        "ast",
        "encodings",
        "codecs",
        "locale",
        "getpass",
        "shlex",
        "argparse",
        "logging",
        "configparser",
        "netrc",
        "xdrlib",
        "plistlib",
        "email",
        "mailbox",
        "mimetypes",
        "quopri",
        "uu",
        "binhex",
        "html",
        "xml",
        "dbm",
        "shelve",
        "pickletools",
        "copyreg",
        "cProfile",
        "profile",
        "stat",
        "errno",
        "getopt",
        "readline",
        "rlcompleter",
        "turtle",
        "tkinter",
        "zipfile",
        "tarfile",
        "gzip",
        "bz2",
        "lzma",
        "zlib",
        "csv",
        "struct",
        "binascii",
        "base64",
        "hashlib",
        "hmac",
        "secrets",
        "uuid",
        "random",
        "decimal",
        "fractions",
        "statistics",
        "datetime",
        "time",
        "calendar",
        "zoneinfo",
        "gettext",
        "unicodedata",
        "stringprep",
        "string",
        "re",
        "json",
        "math",
        "collections",
        "itertools",
        "heapq",
        "bisect",
        "array",
        "copy",
        "pprint",
        "reprlib",
        "enum",
        "numbers",
        "cmath",
        "contextlib",
        "dataclasses",
        "typing",
        "abc",
        "textwrap",
        "graphlib",
        "tomllib",
        "concurrent",
        "asyncio",
        "multiprocessing",
        "subprocess",
        "os",
        "sys",
    }
)

#: Pure modules the sandboxed test runner may import.
ALLOWED_MODULES = frozenset(
    {
        "math",
        "cmath",
        "json",
        "re",
        "random",
        "datetime",
        "collections",
        "itertools",
        "functools",
        "string",
        "decimal",
        "fractions",
        "statistics",
        "typing",
        "dataclasses",
        "enum",
        "abc",
        "copy",
        "heapq",
        "bisect",
        "array",
        "pprint",
        "reprlib",
        "numbers",
        "contextlib",
        "textwrap",
        "unicodedata",
        "operator",
        "uuid",
        "hashlib",
        "hmac",
        "base64",
        "binascii",
        "struct",
        "zlib",
        "gzip",
        "csv",
        "html",
        "graphlib",
        "tomllib",
    }
)


# ---------------------------------------------------------------------------
# Static scans
# ---------------------------------------------------------------------------
def _scan_ast(tree: ast.AST) -> List[str]:
    """Return a list of sandbox violations found in a Python AST."""
    violations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRS or node.attr.startswith("__"):
                violations.append(
                    f"forbidden attribute access '.{node.attr}'"
                )
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_NAMES:
                violations.append(f"forbidden name '{node.id}'")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES or root not in ALLOWED_MODULES:
                    violations.append(f"forbidden import '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_MODULES or root not in ALLOWED_MODULES:
                violations.append(f"forbidden import 'from {node.module}'")
    return violations


def scan_python(source: str) -> List[str]:
    """Statically scan Python ``source`` for sandbox violations.

    Returns a (possibly empty) list of human-readable violations.  A syntax
    error is itself reported as a violation so callers can reject cleanly.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"syntax error: {exc.msg}"]
    return _scan_ast(tree)


#: Textual dunder patterns that must never appear in a Happy candidate.
_HAPPY_DUNDER_TOKENS = (
    "__class__",
    "__bases__",
    "__base__",
    "__subclasses__",
    "__mro__",
    "__globals__",
    "__code__",
    "__closure__",
    "__dict__",
    "__builtins__",
    "__import__",
    "__reduce__",
    "__reduce_ex__",
    "__getattribute__",
    "__loader__",
    "__spec__",
)


def scan_happy(source: str) -> List[str]:
    """Statically scan Happy ``source`` for sandbox-escape attempts.

    Happy has no reflection primitives, so any dunder attribute access in the
    source is an attempt to reach the Python object graph through the backend.
    """
    violations: List[str] = []
    for token in _HAPPY_DUNDER_TOKENS:
        if token in source:
            violations.append(f"forbidden dunder access '{token}'")
    return violations


# ---------------------------------------------------------------------------
# Restricted subprocess execution
# ---------------------------------------------------------------------------
_RUNNER = r'''
import sys

_ALLOWED = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else set()

_NAMES = (
    "print", "len", "range", "str", "int", "float", "bool", "list", "dict",
    "set", "tuple", "frozenset", "bytes", "bytearray", "abs", "min", "max",
    "sum", "sorted", "enumerate", "zip", "map", "filter", "any", "all",
    "isinstance", "issubclass", "repr", "format", "round", "divmod", "pow",
    "chr", "ord", "hex", "oct", "bin", "hash", "id", "iter", "next",
    "reversed", "slice", "callable", "ascii", "True", "False", "None",
    "NotImplemented", "Ellipsis", "Exception", "BaseException", "ValueError",
    "TypeError", "KeyError", "IndexError", "RuntimeError", "StopIteration",
    "StopAsyncIteration", "ZeroDivisionError", "ArithmeticError",
    "AssertionError", "SystemExit", "AttributeError", "NameError",
    "NotImplementedError", "OverflowError", "LookupError", "UnicodeError",
    "UnicodeDecodeError", "UnicodeEncodeError", "FloatingPointError",
    "MemoryError", "RecursionError", "EOFError", "OSError", "IOError",
    "Warning", "UserWarning", "DeprecationWarning", "object", "type",
    "super", "classmethod", "staticmethod", "property", "__build_class__",
)

_SAFE = {}
for _n in _NAMES:
    try:
        _SAFE[_n] = getattr(__builtins__, _n)
    except Exception:
        pass

_real_import = getattr(__builtins__, "__import__")


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if root not in _ALLOWED:
        raise ImportError("import of %r is not permitted in the sandbox" % name)
    return _real_import(name, globals, locals, fromlist, level)


_SAFE["__import__"] = _safe_import
_SAFE["__builtins__"] = _SAFE

with open(sys.argv[1], "r", encoding="utf-8") as _fh:
    _code = _fh.read()
exec(compile(_code, "<sandbox>", "exec"), {"__name__": "__sandbox__", "__builtins__": _SAFE})
'''


def _limits(timeout: float):
    """Return a preexec_fn that applies OS resource limits (best effort)."""
    def _apply() -> None:  # pragma: no cover - runs in the child
        try:
            import resource

            cpu = int(timeout) + 2
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 2))
            mem = 512 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            except (ValueError, OSError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
            except (ValueError, OSError):
                pass
        except Exception:
            pass

    return _apply


#: Output budget for one sandboxed run (about 4 characters per token).
DEFAULT_MAX_OUTPUT_TOKENS = 2048
_TRUNCATION_MARK = "\n[output truncated: token limit reached]"


def _read_capped(path: str, max_chars: int) -> str:
    """Read at most ``max_chars`` characters of ``path`` (never the whole file)."""
    with open(path, "rb") as fh:
        raw = fh.read(max_chars * 4 + 1)  # UTF-8: <= 4 bytes per character
    text = raw.decode("utf-8", errors="replace")
    if len(text) > max_chars:
        keep = max(0, max_chars - len(_TRUNCATION_MARK))
        return text[:keep] + _TRUNCATION_MARK
    return text


def _kill_group(proc: "subprocess.Popen[bytes]") -> None:
    """Kill the child *and everything it spawned*."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        try:
            proc.kill()
        except OSError:  # pragma: no cover - already gone
            pass


def run_sandboxed_python(
    source: str,
    timeout: float = 30.0,
    python: Optional[str] = None,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    isolation: Optional["IsolationPolicy"] = None,
) -> Tuple[bool, str]:
    """Run ``source`` as Python inside a restricted subprocess.

    Returns ``(ok, output)``.  ``ok`` is False when the static scan rejects the
    code, the process times out, or it exits non-zero.

    Hard limits applied to every call: a wall-clock ``timeout`` (the whole
    process group is killed), OS CPU / memory / process / file-size limits, and
    an output budget of ``max_output_tokens`` -- output is written to files and
    read back capped, so a program that prints forever cannot exhaust the
    parent's memory or flood the model with tool output.

    ``isolation`` adds the kernel-enforced boundary (container / namespaces,
    see :mod:`happy.ai.isolation`).  By default the policy comes from the
    ``HAPPY_ISOLATION`` environment variable (``auto`` if unset): with
    ``required`` the run is *refused* when no OS-level backend is usable.
    """
    from .isolation import IsolationPolicy, IsolationUnavailable, select_backend

    violations = scan_python(source)
    if violations:
        return False, "sandbox violation: " + "; ".join(sorted(set(violations)))

    python = python or sys.executable
    max_chars = max(0, int(max_output_tokens)) * 4
    try:
        backend = select_backend(isolation or IsolationPolicy.from_env())
    except IsolationUnavailable as exc:
        return False, f"sandbox refused: {exc}"
    policy = isolation or IsolationPolicy.from_env()
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outdir:
        # The code directory is exposed read-only to the jail's unprivileged
        # user; captured output lives in a separate directory the jail never sees.
        os.chmod(tmp, 0o755)
        candidate = os.path.join(tmp, "candidate.py")
        runner = os.path.join(tmp, "_runner.py")
        out_path = os.path.join(outdir, "stdout.txt")
        err_path = os.path.join(outdir, "stderr.txt")
        for path, text in ((candidate, source), (runner, _RUNNER)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(path, 0o644)
        mods = ",".join(sorted(ALLOWED_MODULES))
        if backend is None:
            cmd = [python, "-I", "-S", runner, candidate, mods]
        else:
            cmd = backend.wrap(
                [python, "-I", "-S", "/work/_runner.py", "/work/candidate.py", mods],
                tmp, python, policy,
            )
        path_env = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"
        try:
            with open(out_path, "wb") as out_fh, open(err_path, "wb") as err_fh:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=out_fh,
                    stderr=err_fh,
                    cwd=tmp,
                    env={"PATH": path_env, "LC_ALL": "C.UTF-8",
                         "PYTHONIOENCODING": "utf-8"},
                    preexec_fn=_limits(timeout),
                    start_new_session=True,
                )
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    _kill_group(proc)
                    proc.wait()
                    return False, f"sandboxed run timed out after {timeout}s"
                finally:
                    _kill_group(proc)  # reap any grandchildren that outlived it
        except OSError as exc:  # pragma: no cover - defensive
            return False, f"sandboxed run failed to start: {exc}"
        finally:
            if backend is not None:
                backend.cleanup()
        output = _read_capped(out_path, max_chars) + _read_capped(err_path, max_chars)
        if len(output) > max_chars:
            output = output[: max(0, max_chars - len(_TRUNCATION_MARK))] + _TRUNCATION_MARK
        return proc.returncode == 0, output.strip()
