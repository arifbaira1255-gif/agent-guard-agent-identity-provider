"""OS-level isolation for untrusted AI-generated code.

``happy.ai.sandbox`` restricts *what Python can do* (AST scan, builtins
allow-list).  That is a language-level fence and, on its own, not a security
boundary.  This module adds the boundary the kernel enforces: the untrusted
process runs inside a container or a set of Linux namespaces where

* there is **no network** (own, empty network namespace),
* the root filesystem is **read-only** and contains only the interpreter --
  host files (``/etc``, ``/home``, secrets, other tenants' data) do not exist,
* it only sees **its own processes** (own PID namespace),
* it runs as an **unprivileged user** with every Linux capability dropped and
  ``no_new_privs`` set,
* the **whole process tree** dies on timeout.

Backends, in order of preference (``auto``):

``docker`` / ``podman``  container with ``--network none --read-only
                         --cap-drop ALL --pids-limit --memory --cpus``
                         plus the runtime's default seccomp profile.
``bwrap``                bubblewrap (what Flatpak uses); rootless.
``namespaces``           raw ``unshare`` + private mount tree + ``chroot``;
                         needs root *or* unprivileged user namespaces.

Modes (``IsolationPolicy.mode`` or the ``HAPPY_ISOLATION`` env variable):

``required``  fail **closed**: if no backend is usable the run is refused.
``auto``      use the best available backend, fall back to the language-level
              sandbox only (reported via :func:`isolation_status`).
``off``       language-level sandbox only -- development use, never for
              untrusted input in production.

Run ``python -m happy.ai.isolation`` to see what this host supports and to run
an escape self-test (host file read, network, write to rootfs, PID visibility,
privilege level) against the selected backend.
"""

from __future__ import annotations

import abc
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "IsolationPolicy",
    "IsolationUnavailable",
    "Backend",
    "available_backends",
    "select_backend",
    "isolation_status",
    "self_test",
]

#: Unprivileged identity the workload runs as inside the jail ("nobody").
_NOBODY = 65534
_VALID_MODES = ("required", "auto", "off")
_VALID_BACKENDS = ("auto", "docker", "podman", "bwrap", "namespaces")


class IsolationUnavailable(RuntimeError):
    """Raised when ``mode='required'`` and no backend can be used."""


@dataclass(frozen=True)
class IsolationPolicy:
    """What the jail allows.  The defaults are the strictest useful ones."""

    mode: str = "auto"
    backend: str = "auto"
    #: Container image used by the docker/podman backends.
    image: str = "python:3.12-slim"
    memory_mb: int = 256
    cpus: float = 1.0
    max_pids: int = 32
    tmpfs_mb: int = 16
    #: Network is always off; kept as a field so audits can see it is False.
    network: bool = False

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise ValueError(f"isolation mode must be one of {_VALID_MODES}")
        if self.backend not in _VALID_BACKENDS:
            raise ValueError(f"isolation backend must be one of {_VALID_BACKENDS}")
        if self.network:
            raise ValueError("network access is never granted to sandboxed code")

    @classmethod
    def from_env(cls, **overrides: object) -> "IsolationPolicy":
        """Policy from ``HAPPY_ISOLATION`` / ``HAPPY_ISOLATION_BACKEND`` / ``..._IMAGE``."""
        values: Dict[str, object] = {}
        mode = os.environ.get("HAPPY_ISOLATION")
        if mode:
            values["mode"] = mode.strip().lower()
        backend = os.environ.get("HAPPY_ISOLATION_BACKEND")
        if backend:
            values["backend"] = backend.strip().lower()
        image = os.environ.get("HAPPY_ISOLATION_IMAGE")
        if image:
            values["image"] = image.strip()
        values.update(overrides)
        return cls(**values)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Python interpreter layout (which host directories the jail must expose)
# --------------------------------------------------------------------------
def _interpreter_dirs(python: str) -> Tuple[str, List[str]]:
    """Return ``(real_python_path, read-only host dirs needed to run it)``."""
    real = os.path.realpath(python)
    dirs = ["/usr"]
    for cand in (os.path.realpath(sys.base_prefix), os.path.dirname(real)):
        if cand in ("/", ""):
            continue
        if not any(cand == d or cand.startswith(d + os.sep) for d in dirs):
            dirs.append(cand)
    return real, dirs


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------
class Backend(abc.ABC):
    """A way to run one command inside a kernel-enforced jail."""

    name = "base"

    @abc.abstractmethod
    def available(self) -> Tuple[bool, str]:
        ...

    @abc.abstractmethod
    def wrap(
        self, argv: Sequence[str], workdir: str, python: str, policy: IsolationPolicy
    ) -> List[str]:
        """Return the host command that runs ``argv`` jailed.

        ``workdir`` is mounted **read-only** at ``/work`` inside the jail and
        ``argv`` must refer to files there (``/work/...``).  ``python`` is the
        interpreter to use; it is rewritten as needed.
        """
        ...

    def cleanup(self) -> None:
        """Called after the run (and after a timeout kill)."""


class _ContainerBackend(Backend):
    def __init__(self, engine: str) -> None:
        self.name = engine
        self.engine = engine
        self._container: Optional[str] = None

    def available(self) -> Tuple[bool, str]:
        exe = shutil.which(self.engine)
        if not exe:
            return False, f"{self.engine} not installed"
        try:
            probe = subprocess.run(
                [exe, "info"], capture_output=True, timeout=10, stdin=subprocess.DEVNULL
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{self.engine} not usable: {exc}"
        if probe.returncode != 0:
            return False, f"{self.engine} daemon not reachable"
        return True, exe

    def wrap(self, argv, workdir, python, policy):
        exe = shutil.which(self.engine) or self.engine
        self._container = f"happy-sbx-{uuid.uuid4().hex[:12]}"
        # Inside the image the interpreter is simply ``python``.
        inner = ["python" if a == python else a for a in argv]
        return [
            exe, "run", "--rm", "--name", self._container,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(policy.max_pids),
            "--memory", f"{policy.memory_mb}m",
            "--memory-swap", f"{policy.memory_mb}m",
            "--cpus", str(policy.cpus),
            "--user", f"{_NOBODY}:{_NOBODY}",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_mb}m",
            "-v", f"{workdir}:/work:ro",
            "-w", "/work",
            "--env", "HOME=/tmp",
            policy.image,
            *inner,
        ]

    def cleanup(self) -> None:
        # Killing the CLI client does NOT stop the container: remove it.
        if self._container:
            exe = shutil.which(self.engine) or self.engine
            try:
                subprocess.run(
                    [exe, "rm", "-f", self._container],
                    capture_output=True, timeout=15, stdin=subprocess.DEVNULL,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            self._container = None


class _BwrapBackend(Backend):
    name = "bwrap"

    def available(self) -> Tuple[bool, str]:
        exe = shutil.which("bwrap")
        if not exe:
            return False, "bwrap (bubblewrap) not installed"
        try:
            probe = subprocess.run(
                [exe, "--unshare-all", "--ro-bind", "/", "/", "true"],
                capture_output=True, timeout=10, stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"bwrap not usable: {exc}"
        if probe.returncode != 0:
            return False, "bwrap cannot create namespaces here"
        return True, exe

    def wrap(self, argv, workdir, python, policy):
        exe = shutil.which("bwrap") or "bwrap"
        real, dirs = _interpreter_dirs(python)
        cmd = [
            exe, "--unshare-all", "--die-with-parent", "--new-session",
            "--cap-drop", "ALL", "--clearenv", "--setenv", "HOME", "/tmp",
            "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--size", str(policy.tmpfs_mb * 1024 * 1024),
        ]
        for d in dirs:
            cmd += ["--ro-bind", d, d]
        for link in ("bin", "lib", "lib64", "sbin"):
            target = os.path.join("/", link)
            if os.path.islink(target):
                cmd += ["--symlink", os.readlink(target), target]
        cmd += ["--ro-bind", workdir, "/work", "--chdir", "/work"]
        cmd += ["--uid", str(_NOBODY), "--gid", str(_NOBODY)] if os.geteuid() == 0 else []
        return cmd + ["--"] + [real if a == python else a for a in argv]


# The jail is assembled by this script *inside* fresh namespaces, so none of
# the mounts are ever visible to (or can touch) the host mount table.
_JAIL_SCRIPT = r"""
set -eu
WORK="$1"; PRIV="$2"; TMPFS_MB="$3"; shift 3
RO_DIRS=""
while [ "$1" != "--" ]; do RO_DIRS="$RO_DIRS $1"; shift; done
shift
# The jail root is a private tmpfs mounted over /mnt *inside this mount
# namespace*: nothing is created on (or left behind in) the host filesystem.
R=/mnt
[ -d "$R" ] || R=/tmp
mount -t tmpfs -o size=2m,mode=755 tmpfs "$R"
mkdir -p "$R/proc" "$R/tmp" "$R/work" "$R/dev" "$R/etc"
for d in $RO_DIRS; do
  mkdir -p "$R$d"; mount --bind "$d" "$R$d"; mount -o remount,bind,ro "$R$d"
done
for l in bin lib lib64 sbin; do
  if [ -L "/$l" ]; then ln -s "$(readlink "/$l")" "$R/$l"; fi
done
mount --bind "$WORK" "$R/work"; mount -o remount,bind,ro "$R/work"
mount -t proc proc "$R/proc"
mount -t tmpfs -o "size=${TMPFS_MB}m,nosuid,nodev,noexec" tmpfs "$R/tmp"
for n in null zero urandom; do
  : > "$R/dev/$n"; mount --bind "/dev/$n" "$R/dev/$n"
done
SETPRIV=/usr/bin/setpriv
if [ "$PRIV" = "1" ]; then
  exec chroot "$R" "$SETPRIV" --reuid=65534 --regid=65534 --clear-groups \
    --bounding-set=-all --inh-caps=-all --no-new-privs \
    /usr/bin/env -C /work HOME=/tmp "$@"
else
  exec chroot "$R" "$SETPRIV" --bounding-set=-all --inh-caps=-all --no-new-privs \
    /usr/bin/env -C /work HOME=/tmp "$@"
fi
"""


class _NamespaceBackend(Backend):
    """Raw Linux namespaces + a private, read-only, chrooted mount tree."""

    name = "namespaces"

    def _flags(self) -> List[str]:
        flags = ["--mount", "--pid", "--fork", "--net", "--ipc", "--uts", "--kill-child"]
        if os.geteuid() != 0:
            flags = ["--user", "--map-root-user"] + flags
        return flags

    def available(self) -> Tuple[bool, str]:
        if sys.platform != "linux":
            return False, "Linux namespaces are only available on Linux"
        unshare = shutil.which("unshare")
        if not unshare or not shutil.which("setpriv") or not shutil.which("chroot"):
            return False, "unshare/setpriv/chroot (util-linux, coreutils) not installed"
        try:
            probe = subprocess.run(
                [unshare, *self._flags(), "true"],
                capture_output=True, timeout=10, stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"namespaces not usable: {exc}"
        if probe.returncode != 0:
            return False, "kernel refuses new namespaces for this user"
        return True, unshare

    def wrap(self, argv, workdir, python, policy):
        unshare = shutil.which("unshare") or "unshare"
        real, dirs = _interpreter_dirs(python)
        privileged = "1" if os.geteuid() == 0 else "0"
        return [
            unshare, *self._flags(),
            "/bin/sh", "-c", _JAIL_SCRIPT, "happy-jail",
            workdir, privileged, str(policy.tmpfs_mb), *dirs, "--",
            *[real if a == python else a for a in argv],
        ]


def _all_backends() -> List[Backend]:
    return [
        _ContainerBackend("docker"),
        _ContainerBackend("podman"),
        _BwrapBackend(),
        _NamespaceBackend(),
    ]


def available_backends() -> Dict[str, Tuple[bool, str]]:
    """``{backend: (usable, detail)}`` for every backend, usable or not."""
    return {b.name: b.available() for b in _all_backends()}


def select_backend(policy: Optional[IsolationPolicy] = None) -> Optional[Backend]:
    """Pick the backend for ``policy``.

    Returns ``None`` when nothing usable exists and the mode allows falling
    back; raises :class:`IsolationUnavailable` in ``required`` mode, and when
    a specific backend was requested but is not usable (never silently
    downgrade an explicit choice).
    """
    policy = policy or IsolationPolicy.from_env()
    if policy.mode == "off":
        return None
    candidates = _all_backends()
    if policy.backend != "auto":
        candidates = [b for b in candidates if b.name == policy.backend]
    reasons: List[str] = []
    for backend in candidates:
        ok, detail = backend.available()
        if ok:
            return backend
        reasons.append(f"{backend.name}: {detail}")
    if policy.mode == "required" or policy.backend != "auto":
        raise IsolationUnavailable(
            "no usable OS-level isolation backend (" + "; ".join(reasons) + ")"
        )
    return None


def isolation_status(policy: Optional[IsolationPolicy] = None) -> Dict[str, object]:
    """Machine-readable report: chosen backend, mode, and why others failed."""
    policy = policy or IsolationPolicy.from_env()
    report: Dict[str, object] = {
        "mode": policy.mode,
        "requested_backend": policy.backend,
        "backends": {k: {"usable": v[0], "detail": v[1]} for k, v in available_backends().items()},
    }
    try:
        chosen = select_backend(policy)
        report["selected"] = chosen.name if chosen else None
        report["os_isolated"] = chosen is not None
    except IsolationUnavailable as exc:
        report["selected"] = None
        report["os_isolated"] = False
        report["error"] = str(exc)
    return report


# --------------------------------------------------------------------------
# Self-test: try to escape, report what the jail actually stops
# --------------------------------------------------------------------------
_PROBE = r"""
import os, socket
res = {}
def attempt(name, fn):
    try:
        fn(); res[name] = "ALLOWED"
    except Exception as e:
        res[name] = "blocked"
attempt("read_host_etc_passwd", lambda: open("/etc/passwd").read())
attempt("read_host_home", lambda: os.listdir("/home"))
attempt("write_rootfs", lambda: open("/usr/happy_probe", "w"))
attempt("write_workdir", lambda: open("/work/happy_probe", "w"))
attempt("network", lambda: socket.create_connection(("1.1.1.1", 53), 2))
attempt("setuid_root", lambda: os.setuid(0) if os.getuid() != 0 else (_ for _ in ()).throw(OSError()))
pids = [p for p in os.listdir("/proc") if p.isdigit()] if os.path.isdir("/proc") else []
res["visible_pids"] = len(pids)
caps = "unknown"
try:
    for line in open("/proc/self/status"):
        if line.startswith("CapEff:"):
            caps = line.split()[1]
except Exception:
    pass
res["effective_caps"] = caps
res["uid"] = os.getuid()
import json; print(json.dumps(res))
"""


def self_test(policy: Optional[IsolationPolicy] = None) -> Dict[str, object]:
    """Run escape probes inside the selected backend and judge the result."""
    import json
    import tempfile

    policy = policy or IsolationPolicy.from_env(mode="required")
    backend = select_backend(policy)
    if backend is None:
        return {"ok": False, "backend": None, "detail": "no OS-level backend selected"}
    python = sys.executable
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o755)
        probe = os.path.join(work, "probe.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write(_PROBE)
        os.chmod(probe, 0o644)
        cmd = backend.wrap([python, "-I", "-S", "/work/probe.py"], work, python, policy)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "backend": backend.name, "detail": "probe timed out"}
        finally:
            backend.cleanup()
    out = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        res = json.loads(out[-1])
    except (IndexError, ValueError):
        return {
            "ok": False, "backend": backend.name,
            "detail": "probe did not run: " + proc.stderr.decode("utf-8", "replace")[-300:],
        }
    must_block = ["read_host_etc_passwd", "read_host_home", "write_rootfs",
                  "write_workdir", "network", "setuid_root"]
    failures = [k for k in must_block if res.get(k) != "blocked"]
    if res.get("uid") == 0 and "namespaces" != backend.name:
        failures.append("runs_as_root")
    if res.get("effective_caps") not in ("0000000000000000", "unknown"):
        failures.append("capabilities_not_dropped")
    if isinstance(res.get("visible_pids"), int) and res["visible_pids"] > 3:
        failures.append("host_pids_visible")
    return {"ok": not failures, "backend": backend.name, "failures": failures, "probes": res}


def main(argv: Optional[Sequence[str]] = None) -> int:
    import json

    status = isolation_status(IsolationPolicy.from_env())
    print(json.dumps(status, indent=2))
    try:
        result = self_test()
    except IsolationUnavailable as exc:
        print(f"\nSELF-TEST SKIPPED: {exc}")
        return 2
    print("\nself-test:", json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
