"""Step 10 policy engine: a clean evaluation interface over Open Policy Agent (OPA) + Rego.

Design
------
* **One interface, pluggable backends.** :class:`PolicyEngine` is the contract; the concrete
  implementations are :class:`OpaHttpEngine` (talks to a running ``opa run --server``) and
  :class:`OpaCliEngine` (evaluates with the ``opa`` binary, no server required). :class:`NullEngine`
  is the explicit "no engine configured" backend.
* **Rego, not a bespoke language.** Policies are Rego modules. The author writes
  ``package agentguard.authz`` and a ``decision`` rule returning an object
  ``{"decision": "ALLOW"|"DENY"|"REQUIRE_APPROVAL", "reason": "...", "obligations": [...]}``.
  The engine namespaces each policy version into its own package
  (``agentguard.policies.<id>_v<version>``) so many policies coexist in one OPA instance, and
  queries ``data.<pkg>.decision``.
* **Fail closed, always.** A timeout, a non-zero exit, an unparseable result, an undefined rule or
  a malformed decision object all yield :class:`~agent_identity.policy.models.DecisionKind.INDETERMINATE`
  — which is never an allow. The engine never raises into the caller's decision path.
* **Bounded resources.** Every evaluation has a wall-clock timeout, an input-size ceiling and a
  bounded concurrency gate. There are no unbounded waits and no unbounded memory claims.
* **Untrusted Rego is validated before it is ever executed.** :func:`validate_rego` rejects
  oversized source, missing/duplicate package declarations, and a denylist of dangerous builtins
  (``http.send``, ``net.lookup_ip_addr``, ``opa.runtime``, ``trace``) that would let a policy reach
  the network or the host. Validation is a guard, not a sandbox: OPA itself is the isolation
  boundary and is run with a timeout.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Optional, Protocol

from .config import PolicyConfig
from .errors import PolicyEngineUnavailableError, PolicyValidationError
from .models import DecisionKind, PolicyDecision

log = logging.getLogger("agentguard.policy.engine")

#: Builtins a policy may never call: they reach the network, the host, or leak runtime internals.
_FORBIDDEN_BUILTINS = ("http.send", "net.lookup_ip_addr", "opa.runtime", "trace", "print")
_PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*$", re.MULTILINE)
_PKG_SAFE = re.compile(r"[^a-z0-9_]")
_AUTHOR_PACKAGE = "agentguard.authz"
_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_comments(source: str) -> str:
    """Remove Rego ``#`` comments so validation inspects CODE, not prose.

    Without this, a comment mentioning ``decision`` or ``http.send`` would fool the checks (a
    comment cannot call a builtin, and a comment is not a rule).
    """
    return _COMMENT_RE.sub("", source)


def validate_rego(source: str, *, max_bytes: int) -> str:
    """Validate a Rego module before it is stored or executed. Returns the source unchanged.

    Raises :class:`PolicyValidationError` on any problem. This is deliberately conservative: it
    rejects the shapes that are dangerous or ambiguous rather than trying to be clever.
    """
    if not isinstance(source, str) or not source.strip():
        raise PolicyValidationError("policy source is empty")
    if len(source.encode("utf-8")) > max_bytes:
        raise PolicyValidationError("policy source exceeds the maximum size")
    code = _strip_comments(source)
    packages = _PACKAGE_RE.findall(code)
    if not packages:
        raise PolicyValidationError("policy must declare a package")
    if len(packages) != 1:
        raise PolicyValidationError("policy must declare exactly one package")
    if packages[0] != _AUTHOR_PACKAGE:
        raise PolicyValidationError(f"policy package must be '{_AUTHOR_PACKAGE}'")
    if not re.search(r"\bdecision\b", code):
        raise PolicyValidationError("policy must define a 'decision' rule")
    lowered = code.lower()
    for builtin in _FORBIDDEN_BUILTINS:
        if builtin in lowered:
            raise PolicyValidationError(f"policy uses a forbidden builtin: {builtin}")
    return source


def namespaced_package(policy_id: str, version: int) -> str:
    """The unique OPA package a policy version is loaded under."""
    safe = _PKG_SAFE.sub("_", policy_id.lower())
    return f"agentguard.policies.{safe}_v{version}"


def rewrite_package(source: str, package: str) -> str:
    """Rewrite the single ``package agentguard.authz`` declaration to ``package <package>``.

    Only the package line is touched; the rest of the module is byte-for-byte preserved.
    """
    return _PACKAGE_RE.sub(f"package {package}", source, count=1)


def _coerce_decision(raw, *, policy_id: Optional[str], policy_version: Optional[str],
                     correlation_id: Optional[str], latency_ms: int) -> PolicyDecision:
    """Map an OPA result value to a :class:`PolicyDecision`. Anything unexpected -> INDETERMINATE."""
    if raw is None:
        return PolicyDecision.indeterminate("policy_undefined", policy_id=policy_id,
                                            policy_version=policy_version,
                                            correlation_id=correlation_id, latency_ms=latency_ms)
    if not isinstance(raw, dict):
        return PolicyDecision.indeterminate("policy_result_not_object", policy_id=policy_id,
                                            policy_version=policy_version,
                                            correlation_id=correlation_id, latency_ms=latency_ms)
    kind_raw = raw.get("decision")
    if not isinstance(kind_raw, str):
        return PolicyDecision.indeterminate("policy_result_missing_decision", policy_id=policy_id,
                                            policy_version=policy_version,
                                            correlation_id=correlation_id, latency_ms=latency_ms)
    try:
        kind = DecisionKind(kind_raw.strip().upper())
    except ValueError:
        return PolicyDecision.indeterminate("policy_result_unknown_decision", policy_id=policy_id,
                                            policy_version=policy_version,
                                            correlation_id=correlation_id, latency_ms=latency_ms)
    reason = raw.get("reason")
    reason = reason if isinstance(reason, str) else ""
    obligations = raw.get("obligations")
    obligations = tuple(o for o in obligations if isinstance(o, dict)) if isinstance(obligations, list) else ()
    return PolicyDecision(kind, reason, policy_id=policy_id, policy_version=policy_version,
                          obligations=obligations, correlation_id=correlation_id, latency_ms=latency_ms)


class PolicyEngine(Protocol):
    """The evaluation contract. Implementations MUST fail closed and never raise into callers."""

    def evaluate(self, *, policy_source: str, policy_id: str, version: int, input_doc: dict,
                 correlation_id: Optional[str] = None) -> PolicyDecision:  # pragma: no cover
        ...

    def health(self) -> bool:  # pragma: no cover
        ...


class NullEngine:
    """No engine configured. Every evaluation is INDETERMINATE (fail closed)."""

    def evaluate(self, *, policy_source, policy_id, version, input_doc, correlation_id=None):
        return PolicyDecision.indeterminate("no_policy_engine_configured", policy_id=policy_id,
                                            policy_version=f"{policy_id}@v{version}",
                                            correlation_id=correlation_id)

    def health(self) -> bool:
        return False


class _BoundedGate:
    """A bounded concurrency gate. Excess callers wait up to the eval timeout, then fail closed."""

    def __init__(self, limit: int):
        self._sem = threading.BoundedSemaphore(limit)
        self._limit = limit

    def acquire(self, timeout_s: float) -> bool:
        return self._sem.acquire(timeout=timeout_s)

    def release(self) -> None:
        try:
            self._sem.release()
        except ValueError:  # pragma: no cover - defensive
            pass


class OpaHttpEngine:
    """Evaluate Rego through a running OPA server (``opa run --server``).

    Policies are pushed with ``PUT /v1/policies/{id}`` and decisions queried with
    ``POST /v1/data/{path}``. Both calls are bounded by ``eval_timeout_ms``.
    """

    def __init__(self, config: PolicyConfig):
        self.cfg = config
        self._gate = _BoundedGate(config.max_concurrent_evals)
        self._loaded: dict[str, str] = {}          # package -> checksum of the loaded source
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ internals
    def _request(self, method: str, path: str, body, timeout_s: float, *, raw: bool = False):
        url = self.cfg.opa_url.rstrip("/") + path
        if raw:
            data = body.encode("utf-8") if isinstance(body, str) else body
            ctype = "text/plain"
        else:
            data = json.dumps(body).encode("utf-8") if body is not None else None
            ctype = "application/json"
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": ctype})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - loopback/https
            raw_out = resp.read()
        return json.loads(raw_out) if raw_out else {}

    def _ensure_loaded(self, package: str, source: str, checksum: str, timeout_s: float) -> None:
        with self._lock:
            if self._loaded.get(package) == checksum:
                return
        # OPA's policy API takes the RAW Rego module as the request body (not a JSON wrapper).
        self._request("PUT", f"/v1/policies/{package}", source, timeout_s, raw=True)
        with self._lock:
            self._loaded[package] = checksum

    # ------------------------------------------------------------------ contract
    def evaluate(self, *, policy_source, policy_id, version, input_doc, correlation_id=None):
        started = time.perf_counter()
        timeout_s = self.cfg.eval_timeout_ms / 1000.0
        pkg = namespaced_package(policy_id, version)
        try:
            validate_rego(policy_source, max_bytes=self.cfg.max_policy_bytes)
        except PolicyValidationError as exc:
            return PolicyDecision.indeterminate(f"policy_invalid:{exc.code}", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        payload = json.dumps(input_doc).encode("utf-8")
        if len(payload) > self.cfg.max_input_bytes:
            return PolicyDecision.indeterminate("policy_input_too_large", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        if not self._gate.acquire(timeout_s):
            return PolicyDecision.indeterminate("policy_engine_overloaded", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        try:
            import hashlib
            checksum = hashlib.sha256(policy_source.encode("utf-8")).hexdigest()
            self._ensure_loaded(pkg, rewrite_package(policy_source, pkg), checksum, timeout_s)
            result = self._request("POST", f"/v1/data/{pkg.replace('.', '/')}/decision",
                                   {"input": input_doc}, timeout_s)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            log.warning("opa http evaluation failed type=%s", type(exc).__name__)
            return PolicyDecision.indeterminate("policy_engine_unavailable", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        finally:
            self._gate.release()
        latency_ms = int((time.perf_counter() - started) * 1000)
        return _coerce_decision(result.get("result"), policy_id=policy_id,
                                policy_version=f"{policy_id}@v{version}",
                                correlation_id=correlation_id, latency_ms=latency_ms)

    def health(self) -> bool:
        try:
            self._request("GET", "/health", None, self.cfg.eval_timeout_ms / 1000.0)
            return True
        except Exception:  # noqa: BLE001
            return False


class OpaCliEngine:
    """Evaluate Rego with the ``opa`` binary (``opa eval``), no server required.

    Each evaluation writes the namespaced module to a temp file and runs ``opa eval`` with a hard
    timeout. This is slower than the HTTP engine (a process per evaluation) and is intended for
    development, CI and single-node deployments; production should use :class:`OpaHttpEngine`.
    """

    def __init__(self, config: PolicyConfig):
        self.cfg = config
        self._gate = _BoundedGate(config.max_concurrent_evals)
        self._binary = shutil.which(config.opa_binary) or config.opa_binary

    def evaluate(self, *, policy_source, policy_id, version, input_doc, correlation_id=None):
        started = time.perf_counter()
        timeout_s = self.cfg.eval_timeout_ms / 1000.0
        pkg = namespaced_package(policy_id, version)
        try:
            validate_rego(policy_source, max_bytes=self.cfg.max_policy_bytes)
        except PolicyValidationError as exc:
            return PolicyDecision.indeterminate(f"policy_invalid:{exc.code}", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        payload = json.dumps(input_doc).encode("utf-8")
        if len(payload) > self.cfg.max_input_bytes:
            return PolicyDecision.indeterminate("policy_input_too_large", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        if not self._gate.acquire(timeout_s):
            return PolicyDecision.indeterminate("policy_engine_overloaded", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix="ag_policy_")
            with open(f"{tmpdir}/policy.rego", "w", encoding="utf-8") as fh:
                fh.write(rewrite_package(policy_source, pkg))
            proc = subprocess.run(
                [self._binary, "eval", "--format=json", "--stdin-input", "-d", tmpdir,
                 f"data.{pkg}.decision"],
                input=payload, capture_output=True, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            return PolicyDecision.indeterminate("policy_engine_timeout", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        except (OSError, ValueError) as exc:
            log.warning("opa cli evaluation failed type=%s", type(exc).__name__)
            return PolicyDecision.indeterminate("policy_engine_unavailable", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id)
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
            self._gate.release()
        latency_ms = int((time.perf_counter() - started) * 1000)
        if proc.returncode != 0:
            return PolicyDecision.indeterminate("policy_engine_error", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id, latency_ms=latency_ms)
        try:
            parsed = json.loads(proc.stdout.decode("utf-8"))
            result = parsed.get("result")
            if isinstance(result, list) and result:
                value = result[0].get("expressions", [{}])[0].get("value")
            else:
                value = None
        except (ValueError, KeyError, IndexError):
            return PolicyDecision.indeterminate("policy_result_unparseable", policy_id=policy_id,
                                                policy_version=f"{policy_id}@v{version}",
                                                correlation_id=correlation_id, latency_ms=latency_ms)
        return _coerce_decision(value, policy_id=policy_id, policy_version=f"{policy_id}@v{version}",
                                correlation_id=correlation_id, latency_ms=latency_ms)

    def health(self) -> bool:
        try:
            proc = subprocess.run([self._binary, "version"], capture_output=True,
                                  timeout=self.cfg.eval_timeout_ms / 1000.0)
            return proc.returncode == 0
        except Exception:  # noqa: BLE001
            return False


def build_engine(config: PolicyConfig) -> PolicyEngine:
    """Select the engine from configuration. ``engine='none'`` -> :class:`NullEngine`."""
    if config.engine == "none":
        return NullEngine()
    if config.engine == "opa":
        if config.opa_mode == "http":
            return OpaHttpEngine(config)
        return OpaCliEngine(config)
    raise PolicyEngineUnavailableError("unknown policy engine")  # pragma: no cover - config guards
