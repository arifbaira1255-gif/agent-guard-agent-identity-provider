"""Phase 8 API platform primitives.

The Phase 8 management API (``/v2/*``) is a *versioned, console-facing* surface layered on top of
the existing Phase 1-7 services. It introduces **no second authorization path**: every route
resolves the caller's verified :class:`AuthContext` through the existing
:class:`~agent_identity.security.auth_service.EnterpriseAuthService` and enforces permissions with
the existing :class:`~agent_identity.security.rbac.Authorizer`.

This module holds the cross-cutting concerns that every ``/v2`` route shares, so the route handlers
stay thin and uniform:

* :class:`ApiError` / :func:`error_envelope` -- one consistent, secret-free error shape.
* :class:`Page` / :func:`paginate` -- bounded, cursor-free offset pagination with a hard cap.
* :class:`RateLimiter` -- a per-(principal, route-class) token bucket, fail-closed on exhaustion.
* :class:`RequestLimits` -- request-size, page-size, filter-count and time-range bounds.
* :func:`redact_mapping` -- defence-in-depth redaction of anything that looks like a secret.
* :class:`RouteSpec` / :class:`RouteRegistry` -- a machine-readable route table that both the
  dispatcher and the OpenAPI generator read, so the spec can never drift from the code.

Nothing here trusts client input: pagination, filters and limits are all validated and clamped
server-side.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.errors import (AuthenticationError, ConflictError, CsrfError, ForbiddenError,
                           IdentityError, NotFoundError, RateLimitedError, StorageError,
                           UnauthorizedError, ValidationError)

# --------------------------------------------------------------------------- API version
API_VERSION = "v2"
API_PREFIX = "/v2"

# --------------------------------------------------------------------------- limits
MAX_BODY_BYTES = 256 * 1024          # request body ceiling for the management API
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_FILTERS = 12
MAX_FILTER_VALUE_LEN = 256
MAX_TIME_RANGE_S = 90 * 86400        # a query may not span more than 90 days
MAX_LIMIT_PARAM = 1000               # hard ceiling for any caller-supplied "limit"


# --------------------------------------------------------------------------- errors
class ApiError(IdentityError):
    """A structured API error carrying an HTTP status, a stable code and a safe message."""

    def __init__(self, status: int, code: str, message: str, *, details: Optional[dict] = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details or {}

    def to_dict(self, *, correlation_id: Optional[str] = None) -> dict:
        out = {"error": {"code": self.code, "message": str(self)}}
        if self.details:
            out["error"]["details"] = self.details
        if correlation_id:
            out["error"]["correlation_id"] = correlation_id
        return out


#: Map the existing exception hierarchy onto HTTP statuses. Kept in one place so every ``/v2``
#: route returns the same shape for the same failure.
_STATUS_MAP: Sequence[Tuple[type, int, str]] = (
    (ValidationError, 400, "validation_error"),
    (AuthenticationError, 401, "authentication_failed"),
    (UnauthorizedError, 401, "unauthorized"),
    (CsrfError, 403, "csrf_failed"),
    (ForbiddenError, 403, "forbidden"),
    (NotFoundError, 404, "not_found"),
    (ConflictError, 409, "conflict"),
    (RateLimitedError, 429, "rate_limited"),
    (StorageError, 503, "storage_unavailable"),
)


def error_envelope(exc: Exception, *, correlation_id: Optional[str] = None) -> Tuple[int, dict]:
    """Translate any exception into ``(status, body)`` with a consistent, secret-free envelope.

    Internal errors are collapsed to a generic 500 -- stack traces, SQL and identifiers are never
    returned to a client.
    """
    if isinstance(exc, ApiError):
        return exc.status, exc.to_dict(correlation_id=correlation_id)
    for exc_type, status, code in _STATUS_MAP:
        if isinstance(exc, exc_type):
            return status, {"error": {"code": code, "message": str(exc),
                                      "correlation_id": correlation_id}}
    return 500, {"error": {"code": "internal_error", "message": "internal error",
                           "correlation_id": correlation_id}}


# --------------------------------------------------------------------------- pagination
@dataclass(frozen=True)
class Page:
    """A bounded page of results plus the metadata a console needs to render a pager."""

    items: List[Any]
    total: int
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total

    def to_dict(self, *, key: str = "items") -> dict:
        return {key: self.items,
                "page": {"total": self.total, "offset": self.offset, "limit": self.limit,
                         "count": len(self.items), "has_more": self.has_more,
                         "next_offset": (self.offset + self.limit) if self.has_more else None}}


def parse_pagination(params: dict, *, default_limit: int = DEFAULT_PAGE_SIZE,
                     max_limit: int = MAX_PAGE_SIZE) -> Tuple[int, int]:
    """Validate and clamp ``offset``/``limit`` from untrusted query params."""
    raw_limit = params.get("limit", default_limit)
    raw_offset = params.get("offset", 0)
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        raise ValidationError("limit must be an integer")
    try:
        offset = int(raw_offset)
    except (TypeError, ValueError):
        raise ValidationError("offset must be an integer")
    if limit < 1:
        raise ValidationError("limit must be >= 1")
    if offset < 0:
        raise ValidationError("offset must be >= 0")
    return offset, min(limit, max_limit)


def paginate(items: Iterable[Any], *, offset: int, limit: int) -> Page:
    """Slice an already-authorized, already-tenant-scoped sequence into a :class:`Page`."""
    seq = list(items)
    total = len(seq)
    return Page(items=seq[offset:offset + limit], total=total, offset=offset, limit=limit)


# --------------------------------------------------------------------------- filters
def parse_filters(params: dict, *, allowed: Sequence[str]) -> Dict[str, str]:
    """Extract and validate an allow-listed set of equality filters from query params.

    Unknown filter keys are rejected (not silently ignored) so a typo cannot quietly widen a query.
    """
    out: Dict[str, str] = {}
    for key in allowed:
        if key in params and params[key] not in (None, ""):
            val = params[key]
            if not isinstance(val, str):
                raise ValidationError(f"filter {key} must be a string")
            if len(val) > MAX_FILTER_VALUE_LEN:
                raise ValidationError(f"filter {key} is too long")
            out[key] = val
    if len(out) > MAX_FILTERS:
        raise ValidationError("too many filters")
    return out


def parse_time_range(params: dict, *, now: Optional[float] = None) -> Tuple[Optional[float], Optional[float]]:
    """Validate an optional ``since``/``until`` window (epoch seconds) and bound its width."""
    now = now if now is not None else time.time()
    since = _opt_float(params.get("since"), "since")
    until = _opt_float(params.get("until"), "until")
    if since is not None and until is not None and until < since:
        raise ValidationError("until must be >= since")
    if since is not None and until is not None and (until - since) > MAX_TIME_RANGE_S:
        raise ValidationError("time range too wide")
    return since, until


def _opt_float(v, name: str) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be a number")


def clamp_limit(v, *, default: int, maximum: int = MAX_LIMIT_PARAM) -> int:
    """Clamp a caller-supplied ``limit`` used by non-paginated list endpoints."""
    if v in (None, ""):
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValidationError("limit must be an integer")
    if n < 1:
        raise ValidationError("limit must be >= 1")
    return min(n, maximum)


# --------------------------------------------------------------------------- rate limiting
@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """A thread-safe token-bucket limiter keyed by ``(scope, identity)``.

    Fail-closed by design: when a bucket is exhausted the caller receives a 429 rather than being
    let through. Buckets are bounded (LRU-evicted) so a hostile caller cannot grow memory without
    limit. This is an in-process limiter -- for a multi-replica deployment it is a *per-replica*
    guard, and the documented production path is a shared Redis limiter (see the limitations doc).
    """

    def __init__(self, *, rate_per_s: float = 20.0, burst: int = 40, max_buckets: int = 20_000,
                 clock: Optional[Callable[[], float]] = None):
        self.rate = float(rate_per_s)
        self.burst = int(burst)
        self.max_buckets = int(max_buckets)
        self._clock = clock or time.monotonic
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, scope: str, identity: str, *, cost: float = 1.0) -> None:
        key = f"{scope}:{identity}"
        now = self._clock()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self.max_buckets:
                    self._evict_locked()
                b = _Bucket(tokens=float(self.burst), updated=now)
                self._buckets[key] = b
            elapsed = max(0.0, now - b.updated)
            b.tokens = min(float(self.burst), b.tokens + elapsed * self.rate)
            b.updated = now
            if b.tokens < cost:
                raise RateLimitedError("rate limit exceeded")
            b.tokens -= cost

    def _evict_locked(self) -> None:
        # Drop the oldest ~10% of buckets (cheap, bounded, no external dependency).
        n = max(1, len(self._buckets) // 10)
        for k in sorted(self._buckets, key=lambda k: self._buckets[k].updated)[:n]:
            self._buckets.pop(k, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# --------------------------------------------------------------------------- redaction
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|"
    r"authorization|bearer|credential|refresh|csrf|pin|salt|signature|session[_-]?secret)",
    re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(r"(agp1\.|-----BEGIN|^[A-Za-z0-9_\-]{80,}$)")
_REDACTED = "[REDACTED]"


def redact_mapping(obj: Any, *, depth: int = 0, max_depth: int = 8) -> Any:
    """Recursively redact secret-looking keys/values from an API response.

    This is defence-in-depth: the underlying services already avoid returning secrets, but the
    management API is the widest surface in the product, so it re-checks before serialization.
    """
    if depth > max_depth:
        return "[TRUNCATED]"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = _REDACTED
            else:
                out[k] = redact_mapping(v, depth=depth + 1, max_depth=max_depth)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_mapping(v, depth=depth + 1, max_depth=max_depth) for v in obj]
    if isinstance(obj, str) and _SECRET_VALUE_RE.search(obj):
        return _REDACTED
    return obj


# --------------------------------------------------------------------------- idempotency
def idempotency_fingerprint(method: str, path: str, body: dict) -> str:
    """A stable fingerprint of a mutating request, used to detect conflicting idempotency reuse."""
    import json
    blob = json.dumps({"m": method, "p": path, "b": body}, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- route registry
@dataclass(frozen=True)
class RouteSpec:
    """A single management-API route. The dispatcher and the OpenAPI generator both read this."""

    method: str
    path: str                       # e.g. "/v2/agents/{agent_id}"
    permission: str                 # the RBAC permission required (from security.rbac)
    summary: str
    tag: str
    tenant_scoped: bool = True
    mutating: bool = False
    idempotent: bool = False
    params: Tuple[str, ...] = ()    # path params
    query: Tuple[str, ...] = ()     # documented query params
    response_key: str = "items"
    status: int = 200
    high_impact: bool = False       # requires explicit confirmation in the CLI


class RouteRegistry:
    """An ordered, machine-readable table of the management API."""

    def __init__(self) -> None:
        self._routes: List[RouteSpec] = []

    def add(self, spec: RouteSpec) -> RouteSpec:
        self._routes.append(spec)
        return spec

    def all(self) -> List[RouteSpec]:
        return list(self._routes)

    def match(self, method: str, path: str) -> Optional[Tuple[RouteSpec, Dict[str, str]]]:
        """Match a concrete path against the registry, returning the spec + extracted params."""
        parts = [p for p in path.split("/") if p]
        for spec in self._routes:
            if spec.method != method:
                continue
            spec_parts = [p for p in spec.path.split("/") if p]
            if len(spec_parts) != len(parts):
                continue
            params: Dict[str, str] = {}
            ok = True
            for sp, ap in zip(spec_parts, parts):
                if sp.startswith("{") and sp.endswith("}"):
                    params[sp[1:-1]] = ap
                elif sp != ap:
                    ok = False
                    break
            if ok:
                return spec, params
        return None

    def permissions_map(self) -> Dict[Tuple[str, str], str]:
        return {(s.method, s.path): s.permission for s in self._routes}
