"""API-key authentication and per-key rate limiting for the AQL-1 REST API.

Design goals
------------
* **Never store a raw key.** Only the SHA-256 hash of a key is persisted; the
  plaintext is returned to the caller exactly once, at creation time.
* **Runs with zero configuration.** With no Supabase credentials the key store
  and the rate limiter fall back to in-memory implementations, so the app boots
  and the middleware works in local development.
* **Typed failures.** ``AuthError`` and friends — never a bare ``Exception``.
* **Graceful degradation.** A broken store logs a warning and denies the
  request rather than crashing the process.

The middleware protects every route except the public ones (health, docs,
OpenAPI). Set ``AUTH_ENABLED=false`` to turn the whole layer off in local dev.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Settings, get_settings

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# Typed exceptions
# ══════════════════════════════════════════════════════════════════════════════
class AuthError(Exception):
    """Base class for every authentication/authorisation failure."""


class APIKeyError(AuthError):
    """Base class for API-key problems (maps to HTTP 401)."""


class MissingAPIKeyError(APIKeyError):
    """No key was supplied on a protected route."""


class InvalidAPIKeyError(APIKeyError):
    """The supplied key does not match any stored key hash."""


class RevokedAPIKeyError(APIKeyError):
    """The key exists but has been deactivated."""


class APIKeyStoreError(AuthError):
    """The key store could not be read or written."""


class RateLimitExceededError(AuthError):
    """The key exceeded its request budget for the current window."""


# ══════════════════════════════════════════════════════════════════════════════
# Hashing & key generation
# ══════════════════════════════════════════════════════════════════════════════
def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of ``raw_key``.

    This is the ONLY representation of a key that is ever persisted. Hashing is
    deterministic, so verification is a single indexed lookup by hash.
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key(prefix: str = "aql1_") -> str:
    """Mint a new high-entropy raw API key.

    ``secrets.token_urlsafe(32)`` yields ~256 bits of entropy, which is far
    beyond brute-force reach. The prefix makes keys recognisable to secret
    scanners (the same trick GitHub/Stripe use).
    """
    return f"{prefix}{secrets.token_urlsafe(32)}"


def _display_prefix(raw_key: str) -> str:
    """A safe, non-reversible label for a key (first 12 chars + ellipsis)."""
    return f"{raw_key[:12]}…" if len(raw_key) > 12 else raw_key


# ══════════════════════════════════════════════════════════════════════════════
# Records
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class APIKeyRecord:
    """One stored API key. Holds the hash — never the raw key."""

    key_id: str
    key_hash: str
    name: str
    owner_id: str = "anonymous"
    scopes: list[str] = field(default_factory=list)
    active: bool = True
    created_at: str = field(default_factory=_utcnow_iso)
    last_used_at: str | None = None
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    prefix: str = ""

    def to_dict(self, *, include_hash: bool = False) -> dict[str, Any]:
        """Serialise the record. The hash is omitted unless explicitly asked."""
        data: dict[str, Any] = {
            "key_id": self.key_id,
            "name": self.name,
            "owner_id": self.owner_id,
            "scopes": list(self.scopes),
            "active": self.active,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "prefix": self.prefix,
        }
        if include_hash:
            data["key_hash"] = self.key_hash
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "APIKeyRecord":
        """Rebuild a record from its stored form (tolerates missing fields)."""
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class RateLimitStatus:
    """The outcome of one rate-limit check, plus the headers to advertise it."""

    allowed: bool
    limit: int
    remaining: int
    reset: int          # epoch seconds when the window frees up
    retry_after: int    # seconds to wait (0 when allowed)

    def headers(self) -> dict[str, str]:
        """Standard ``X-RateLimit-*`` headers for the response."""
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(self.remaining, 0)),
            "X-RateLimit-Reset": str(self.reset),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Key store
# ══════════════════════════════════════════════════════════════════════════════
class APIKeyStore:
    """Creates, verifies, lists and revokes API keys.

    Persistence is delegated to :class:`memory.state.StateManager`, which uses
    Supabase when configured and an in-memory dict otherwise — so this class
    never needs to know which backend is live.
    """

    def __init__(self, state: Any | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        if state is None:
            # Imported lazily so ``core.auth`` stays importable on its own.
            from memory.state import StateManager

            state = StateManager()
        self._state = state

    @property
    def is_local(self) -> bool:
        """True when keys live in memory only (no Supabase configured)."""
        return bool(getattr(self._state, "is_local", True))

    # ── create ───────────────────────────────────────────────────────────────
    def create(
        self,
        name: str,
        *,
        owner_id: str = "anonymous",
        scopes: list[str] | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_window_seconds: int | None = None,
    ) -> tuple[str, APIKeyRecord]:
        """Mint a key. Returns ``(raw_key, record)`` — the raw key is shown once.

        Only ``record.key_hash`` is persisted; the caller must hand the raw key
        to the user immediately, because it cannot be recovered afterwards.
        """
        raw_key = generate_api_key(self.settings.api_key_prefix)
        record = APIKeyRecord(
            key_id=str(uuid.uuid4()),
            key_hash=hash_api_key(raw_key),
            name=name,
            owner_id=owner_id,
            scopes=list(scopes or ["agent:run", "agent:read"]),
            rate_limit_requests=rate_limit_requests
            or self.settings.rate_limit_requests,
            rate_limit_window_seconds=rate_limit_window_seconds
            or self.settings.rate_limit_window_seconds,
            prefix=_display_prefix(raw_key),
        )
        try:
            self._state.save_api_key(record.key_hash, record.to_dict(include_hash=True))
        except Exception as exc:  # noqa: BLE001 — surface as a typed error
            raise APIKeyStoreError(f"could not persist API key: {exc}") from exc
        return raw_key, record

    # ── verify ───────────────────────────────────────────────────────────────
    def verify(self, raw_key: str | None) -> APIKeyRecord:
        """Resolve ``raw_key`` to its record, or raise a typed error.

        Raises:
            MissingAPIKeyError: ``raw_key`` is empty/None.
            InvalidAPIKeyError: no stored key matches the hash.
            RevokedAPIKeyError: the key exists but is deactivated.
            APIKeyStoreError: the store itself failed.
        """
        if not raw_key:
            raise MissingAPIKeyError("no API key supplied")

        key_hash = hash_api_key(raw_key)
        try:
            stored = self._state.get_api_key(key_hash)
        except Exception as exc:  # noqa: BLE001 — a broken store must not crash
            raise APIKeyStoreError(f"could not read API key store: {exc}") from exc

        if stored is None:
            raise InvalidAPIKeyError("API key is not recognised")
        record = APIKeyRecord.from_dict(stored)
        if not record.active:
            raise RevokedAPIKeyError("API key has been revoked")
        return record

    # ── read / mutate ────────────────────────────────────────────────────────
    def list(self) -> list[APIKeyRecord]:
        """Return every stored key record (hashes included, for admin use)."""
        try:
            rows = self._state.list_api_keys()
        except Exception as exc:  # noqa: BLE001
            raise APIKeyStoreError(f"could not list API keys: {exc}") from exc
        return [APIKeyRecord.from_dict(r) for r in rows]

    def get(self, key_id: str) -> APIKeyRecord | None:
        """Find a record by its public ``key_id``."""
        return next((r for r in self.list() if r.key_id == key_id), None)

    def revoke(self, key_id: str) -> APIKeyRecord:
        """Deactivate a key by ``key_id``.

        Raises:
            InvalidAPIKeyError: no key with that id exists.
        """
        record = self.get(key_id)
        if record is None:
            raise InvalidAPIKeyError(f"no API key with id {key_id}")
        record.active = False
        try:
            self._state.update_api_key(
                record.key_hash, record.to_dict(include_hash=True)
            )
        except Exception as exc:  # noqa: BLE001
            raise APIKeyStoreError(f"could not revoke API key: {exc}") from exc
        return record

    def touch(self, record: APIKeyRecord) -> None:
        """Record that ``record`` was just used (best-effort, never raises).

        Only ``last_used_at`` is patched. Writing the whole record back would
        resurrect a key that was revoked *during* this very request: the record
        was resolved before the handler ran, so its in-memory ``active`` flag is
        stale by the time we get here.
        """
        try:
            self._state.update_api_key(
                record.key_hash, {"last_used_at": _utcnow_iso()}
            )
        except Exception as exc:  # noqa: BLE001 — usage tracking is not critical
            logger.warning("Could not update last_used_at (%s)", exc)


# ══════════════════════════════════════════════════════════════════════════════
# Rate limiter
# ══════════════════════════════════════════════════════════════════════════════
class RateLimiter:
    """In-memory sliding-window rate limiter, keyed by API-key hash.

    A sliding window (rather than a fixed bucket) avoids the burst-at-the-
    boundary problem: a client can never fire 2x the limit across a window
    edge. State is per-process, which is the right trade-off for a boilerplate
    — swap in Redis for a multi-worker deployment.
    """

    def __init__(
        self,
        requests: int | None = None,
        window_seconds: int | None = None,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or get_settings()
        self.requests = requests or settings.rate_limit_requests
        self.window_seconds = window_seconds or settings.rate_limit_window_seconds
        self._hits: dict[str, deque[float]] = {}

    def check(
        self,
        key_hash: str,
        *,
        limit: int | None = None,
        window_seconds: int | None = None,
    ) -> RateLimitStatus:
        """Record one hit for ``key_hash`` and report whether it is allowed."""
        limit = limit or self.requests
        window = window_seconds or self.window_seconds
        now = time.time()
        cutoff = now - window

        hits = self._hits.setdefault(key_hash, deque())
        # Drop everything that has aged out of the window.
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= limit:
            # The window frees up when the oldest hit expires.
            reset = int(hits[0] + window)
            return RateLimitStatus(
                allowed=False,
                limit=limit,
                remaining=0,
                reset=reset,
                retry_after=max(reset - int(now), 1),
            )

        hits.append(now)
        remaining = limit - len(hits)
        reset = int(now + window)
        return RateLimitStatus(
            allowed=True, limit=limit, remaining=remaining, reset=reset, retry_after=0
        )

    def reset(self, key_hash: str | None = None) -> None:
        """Clear the counters for one key, or for every key."""
        if key_hash is None:
            self._hits.clear()
        else:
            self._hits.pop(key_hash, None)


# ══════════════════════════════════════════════════════════════════════════════
# Shared singletons
# ══════════════════════════════════════════════════════════════════════════════
# One store + one limiter per process, so the middleware and the /v1/keys
# endpoints always agree on which keys exist and how much budget they have left.
_store: APIKeyStore | None = None
_limiter: RateLimiter | None = None


def get_api_key_store() -> APIKeyStore:
    """Return the process-wide API-key store (created on first use)."""
    global _store
    if _store is None:
        _store = APIKeyStore()
    return _store


def get_rate_limiter() -> RateLimiter:
    """Return the process-wide rate limiter (created on first use)."""
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def reset_auth_state() -> None:
    """Drop the cached store/limiter — used by tests to isolate state."""
    global _store, _limiter
    _store = None
    _limiter = None


# ══════════════════════════════════════════════════════════════════════════════
# Middleware
# ══════════════════════════════════════════════════════════════════════════════
def extract_api_key(request: Request) -> str | None:
    """Pull the key from ``Authorization: Bearer`` or ``X-API-Key``.

    ``X-API-Key`` wins when both are present, since it is unambiguous.
    """
    header_key = request.headers.get("x-api-key")
    if header_key:
        return header_key.strip()

    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def _is_public(path: str, public_paths: list[str]) -> bool:
    """True when ``path`` is exempt from authentication.

    Entries ending in ``/`` (other than the root) act as prefixes so that
    ``/docs/`` covers ``/docs/oauth2-redirect``; everything else is an exact
    match, which keeps ``/`` from accidentally opening the whole API.
    """
    normalised = path.rstrip("/") or "/"
    for entry in public_paths:
        if entry == "/":
            if normalised == "/":
                return True
            continue
        if entry.endswith("/"):
            if path.startswith(entry):
                return True
        elif normalised == entry.rstrip("/"):
            return True
    return False


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Authenticate every non-public request and enforce its rate limit.

    On success the resolved identity is attached to ``request.state`` so
    endpoints can read it without re-parsing headers:

    * ``request.state.api_key``      — the :class:`APIKeyRecord`
    * ``request.state.api_key_hash`` — its SHA-256 hash (rate-limit bucket)
    * ``request.state.rate_limit``   — the :class:`RateLimitStatus`
    """

    def __init__(
        self,
        app: Any,
        *,
        store: APIKeyStore | None = None,
        limiter: RateLimiter | None = None,
        enabled: bool | None = None,
        public_paths: list[str] | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(app)
        self.settings = settings or get_settings()
        self._store = store
        self._limiter = limiter
        # ``enabled`` is resolved per request so tests (and hot reloads) can
        # flip it without rebuilding the app.
        self._enabled_override = enabled
        self._public_paths = public_paths

    # ── lazily-resolved collaborators ────────────────────────────────────────
    @property
    def store(self) -> APIKeyStore:
        return self._store or get_api_key_store()

    @property
    def limiter(self) -> RateLimiter:
        return self._limiter or get_rate_limiter()

    @property
    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return self._enabled_override
        return self.settings.auth_enabled

    @property
    def public_paths(self) -> list[str]:
        return self._public_paths or self.settings.auth_public_path_list

    # ── request handling ─────────────────────────────────────────────────────
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        # 1. Auth disabled (local dev) → straight through.
        if not self.enabled:
            return await call_next(request)

        # 2. CORS preflight and public routes never need a key.
        if request.method == "OPTIONS" or _is_public(
            request.url.path, self.public_paths
        ):
            return await call_next(request)

        # 3. Resolve the key. Any store failure degrades to a 401, never a 500.
        raw_key = extract_api_key(request)
        try:
            record = self.store.verify(raw_key)
        except MissingAPIKeyError as exc:
            return self._unauthorized(str(exc), "missing_api_key")
        except RevokedAPIKeyError as exc:
            return self._unauthorized(str(exc), "revoked_api_key")
        except InvalidAPIKeyError as exc:
            return self._unauthorized(str(exc), "invalid_api_key")
        except AuthError as exc:  # store failure — log loudly, deny quietly
            logger.warning("API-key verification failed (%s)", exc)
            return self._unauthorized("API key could not be verified", "auth_error")

        # 4. Per-key rate limit (the key's own budget overrides the default).
        status = self.limiter.check(
            record.key_hash,
            limit=record.rate_limit_requests,
            window_seconds=record.rate_limit_window_seconds,
        )
        if not status.allowed:
            return self._rate_limited(status)

        # 5. Expose the identity to the endpoint and run it.
        request.state.api_key = record
        request.state.api_key_hash = record.key_hash
        request.state.rate_limit = status

        response = await call_next(request)

        # 6. Advertise the remaining budget on the way out.
        for header, value in status.headers().items():
            response.headers[header] = value
        # Usage tracking is best-effort and must never break a response.
        try:
            self.store.touch(record)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record key usage (%s)", exc)
        return response

    # ── error responses ──────────────────────────────────────────────────────
    @staticmethod
    def _unauthorized(detail: str, code: str) -> JSONResponse:
        """A 401 with a machine-readable body and the right challenge header."""
        return JSONResponse(
            status_code=401,
            content={"error": "unauthorized", "code": code, "detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _rate_limited(status: RateLimitStatus) -> JSONResponse:
        """A 429 carrying ``Retry-After`` plus the standard rate-limit headers."""
        headers = status.headers()
        headers["Retry-After"] = str(status.retry_after)
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limited",
                "code": "rate_limit_exceeded",
                "detail": (
                    f"Rate limit of {status.limit} requests per window exceeded. "
                    f"Retry in {status.retry_after}s."
                ),
                "retry_after": status.retry_after,
            },
            headers=headers,
        )
