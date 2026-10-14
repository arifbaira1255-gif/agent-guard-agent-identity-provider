"""HTTP transport: TLS-verified, timeout-bounded, retry-bounded, cancellable.

Security properties
-------------------
* **Server identity is validated.** The default SSL context verifies the certificate chain AND the
  hostname. Disabling verification is refused outside ``development`` (see ``SdkConfig``).
* **Bounded everything.** A per-request timeout, a maximum response size, and a bounded number of
  retries with exponential backoff + jitter. Retries only ever happen for requests that are safe to
  repeat: ``GET``/``HEAD``, or any request carrying an ``Idempotency-Key``. A non-idempotent POST is
  never silently replayed.
* **Cancellation.** A :class:`CancellationToken` is checked before every attempt and before every
  retry, so a caller can abort promptly.
* **No secret leakage.** Errors carry a status, a stable code and a correlation id \u2014 never the
  request body, the Authorization header, or a token.
"""
from __future__ import annotations

import json
import random
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .config import SdkConfig
from .errors import (AgentGuardError, AuthenticationError, AuthorizationError, CancelledError,
                     ConflictError, NotFoundError, RateLimitedError, ServerError, TimeoutError,
                     TransportError, ValidationError)

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class CancellationToken:
    """Cooperative cancellation. Thread-safe enough for the SDK's single-request usage."""

    def __init__(self):
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def raise_if_cancelled(self) -> None:
        if self._cancelled:
            raise CancelledError("operation cancelled")


@dataclass
class Response:
    status: int
    body: object
    headers: dict

    def correlation_id(self) -> Optional[str]:
        if isinstance(self.body, dict):
            cid = self.body.get("correlation_id")
            if isinstance(cid, str) and cid:
                return cid
        for k, v in self.headers.items():
            if k.lower() in ("x-correlation-id", "x-request-id"):
                return v
        return None


class Transport:
    def __init__(self, config: SdkConfig, *, opener=None, sleep: Callable[[float], None] = time.sleep,
                 rng: Optional[random.Random] = None):
        self.config = config
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._opener = opener if opener is not None else self._build_opener()

    # ------------------------------------------------------------------ construction
    def _build_opener(self):
        handlers = []
        if self.config.base_url.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=self._ssl_context()))
        return urllib.request.build_opener(*handlers)

    def _ssl_context(self) -> ssl.SSLContext:
        cfg = self.config
        if cfg.verify_tls:
            ctx = ssl.create_default_context(cafile=cfg.ca_bundle)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:                                            # development only (enforced in SdkConfig)
            ctx = ssl._create_unverified_context()       # noqa: S323 - explicit dev escape hatch
        if cfg.client_cert and cfg.client_key:
            ctx.load_cert_chain(certfile=cfg.client_cert, keyfile=cfg.client_key)
        return ctx

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.config.base_url.rstrip("/") + path

    # ------------------------------------------------------------------ request
    def request(self, method: str, path: str, *, body: Optional[dict] = None,
                headers: Optional[dict] = None, idempotency_key: Optional[str] = None,
                cancel: Optional[CancellationToken] = None,
                expect: Tuple[int, ...] = (200, 201, 204)) -> Response:
        url = self._url(path)
        hdrs = {"Accept": "application/json", "User-Agent": self.config.user_agent}
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if idempotency_key:
            hdrs["Idempotency-Key"] = idempotency_key
        # Only repeat requests that are safe to repeat.
        repeatable = method in ("GET", "HEAD") or idempotency_key is not None
        attempt = 0
        while True:
            if cancel is not None:
                cancel.raise_if_cancelled()
            attempt += 1
            try:
                resp = self._once(method, url, data, hdrs)
            except TransportError:
                if repeatable and attempt <= self.config.max_retries:
                    self._backoff(attempt)
                    continue
                raise
            if resp.status in expect:
                return resp
            err = self._error_for(resp)
            if isinstance(err, (RateLimitedError, ServerError)) and repeatable \
                    and attempt <= self.config.max_retries:
                self._backoff(attempt, retry_after=resp.headers.get("Retry-After"))
                continue
            raise err

    def _once(self, method: str, url: str, data, headers: dict) -> Response:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.config.timeout_seconds) as r:
                raw = r.read(self.config.max_response_bytes + 1)
                if len(raw) > self.config.max_response_bytes:
                    raise TransportError("response exceeded the maximum allowed size")
                return Response(r.status, self._decode(raw), dict(r.headers))
        except urllib.error.HTTPError as e:              # a real HTTP response with an error status
            raw = e.read(self.config.max_response_bytes + 1)
            return Response(e.code, self._decode(raw), dict(e.headers))
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                raise TimeoutError("request timed out")
            raise TransportError(f"network error: {type(e.reason).__name__}")
        except socket.timeout:
            raise TimeoutError("request timed out")
        except (ssl.SSLError, ssl.CertificateError) as e:
            raise TransportError(f"TLS failure: {type(e).__name__}")

    @staticmethod
    def _decode(raw: bytes) -> object:
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return raw.decode("utf-8", errors="replace")[:512]

    def _error_for(self, resp: Response) -> AgentGuardError:
        code = None
        message = ""
        if isinstance(resp.body, dict):
            code = resp.body.get("error")
            message = resp.body.get("message") or ""
        cid = resp.correlation_id()
        s = resp.status
        if s == 400:
            return ValidationError(message or "invalid request", code=code, status=s,
                                   correlation_id=cid)
        if s in (401,):
            return AuthenticationError(message or "authentication failed", code=code, status=s,
                                       correlation_id=cid)
        if s == 403:
            return AuthorizationError(message or "forbidden", code=code, status=s,
                                      correlation_id=cid)
        if s == 404:
            return NotFoundError(message or "not found", code=code, status=s, correlation_id=cid)
        if s == 409:
            return ConflictError(message or "conflict", code=code, status=s, correlation_id=cid)
        if s == 429:
            return RateLimitedError(message or "rate limited", code=code, status=s,
                                    correlation_id=cid)
        if s >= 500:
            return ServerError(message or "server error", code=code, status=s, correlation_id=cid)
        return AgentGuardError(message or f"unexpected status {s}", code=code, status=s,
                               correlation_id=cid)

    def _backoff(self, attempt: int, *, retry_after: Optional[str] = None) -> None:
        if retry_after:
            try:
                delay = min(float(retry_after), self.config.retry_max_seconds)
                self._sleep(max(0.0, delay))
                return
            except (TypeError, ValueError):
                pass
        base = min(self.config.retry_base_seconds * (2 ** (attempt - 1)),
                   self.config.retry_max_seconds)
        self._sleep(base * (0.5 + self._rng.random() / 2))     # full-ish jitter
