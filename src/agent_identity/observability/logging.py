"""Structured security logging with an allow-list: unknown fields are dropped and
anything that looks like a token or key material is redacted."""
import contextlib
import contextvars
import json
import logging
import re
import threading
import time
from collections import deque
from typing import Optional

ALLOWED = {"event", "agent_id", "instance_id", "credential_id", "org_id", "issuer",
           "issuer_key_id", "result", "reason", "actor", "correlation_id", "target_type",
           "target_id", "expires_at", "key_id", "parent_agent_id", "child_agent_id",
           "fingerprint", "revocation_reason", "audience", "spiffe_id", "trust_domain"}
_LOOKS_SECRET = re.compile(r"(agp1\.|-----BEGIN|^[A-Za-z0-9_\-]{80,}$)")

_correlation: contextvars.ContextVar = contextvars.ContextVar("correlation_id", default=None)


@contextlib.contextmanager
def correlation(cid: str):
    tok = _correlation.set(cid)
    try:
        yield cid
    finally:
        _correlation.reset(tok)


def current_correlation_id() -> Optional[str]:
    return _correlation.get()


class SecurityLogger:
    def __init__(self, use_python_logging: bool = True, keep: int = 5000):
        self._log = logging.getLogger("agentguard.identity.security")
        self._use = use_python_logging
        self.events: deque = deque(maxlen=keep)   # in-memory sink (tests / debugging)
        self._lock = threading.Lock()

    @staticmethod
    def _clean(v):
        if v is None:
            return None
        s = str(v).replace("\n", " ").replace("\r", " ")[:256]
        return "[REDACTED]" if _LOOKS_SECRET.search(s) else s

    def emit(self, event: str, **fields) -> dict:
        rec = {"ts": round(time.time(), 3), "event": event}
        cid = fields.get("correlation_id") or current_correlation_id()
        if cid:
            fields["correlation_id"] = cid
        for k, v in fields.items():
            if k in ALLOWED and v is not None:
                rec[k] = self._clean(v)
        with self._lock:
            self.events.append(rec)
        if self._use:
            self._log.info(json.dumps(rec, sort_keys=True))
        return rec
