"""Liveness vs readiness aggregation (Step 7).

Two distinct questions, two distinct answers:

  * **Liveness** — is the process itself healthy? It must NOT depend on PostgreSQL, Redis, SPIRE or
    KMS: a dependency outage must never cause the orchestrator to kill and restart a perfectly
    healthy process (that would turn a transient dependency blip into a restart storm).
  * **Readiness** — can this instance safely accept traffic *right now*? It reflects every
    capability required to make a correct security decision: the authoritative database (and its
    schema), the distributed security state, and — where configured — SPIFFE/SPIRE, KMS/HSM and the
    trust store. If any required capability is down, the instance reports NOT ready and is removed
    from the load balancer, so it never serves a decision it cannot make correctly.

The public payload is deliberately coarse: ``ok``/``fail`` per capability. It never exposes
versions, hostnames, connection strings, identities, key ids or error text.
"""
from __future__ import annotations

import time
from typing import Callable, Dict, Optional

from ..spiffe import metrics as _M
from . import metrics as HM


class HealthAggregator:
    """Aggregates dependency health into liveness/readiness verdicts.

    Every dependency is optional and supplied as a zero-argument callable returning bool (or an
    object exposing ``readiness()``/``health()``). A dependency that is not configured is reported
    as ``ok`` (it is not required for this deployment).
    """

    def __init__(self, *, instance_id: str = "instance", db=None, state=None,
                 spiffe: Optional[Callable[[], bool]] = None,
                 kms: Optional[Callable[[], bool]] = None,
                 trust: Optional[Callable[[], bool]] = None,
                 metrics: Optional[_M.Metrics] = None, clock: Callable[[], float] = time.time):
        self.instance_id = instance_id
        self.db = db
        self.state = state
        self._spiffe = spiffe
        self._kms = kms
        self._trust = trust
        self.metrics = metrics or _M.Metrics()
        self._clock = clock

    # ------------------------------------------------------------------ liveness
    def liveness(self) -> dict:
        """Process-only. Never touches a dependency."""
        return {"status": "alive"}

    # ------------------------------------------------------------------ readiness
    def _db_ready(self) -> bool:
        if self.db is None:
            return True
        try:
            return bool(self.db.readiness()["ready"])
        except Exception:  # noqa: BLE001
            return False

    def _redis_ready(self) -> bool:
        if self.state is None:
            return True
        try:
            return bool(self.state.backend.ping())
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _call(fn) -> bool:
        if fn is None:
            return True
        try:
            return bool(fn())
        except Exception:  # noqa: BLE001
            return False

    def readiness(self) -> dict:
        checks: Dict[str, bool] = {
            "database": self._db_ready(),
            "redis": self._redis_ready(),
            "spiffe": self._call(self._spiffe),
            "kms": self._call(self._kms),
            "trust": self._call(self._trust),
        }
        ready = all(checks.values())
        for name, ok in checks.items():
            self.metrics.inc(HM.DEPENDENCY_UP, name, 1 if ok else 0)
        return {"status": "ready" if ready else "not_ready",
                "checks": {k: ("ok" if v else "fail") for k, v in checks.items()}}

    # ------------------------------------------------------------------ operator view
    def diagnostics(self) -> dict:
        """Richer view for authenticated operators (still no secrets/identities)."""
        out = {"instance_id": self.instance_id, "readiness": self.readiness()}
        if self.db is not None:
            try:
                out["db_pool"] = self.db.pool_stats() if hasattr(self.db, "pool_stats") else {}
            except Exception:  # noqa: BLE001
                out["db_pool"] = {}
        return out
