"""Step 7 wiring: build a stateless, multi-instance-ready IdentityService.

One call assembles the whole HA stack from the existing Step 1-6 components:

    pg   = build_postgres_storage(PgConfig.from_env(), master_keys)     # durable, authoritative
    st   = build_security_state(RedisConfig.from_env())                 # distributed transient state
    ha   = build_ha(pg, st, IdentityConfig.from_env())                  # idempotency + coordination + health
    svc  = ha.service()                                                 # IdentityService, ready to serve

Nothing here re-implements identity, storage, KMS/HSM or mTLS: it only composes them and adds the
Step 7 pieces (idempotency ledger, coordination runner, health aggregator, per-instance metrics).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.config import IdentityConfig
from ..spiffe import metrics as _M
from .coordination import CoordinationRunner, PeriodicScheduler
from .health import HealthAggregator
from .idempotency import MemoryIdempotencyStore, PgIdempotencyStore


@dataclass
class HaRuntime:
    service: object
    idempotency: object
    coordination: Optional[CoordinationRunner]
    health: HealthAggregator
    metrics: _M.Metrics
    scheduler: Optional[PeriodicScheduler] = None

    def start(self) -> "HaRuntime":
        if self.scheduler is not None:
            self.scheduler.start()
        return self

    def stop(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()

    def health_callables(self) -> dict:
        return {"health": self.health, "metrics": self.metrics}


def _idempotency_master_keys() -> list:
    """Master key(s) for the idempotency ledger. Reuses the keystore master key by default so a
    deployment has one secret to manage; a dedicated key may be supplied via env."""
    dedicated = os.environ.get("AGENTGUARD_IDEMPOTENCY_MASTER_KEY")
    if dedicated:
        return [dedicated.encode()]
    base = os.environ.get("AGENT_IDENTITY_MASTER_KEY")
    if not base:
        raise ValueError("AGENT_IDENTITY_MASTER_KEY (or AGENTGUARD_IDEMPOTENCY_MASTER_KEY) is required")
    return [base.encode()]


def build_ha(pg_storage, security_state, identity_cfg: Optional[IdentityConfig] = None, *,
             instance_id: Optional[str] = None, metrics: Optional[_M.Metrics] = None,
             spiffe_health: Optional[Callable[[], bool]] = None,
             kms_health: Optional[Callable[[], bool]] = None,
             trust_health: Optional[Callable[[], bool]] = None,
             coordination_interval_seconds: float = 300.0,
             enable_scheduler: bool = True) -> HaRuntime:
    """Compose the Step 7 HA runtime over existing PostgreSQL + Redis storage."""
    from ..api.service import IdentityService

    cfg = (identity_cfg or IdentityConfig()).validate()
    m = metrics or getattr(security_state, "metrics", None) or _M.Metrics()
    iid = instance_id or ("inst_" + os.urandom(8).hex())

    idem = PgIdempotencyStore(pg_storage.db, _idempotency_master_keys())
    agents, revs = security_state.wrap_storage(pg_storage.agents, pg_storage.revocations)
    kw = pg_storage.service_kwargs()
    kw.update(agents=agents, revocations=revs, replay=security_state.replay,
              idempotency=idem, instance_id=iid, metrics=m)
    svc = IdentityService(cfg, **kw)

    runner = CoordinationRunner(pg_storage.db, instance_id=iid, metrics=m)
    jobs = {
        "purge_expired_material": svc.purge_expired_material,
        "purge_idempotency": lambda: idem.purge_expired(svc.clock.now()),
        "reconcile": lambda: _reconcile(pg_storage, svc, m),
    }
    scheduler = (PeriodicScheduler(runner, jobs, interval_seconds=coordination_interval_seconds)
                 if enable_scheduler else None)

    health = HealthAggregator(instance_id=iid, db=pg_storage.db, state=security_state,
                              spiffe=spiffe_health, kms=kms_health, trust=trust_health, metrics=m)
    return HaRuntime(svc, idem, runner, health, m, scheduler)


def _reconcile(pg_storage, svc, metrics) -> int:
    """Periodic consistency check. Read-only: counts drift, never mutates security state.

    Detects (a) organizations whose active issuer certificate is missing (a crash between the two
    writes of register_organization) and (b) credentials past expiry whose service-held key still
    exists. Both are surfaced as metrics for operators; repair is an explicit admin action.
    """
    drift = 0
    now = svc.clock.now()
    for org in _all_orgs(pg_storage):
        if pg_storage.trust.get_issuer_cert(org.active_issuer_key_id) is None:
            drift += 1
    for c in pg_storage.credentials.list_all():
        if c.key_id and now >= c.expires_at and pg_storage.keystore.has_key(c.key_id):
            drift += 1
    metrics.inc("agentguard_reconciliation_runs_total")
    if drift:
        metrics.inc("agentguard_reconciliation_drift_total", "", drift)
    return drift


def _all_orgs(pg_storage):
    rows = pg_storage.db.run("list_orgs", lambda c: c.execute(
        "SELECT org_id, active_issuer_key_id FROM organizations").fetchall())
    from ..core.models import Organization, Status
    return [Organization(r["org_id"], "", 0.0, Status.ACTIVE, r["active_issuer_key_id"]) for r in rows]
