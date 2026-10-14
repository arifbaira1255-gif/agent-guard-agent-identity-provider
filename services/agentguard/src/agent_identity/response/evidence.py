"""Phase 6 evidence preservation.

Evidence records hold REFERENCES and DIGESTS, never raw sensitive payloads: an evidence item points
at the telemetry/audit row that supports it and carries a SHA-256 digest of the referenced content so
an investigator can later prove the referenced material has not changed.

Sealing: an evidence item may be ``sealed``, which exempts it from retention purging. Sealing is the
mechanism used to preserve evidence BEFORE a destructive containment step runs (requirement 7).

Honest limitation: a digest proves the referenced bytes are unchanged *if* the reference is still
resolvable. It is not a notarization and does not survive deletion of the referenced store.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Iterable, List, Optional, Sequence

from ..security.ids import new_id
from .config import ResponseConfig
from .errors import EvidenceError
from .models import EvidenceRecord


class EvidenceService:
    """Preserves evidence references with digests, sealing and retention."""

    def __init__(self, store, *, config: Optional[ResponseConfig] = None, audit=None, clock=None):
        self.store = store
        self.cfg = config or ResponseConfig()
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    @staticmethod
    def digest(payload) -> str:
        """A stable SHA-256 digest of a JSON-serializable payload (sorted keys, no whitespace)."""
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def preserve(self, *, org_id: str, kind: str, summary: str, ref: Optional[str] = None,
                 payload=None, incident_id: Optional[str] = None, agent_id: Optional[str] = None,
                 source: str = "", seal: bool = False,
                 retention_days: Optional[int] = None) -> EvidenceRecord:
        """Record one evidence item. ``payload`` is digested, never stored."""
        if not isinstance(kind, str) or not kind.strip():
            raise EvidenceError("evidence kind is required")
        now = self._now()
        days = retention_days if retention_days is not None else self.cfg.evidence_retention_days
        e = EvidenceRecord(
            evidence_id=new_id("evd"), org_id=org_id, kind=kind.strip()[:64], ts=now,
            summary=summary[:512], ref=ref, digest=(self.digest(payload) if payload is not None
                                                    else None),
            incident_id=incident_id, agent_id=agent_id, source=source[:512],
            retention_until=now + days * 86400, sealed=bool(seal))
        self.store.put_evidence(e)
        self._audit("response.evidence.preserved", org_id=org_id, agent_id=agent_id,
                    extra={"evidence_id": e.evidence_id, "kind": e.kind,
                           "incident_id": incident_id, "sealed": e.sealed})
        return e

    def preserve_many(self, *, org_id: str, items: Sequence[dict], incident_id: Optional[str] = None,
                      agent_id: Optional[str] = None, seal: bool = False) -> List[EvidenceRecord]:
        """Preserve a batch of evidence items (used before a destructive containment step)."""
        out = []
        for item in items:
            out.append(self.preserve(org_id=org_id, kind=item.get("kind", "generic"),
                                     summary=item.get("summary", ""), ref=item.get("ref"),
                                     payload=item.get("payload"), incident_id=incident_id,
                                     agent_id=agent_id, source=item.get("source", ""), seal=seal))
        return out

    def seal(self, *, org_id: str, evidence_id: str, actor_user_id: Optional[str] = None
             ) -> EvidenceRecord:
        """Seal an evidence item so retention purging cannot remove it."""
        e = self.store.get_evidence(evidence_id, org_id=org_id)
        if e is None:
            raise EvidenceError("evidence not found")
        if e.sealed:
            return e
        import dataclasses
        e2 = dataclasses.replace(e, sealed=True)
        self.store.put_evidence(e2)
        self._audit("response.evidence.sealed", org_id=org_id, agent_id=e.agent_id,
                    actor_user_id=actor_user_id, extra={"evidence_id": evidence_id})
        return e2

    def get(self, *, org_id: str, evidence_id: str) -> Optional[EvidenceRecord]:
        return self.store.get_evidence(evidence_id, org_id=org_id)

    def list(self, *, org_id: str, incident_id: Optional[str] = None,
             limit: int = 200) -> List[EvidenceRecord]:
        return self.store.list_evidence(org_id=org_id, incident_id=incident_id, limit=limit)

    def verify(self, *, org_id: str, evidence_id: str, payload) -> bool:
        """Recompute the digest of ``payload`` and compare it with the stored one."""
        e = self.store.get_evidence(evidence_id, org_id=org_id)
        if e is None or e.digest is None:
            return False
        return self.digest(payload) == e.digest

    def apply_retention(self, *, org_id: Optional[str] = None,
                        now: Optional[float] = None) -> int:
        """Purge unsealed evidence past its retention horizon. Sealed items are never purged."""
        current = now if now is not None else self._now()
        removed = self.store.purge_evidence_before(current, org_id=org_id)
        self._audit("response.evidence.retention", org_id=org_id,
                    extra={"removed": removed, "cutoff": round(current, 3)})
        return removed

    def _audit(self, event: str, *, org_id: Optional[str] = None, agent_id: Optional[str] = None,
               outcome: str = "ok", reason: Optional[str] = None,
               actor_user_id: Optional[str] = None, extra: Optional[dict] = None) -> None:
        if self.audit is not None:
            self.audit.record(event, org_id=org_id, agent_id=agent_id, outcome=outcome,
                              reason=reason, actor_user_id=actor_user_id, extra=extra)
