"""Phase 7 tamper-evident audit chain.

What this provides (stated precisely)
-------------------------------------
* **Canonical serialization** -- every record is hashed over a fixed, sorted-key, whitespace-free
  JSON projection of a closed field set, so the hash is reproducible across processes and languages.
* **Hash chaining** -- ``hash = SHA-256(prev_hash || canonical(record))`` per tenant, built in
  INSERTION order. A modified, reordered or removed record is DETECTED by :meth:`verify_chain`.
* **Digital signatures** -- each record's ``hash`` is signed (Ed25519) through the EXISTING KMS/HSM
  layer (``kms.interfaces.KeyManagementProvider``). Private signing keys never live in application
  code. ``key_id``/``key_version`` are recorded so a record stays verifiable across key rotation.
* **Signed checkpoints** -- a periodic signed digest of the chain head. A checkpoint is the ONLY
  mechanism that can detect TRUNCATION of the tail: without an externally retained checkpoint, an
  attacker who controls all storage can delete the last N records and the remaining chain still
  verifies. Checkpoints are intended to be exported/anchored externally.

Threat model and honest limits
------------------------------
This is **tamper-EVIDENT, not tamper-PROOF**. Hash chaining alone does not prevent deletion or
truncation, especially if an attacker controls all relevant storage and checkpoints. Signatures
raise the bar (an attacker without the signing key cannot forge a record or a checkpoint) but do not
make the log immutable. Do NOT describe this as absolutely immutable or tamper-proof. See
``docs/PHASE7_SECURITY_LIMITATIONS.md``.
"""
from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from ..crypto.encoding import b64u_decode, b64u_encode
from ..observability.logging import SecurityLogger, current_correlation_id
from ..security.ids import new_id
from .config import AssuranceConfig
from .errors import AuditIntegrityError, CheckpointError, SigningUnavailableError
from .models import AuditChainRecord, AuditCheckpoint
from .store import AssuranceStore

#: Fields that participate in the hash. Everything else is carried alongside but not hashed.
_HASH_FIELDS = ("seq", "record_id", "org_id", "ts", "event", "actor_user_id", "outcome", "reason",
                "payload_digest", "correlation_id", "detail")


def _canonical(record: dict) -> str:
    payload = {k: record.get(k) for k in _HASH_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: Optional[str], record: dict) -> str:
    """SHA-256 over ``prev_hash`` + the canonical record."""
    blob = f"{prev_hash or ''}|{_canonical(record)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- signers
class AuditSigner(ABC):
    """Signs/verifies a chain hash. Implementations MUST fail closed (raise) when unavailable."""

    name = "abstract"

    @property
    def available(self) -> bool:
        return True

    @abstractmethod
    def sign(self, data: bytes) -> Tuple[str, str, Optional[int]]:
        """Return ``(signature_b64, key_id, key_version)``. Raises when signing is unavailable."""

    @abstractmethod
    def verify(self, data: bytes, signature_b64: str, key_id: str,
               key_version: Optional[int]) -> bool:
        """Return True only for a valid signature. Raises only for a malformed signature."""


class KmsAuditSigner(AuditSigner):
    """Signs through the EXISTING KMS/HSM provider. Private keys never leave the provider."""

    name = "kms"

    def __init__(self, provider, key_id: str, *, domain: str = "agentguard:audit:v1"):
        self.provider = provider
        self.key_id = key_id
        self.domain = domain.encode("utf-8")

    @property
    def available(self) -> bool:
        try:
            return bool(self.provider.health_check())
        except Exception:                                            # noqa: BLE001
            return False

    def sign(self, data: bytes) -> Tuple[str, str, Optional[int]]:
        try:
            sig = self.provider.sign(self.key_id, self.domain, data)
            _, _, version = self.provider.public_key(self.key_id)
        except Exception as e:                                       # noqa: BLE001
            raise SigningUnavailableError("audit signing key unavailable") from e
        return b64u_encode(sig), self.key_id, version

    def verify(self, data: bytes, signature_b64: str, key_id: str,
               key_version: Optional[int]) -> bool:
        try:
            sig = b64u_decode(signature_b64)
        except ValueError:
            return False
        try:
            _, pub_b64, _ = self.provider.public_key(key_id, key_version)
        except Exception:                                            # noqa: BLE001
            return False
        try:
            return bool(self.provider.verify(pub_b64, self.domain, data, sig))
        except Exception:                                            # noqa: BLE001
            return False


class LocalEd25519Signer(AuditSigner):
    """Development/test-only in-process Ed25519 signer. Refuses to run in staging/production."""

    name = "local-ed25519"

    def __init__(self, key_id: str = "audit_signing", *, environment: str = "development",
                 domain: str = "agentguard:audit:v1"):
        if environment in ("staging", "production"):
            raise SigningUnavailableError("local audit signer is disabled outside development")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.key_id = key_id
        self.domain = domain.encode("utf-8")
        self._sk = Ed25519PrivateKey.generate()
        self._pk = self._sk.public_key()

    def sign(self, data: bytes) -> Tuple[str, str, Optional[int]]:
        return b64u_encode(self._sk.sign(self.domain + data)), self.key_id, 1

    def verify(self, data: bytes, signature_b64: str, key_id: str,
               key_version: Optional[int]) -> bool:
        if key_id != self.key_id:
            return False
        try:
            sig = b64u_decode(signature_b64)
        except ValueError:
            return False
        try:
            self._pk.verify(sig, self.domain + data)
            return True
        except Exception:                                            # noqa: BLE001
            return False


class NullSigner(AuditSigner):
    """Explicitly unsigned mode. Only permitted when ``audit_require_signature`` is False."""

    name = "null"

    @property
    def available(self) -> bool:
        return True

    def sign(self, data: bytes) -> Tuple[str, str, Optional[int]]:
        return "", "", None

    def verify(self, data: bytes, signature_b64: str, key_id: str,
               key_version: Optional[int]) -> bool:
        return True


# --------------------------------------------------------------------------- the chain
class TamperEvidentAudit:
    """Append-only, hash-chained, signed audit log for the assurance plane."""

    def __init__(self, store: AssuranceStore, *, config: Optional[AssuranceConfig] = None,
                 signer: Optional[AuditSigner] = None, logger: Optional[SecurityLogger] = None,
                 clock=None):
        self.store = store
        self.cfg = config or AssuranceConfig()
        self.logger = logger
        self._clock = clock
        if signer is None:
            if self.cfg.audit_require_signature:
                raise SigningUnavailableError("a signer is required when audit_require_signature=True")
            signer = NullSigner()
        self.signer = signer
        if self.cfg.audit_require_signature and isinstance(signer, NullSigner):
            raise SigningUnavailableError("NullSigner is not permitted when signatures are required")

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ append
    def record(self, event: str, *, org_id: Optional[str] = None,
               actor_user_id: Optional[str] = None, outcome: str = "ok",
               reason: Optional[str] = None, payload=None, correlation_id: Optional[str] = None,
               detail: Optional[dict] = None) -> AuditChainRecord:
        """Append one record. Fails closed when the store or the signer is unavailable."""
        cid = correlation_id or current_correlation_id()
        head = self.store.audit_chain_head(org_id=org_id)
        prev_hash = head.hash if head is not None else None
        seq = (head.seq + 1) if head is not None else 1
        payload_digest = None
        if payload is not None:
            blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            payload_digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        bounded_detail = None
        if detail:
            bounded_detail = {k: v for k, v in detail.items()
                              if isinstance(v, (str, int, float, bool)) or v is None}
        rec = {"seq": seq, "record_id": new_id("aud"), "org_id": org_id, "ts": self._now(),
               "event": event, "actor_user_id": actor_user_id, "outcome": outcome, "reason": reason,
               "payload_digest": payload_digest, "correlation_id": cid, "detail": bounded_detail}
        h = compute_hash(prev_hash, rec)
        signature = key_id = None
        key_version = None
        if not isinstance(self.signer, NullSigner):
            signature, key_id, key_version = self.signer.sign(h.encode("utf-8"))
        record = AuditChainRecord(prev_hash=prev_hash, hash=h, signature=signature, key_id=key_id,
                                  key_version=key_version, **rec)
        try:
            self.store.append_audit(record)
        except Exception as e:                                       # noqa: BLE001
            if self.cfg.audit_fail_closed:
                raise AuditIntegrityError("audit store unavailable; refusing to proceed") from e
            raise
        if self.logger is not None:
            self.logger.emit(event, outcome=outcome, reason=reason, org_id=org_id,
                             actor=actor_user_id, target_type="audit", target_id=record.record_id,
                             correlation_id=cid)
        # periodic signed checkpoint
        if self.cfg.audit_checkpoint_interval and seq % self.cfg.audit_checkpoint_interval == 0:
            self.checkpoint(org_id=org_id)
        return record

    # ------------------------------------------------------------------ checkpoints
    def checkpoint(self, *, org_id: Optional[str] = None) -> Optional[AuditCheckpoint]:
        head = self.store.audit_chain_head(org_id=org_id)
        if head is None:
            return None
        count = self.store.audit_count(org_id=org_id)
        cp = {"checkpoint_id": new_id("ckp"), "org_id": org_id, "seq": head.seq,
              "head_hash": head.hash, "record_count": count, "ts": self._now()}
        signature = key_id = None
        key_version = None
        if not isinstance(self.signer, NullSigner):
            blob = json.dumps(cp, sort_keys=True, separators=(",", ":"), default=str)
            signature, key_id, key_version = self.signer.sign(
                hashlib.sha256(blob.encode("utf-8")).digest())
        out = AuditCheckpoint(signature=signature, key_id=key_id, key_version=key_version, **cp)
        self.store.put_checkpoint(out)
        return out

    # ------------------------------------------------------------------ verification
    def verify_chain(self, *, org_id: Optional[str] = None, limit: Optional[int] = None
                     ) -> dict:
        """Recompute the chain and report the first divergence.

        Returns ``{"ok", "checked", "broken_at", "reason", "signatures_verified"}``.
        """
        cap = limit if limit is not None else self.cfg.audit_verify_limit
        rows = self.store.list_audit(org_id=org_id, limit=cap)
        # ``list_audit`` returns records in INSERTION order. We must NOT re-sort here, or
        # reordering/removal of records becomes undetectable.
        prev = None
        sig_checked = 0
        for i, r in enumerate(rows):
            if r.prev_hash != prev:
                return {"ok": False, "checked": i, "broken_at": r.record_id,
                        "reason": "prev_hash does not match the preceding record",
                        "signatures_verified": sig_checked}
            if compute_hash(prev, r.__dict__) != r.hash:
                return {"ok": False, "checked": i, "broken_at": r.record_id,
                        "reason": "record hash does not match its content",
                        "signatures_verified": sig_checked}
            if self.cfg.audit_require_signature and not isinstance(self.signer, NullSigner):
                if not r.signature:
                    return {"ok": False, "checked": i, "broken_at": r.record_id,
                            "reason": "record is missing its signature",
                            "signatures_verified": sig_checked}
                if not self.signer.verify(r.hash.encode("utf-8"), r.signature, r.key_id or "",
                                          r.key_version):
                    return {"ok": False, "checked": i, "broken_at": r.record_id,
                            "reason": "record signature is invalid",
                            "signatures_verified": sig_checked}
                sig_checked += 1
            prev = r.hash
        return {"ok": True, "checked": len(rows), "broken_at": None, "reason": "chain intact",
                "signatures_verified": sig_checked}

    def verify_checkpoint(self, checkpoint: AuditCheckpoint) -> dict:
        """Verify a checkpoint against the current chain: signature, head hash and record count.

        A mismatch on ``record_count`` or ``head_hash`` means records were removed or the chain was
        rewritten after the checkpoint was taken (tail truncation / rewrite detected).
        """
        if checkpoint.signature and not isinstance(self.signer, NullSigner):
            blob = json.dumps({"checkpoint_id": checkpoint.checkpoint_id, "org_id": checkpoint.org_id,
                               "seq": checkpoint.seq, "head_hash": checkpoint.head_hash,
                               "record_count": checkpoint.record_count, "ts": checkpoint.ts},
                              sort_keys=True, separators=(",", ":"), default=str)
            if not self.signer.verify(hashlib.sha256(blob.encode("utf-8")).digest(),
                                      checkpoint.signature, checkpoint.key_id or "",
                                      checkpoint.key_version):
                return {"ok": False, "reason": "checkpoint signature is invalid"}
        rows = self.store.list_audit(org_id=checkpoint.org_id, limit=self.cfg.audit_verify_limit)
        if len(rows) < checkpoint.record_count:
            return {"ok": False, "reason": "records were removed after the checkpoint was taken",
                    "expected": checkpoint.record_count, "found": len(rows)}
        at = next((r for r in rows if r.seq == checkpoint.seq), None)
        if at is None:
            return {"ok": False, "reason": "the checkpointed record is missing"}
        if at.hash != checkpoint.head_hash:
            return {"ok": False, "reason": "the checkpointed head hash does not match the chain"}
        return {"ok": True, "reason": "checkpoint verified", "seq": checkpoint.seq}

    def verify_all(self, *, org_id: Optional[str] = None) -> dict:
        """Verify the chain AND the latest checkpoint (the strongest available check)."""
        chain = self.verify_chain(org_id=org_id)
        cp = self.store.latest_checkpoint(org_id=org_id)
        cp_result = self.verify_checkpoint(cp) if cp is not None else {"ok": True,
                                                                      "reason": "no checkpoint"}
        return {"chain": chain, "checkpoint": cp_result,
                "ok": bool(chain.get("ok") and cp_result.get("ok"))}

    def list(self, *, org_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        return [r.public_dict() for r in self.store.list_audit(org_id=org_id, limit=limit)]
