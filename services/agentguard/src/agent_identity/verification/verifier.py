"""Credential verifier. Fails closed: any unexpected exception => invalid."""
from typing import Optional

from ..core.clock import Clock
from ..core.config import IdentityConfig
from ..core.errors import TokenFormatError
from ..core.ids import new_correlation_id
from ..core.models import (Reason, Status, TargetType, VerificationResult, iso)
from ..credentials.passport import issuer_uri, parse_token, payload_digest
from ..crypto import keys
from ..crypto.encoding import b64u_decode
from ..observability.logging import SecurityLogger
from ..storage.interfaces import (AgentRegistry, CredentialRegistry, ReplayCache,
                                  RevocationRegistry, TrustStore)


class _Fail(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class Verifier:
    def __init__(self, config: IdentityConfig, trust: TrustStore, agents: AgentRegistry,
                 credentials: CredentialRegistry, revocations: RevocationRegistry,
                 replay: ReplayCache, clock: Clock, logger: SecurityLogger):
        self.cfg, self.trust, self.agents = config, trust, agents
        self.credentials, self.revocations = credentials, revocations
        self.replay, self.clock, self.log = replay, clock, logger
        self._chain_ok = set()   # cache of (issuer_key_id, root signature) already verified

    # ------------------------------------------------------------------ public
    def verify_credential(self, token: str, *, expected_agent_id: Optional[str] = None,
                          expected_instance_id: Optional[str] = None,
                          proof: Optional[dict] = None, audience: Optional[str] = None,
                          require_proof: Optional[bool] = None,
                          correlation_id: Optional[str] = None) -> VerificationResult:
        cid = correlation_id or new_correlation_id()
        ctx = {}
        try:
            res = self._verify(token, expected_agent_id, expected_instance_id, proof,
                               audience, self.cfg.require_proof if require_proof is None
                               else require_proof, cid, ctx)
        except _Fail as f:
            res = VerificationResult(valid=False, reason=f.reason, correlation_id=cid,
                                     **ctx)
        except TokenFormatError:
            res = VerificationResult(valid=False, reason=Reason.MALFORMED_TOKEN,
                                     correlation_id=cid)
        except Exception:  # noqa: BLE001 - fail closed, never leak details
            res = VerificationResult(valid=False, reason=Reason.INTERNAL_ERROR,
                                     correlation_id=cid)
        self.log.emit("credential.verify", result="valid" if res.valid else "invalid",
                      reason=res.reason, agent_id=res.agent_id, instance_id=res.instance_id,
                      credential_id=res.credential_id, correlation_id=cid,
                      audience=audience)
        return res

    # ---------------------------------------------------------------- internals
    def _chain_valid(self, cert) -> bool:
        ck = (cert.issuer_key_id, cert.signature)
        if ck in self._chain_ok:
            return True
        root = self.trust.get_root(cert.root_key_id)
        if root is None:
            return False
        body = keys.cert_body(cert.issuer_key_id, cert.org_id, cert.public_key,
                              cert.root_key_id, cert.issued_at)
        try:
            ok = keys.verify(root, keys.DOMAIN_ISSUER_CERT, body, b64u_decode(cert.signature))
        except ValueError:
            ok = False
        if ok and keys.fingerprint_b64(cert.public_key) == cert.fingerprint:
            self._chain_ok.add(ck)
            return True
        return False

    def _verify(self, token, exp_agent, exp_inst, proof, audience, need_proof, cid, ctx):
        now = self.clock.now()
        p_ = parse_token(token, self.cfg.max_token_bytes)
        p = p_.payload

        cert = self.trust.get_issuer_cert(p["issuer_key_id"])
        if cert is None:
            raise _Fail(Reason.UNKNOWN_ISSUER)
        if not self._chain_valid(cert):
            raise _Fail(Reason.UNTRUSTED_ISSUER_CHAIN)
        if not keys.verify(cert.public_key, keys.DOMAIN_PASSPORT, p_.payload_bytes,
                           p_.signature):
            raise _Fail(Reason.INVALID_SIGNATURE)

        # Signature is valid => claims are authentic; safe to attach for audit.
        ctx.update(agent_id=p["agent_id"], instance_id=p["instance_id"],
                   credential_id=p["credential_id"], issuer=p["issuer"],
                   expires_at=iso(p["exp"]))

        if (p["org_id"] != cert.org_id or
                p["issuer"] != issuer_uri(self.cfg.trust_domain, cert.org_id,
                                          cert.issuer_key_id)):
            raise _Fail(Reason.ISSUER_MISMATCH)
        if cert.status == "revoked":
            raise _Fail(Reason.ISSUER_REVOKED)
        if cert.not_after is not None and now >= cert.not_after:
            raise _Fail(Reason.ISSUER_KEY_RETIRED)

        skew = self.cfg.clock_skew_seconds
        if now + skew < p["nbf"]:
            raise _Fail(Reason.NOT_YET_VALID)
        if now >= p["exp"]:
            raise _Fail(Reason.EXPIRED)
        if p["exp"] - p["iat"] > self.cfg.max_credential_ttl_seconds:
            raise _Fail(Reason.TTL_EXCEEDS_POLICY)

        # --- registry cross-checks (defeats substitution / privilege confusion) ---
        rec = self.credentials.get(p["credential_id"])
        if rec is None:
            raise _Fail(Reason.UNKNOWN_CREDENTIAL)
        if (rec.payload_digest != payload_digest(p_.payload_bytes) or
                rec.agent_id != p["agent_id"] or rec.instance_id != p["instance_id"]):
            raise _Fail(Reason.CREDENTIAL_MISMATCH)
        agent = self.agents.get_agent(p["agent_id"])
        if agent is None:
            raise _Fail(Reason.UNKNOWN_AGENT)
        inst = self.agents.get_instance(p["instance_id"])
        if inst is None:
            raise _Fail(Reason.UNKNOWN_INSTANCE)
        if inst.agent_id != agent.agent_id or agent.org_id != p["org_id"]:
            raise _Fail(Reason.REGISTRY_MISMATCH)
        if (sorted(p["capabilities"]) != sorted(agent.capabilities) or
                p["parent_agent_id"] != agent.parent_agent_id or
                p["is_sub_agent"] != (agent.parent_agent_id is not None) or
                list(p["lineage"]) != list(agent.lineage) or
                p["key_fingerprint"] != rec.key_fingerprint or
                keys.fingerprint_b64(p["public_key"]) != p["key_fingerprint"]):
            raise _Fail(Reason.REGISTRY_MISMATCH)
        if exp_agent is not None and exp_agent != agent.agent_id:
            raise _Fail(Reason.AGENT_MISMATCH)
        if exp_inst is not None and exp_inst != inst.instance_id:
            raise _Fail(Reason.INSTANCE_MISMATCH)

        # --- lifecycle state ---
        org = self.agents.get_org(agent.org_id)
        if org is None or org.status != Status.ACTIVE:
            raise _Fail(Reason.ORG_NOT_ACTIVE)
        if agent.status != Status.ACTIVE:
            raise _Fail(Reason.AGENT_NOT_ACTIVE)
        if inst.status != Status.ACTIVE:
            raise _Fail(Reason.INSTANCE_NOT_ACTIVE)
        if not agent.key_valid(inst.agent_key_id, now):
            raise _Fail(Reason.AGENT_KEY_RETIRED)
        for anc_id in agent.lineage:
            anc = self.agents.get_agent(anc_id)
            if anc is None or anc.status != Status.ACTIVE or \
                    self.revocations.is_revoked(TargetType.AGENT, anc_id, now):
                raise _Fail(Reason.ANCESTOR_NOT_ACTIVE)

        # --- revocation ---
        R = self.revocations
        if (R.is_revoked(TargetType.CREDENTIAL, p["credential_id"], now) or
                R.is_revoked(TargetType.INSTANCE, inst.instance_id, now) or
                R.is_revoked(TargetType.AGENT, agent.agent_id, now) or
                R.is_revoked(TargetType.ISSUER_KEY, cert.issuer_key_id, now)):
            raise _Fail(Reason.REVOKED)

        # --- proof of possession + replay (last, so invalid requests burn no nonces) ---
        if proof is None:
            if need_proof:
                raise _Fail(Reason.PROOF_REQUIRED)
        else:
            self._check_proof(proof, p, audience, now)

        return VerificationResult(
            valid=True, agent_id=agent.agent_id, instance_id=inst.instance_id,
            credential_id=p["credential_id"], issuer=p["issuer"],
            expires_at=iso(p["exp"]), org_id=agent.org_id,
            capabilities=tuple(agent.capabilities), parent_agent_id=agent.parent_agent_id,
            is_sub_agent=agent.parent_agent_id is not None,
            key_fingerprint=p["key_fingerprint"], correlation_id=cid)

    def _check_proof(self, proof, p, audience, now):
        try:
            need = ("credential_id", "nonce", "timestamp", "request_id", "audience",
                    "signature")
            if (not isinstance(proof, dict) or any(k not in proof for k in need) or
                    not all(isinstance(proof[k], str) for k in
                            ("credential_id", "nonce", "request_id", "audience", "signature")) or
                    not isinstance(proof["timestamp"], int) or
                    isinstance(proof["timestamp"], bool) or
                    not (8 <= len(proof["nonce"]) <= 128) or
                    not (1 <= len(proof["request_id"]) <= 128)):
                raise _Fail(Reason.INVALID_PROOF)
            if proof["credential_id"] != p["credential_id"]:
                raise _Fail(Reason.INVALID_PROOF)
            if not keys.verify(p["public_key"], keys.DOMAIN_PROOF, keys.proof_bytes(proof),
                               b64u_decode(proof["signature"])):
                raise _Fail(Reason.INVALID_PROOF)
        except ValueError:
            raise _Fail(Reason.INVALID_PROOF)
        if audience is not None and proof["audience"] != audience:
            raise _Fail(Reason.AUDIENCE_MISMATCH)
        window = self.cfg.proof_max_age_seconds
        skew = self.cfg.clock_skew_seconds
        if proof["timestamp"] < now - window or proof["timestamp"] > now + skew:
            raise _Fail(Reason.PROOF_STALE)
        ttl = window + skew + 5
        if not self.replay.check_and_store(f"{p['credential_id']}:{proof['nonce']}", ttl, now):
            raise _Fail(Reason.REPLAY_DETECTED)
        if not self.replay.check_and_store(f"{p['credential_id']}:req:{proof['request_id']}",
                                           ttl, now):
            raise _Fail(Reason.REPLAY_DETECTED)
