"""Agent-side helper for the recommended deployment mode: the agent generates and
keeps its own ephemeral private key; only the public key + proof-of-possession (CSR)
is sent to the identity service. The service never sees this private key."""
import time
from typing import Optional

from ..core.ids import new_nonce
from . import keys
from .encoding import b64u_encode


class AgentSideKey:
    def __init__(self):
        self._priv = keys.generate_private_key()
        self.public_key = b64u_encode(keys.public_bytes(self._priv))

    def csr(self, agent_id: str, instance_id: str) -> dict:
        sig = keys.sign(self._priv, keys.DOMAIN_CSR,
                        keys.csr_bytes(agent_id, instance_id, self.public_key))
        return {"public_key": self.public_key, "pop_signature": b64u_encode(sig)}

    def make_proof(self, credential_id: str, audience: str, *, request_id: Optional[str] = None,
                   nonce: Optional[str] = None, timestamp: Optional[int] = None) -> dict:
        proof = {"credential_id": credential_id, "nonce": nonce or new_nonce(),
                 "timestamp": int(timestamp if timestamp is not None else time.time()),
                 "request_id": request_id or new_nonce(), "audience": audience}
        proof["signature"] = b64u_encode(keys.sign(self._priv, keys.DOMAIN_PROOF,
                                                    keys.proof_bytes(proof)))
        return proof

    def __repr__(self):
        return f"AgentSideKey(public_key={self.public_key[:8]}...)"
