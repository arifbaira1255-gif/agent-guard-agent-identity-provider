"""Canonical JSON + proof/CSR byte encoders, byte-compatible with the core library.

These mirror ``agent_identity.crypto.keys`` exactly (same domain separators, same canonical JSON
rule) so a proof produced by the SDK verifies against the same server-side verifier. They exist so
the SDK has no import-time dependency on the core package for its byte formats, and so the
cross-language conformance test can compare the SDK's output against the core's.
"""
from __future__ import annotations

import json
from typing import Any

DOMAIN_PROOF = b"agentguard-proof-v1\n"
DOMAIN_CSR = b"agentguard-csr-v1\n"


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, ASCII-escaped \u2014 identical to the core rule."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def proof_bytes(proof: dict) -> bytes:
    return canonical_json({
        "v": 1,
        "credential_id": proof["credential_id"],
        "nonce": proof["nonce"],
        "timestamp": proof["timestamp"],
        "request_id": proof["request_id"],
        "audience": proof["audience"],
    })


def csr_bytes(agent_id: str, instance_id: str, public_key_b64: str) -> bytes:
    return canonical_json({"agent_id": agent_id, "instance_id": instance_id,
                           "public_key": public_key_b64})
