"""Ed25519 primitives. Domain separation prevents cross-protocol signature reuse."""
import hashlib
from functools import lru_cache
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .encoding import b64u_decode, b64u_encode, canonical_json

DOMAIN_PASSPORT = b"agentguard-passport-v1\n"
DOMAIN_ISSUER_CERT = b"agentguard-issuer-cert-v1\n"
DOMAIN_INSTANCE_BINDING = b"agentguard-instance-binding-v1\n"
DOMAIN_PROOF = b"agentguard-proof-v1\n"
DOMAIN_CSR = b"agentguard-csr-v1\n"


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)


def private_raw(priv: Ed25519PrivateKey) -> bytes:
    """Internal use by KeyStore implementations only."""
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())


def private_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def fingerprint(pub_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub_raw).hexdigest()


def fingerprint_b64(pub_b64: str) -> str:
    return fingerprint(b64u_decode(pub_b64))


def sign(priv: Ed25519PrivateKey, domain: bytes, data: bytes) -> bytes:
    return priv.sign(domain + data)


@lru_cache(maxsize=4096)
def _load_public(pub_b64: str) -> Ed25519PublicKey:
    raw = b64u_decode(pub_b64)
    if len(raw) != 32:
        raise ValueError("bad public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def validate_public_key_b64(pub_b64: str) -> bytes:
    raw = b64u_decode(pub_b64)
    if len(raw) != 32:
        raise ValueError("bad public key length")
    _load_public(pub_b64)
    return raw


def verify(pub_b64: str, domain: bytes, data: bytes, signature: bytes) -> bool:
    try:
        _load_public(pub_b64).verify(signature, domain + data)
        return True
    except (InvalidSignature, ValueError):
        return False


def csr_bytes(agent_id: str, instance_id: str, public_key_b64: str) -> bytes:
    return canonical_json({"agent_id": agent_id, "instance_id": instance_id,
                           "public_key": public_key_b64})


def cert_body(issuer_key_id: str, org_id: str, public_key: str, root_key_id: str,
              issued_at: float) -> bytes:
    return canonical_json({"issuer_key_id": issuer_key_id, "org_id": org_id,
                           "public_key": public_key, "root_key_id": root_key_id,
                           "issued_at": int(issued_at)})


def binding_bytes(agent_id: str, instance_id: str, org_id: str, agent_key_id: str,
                  created_at: float) -> bytes:
    return canonical_json({"agent_id": agent_id, "instance_id": instance_id,
                           "org_id": org_id, "agent_key_id": agent_key_id,
                           "created_at": int(created_at)})


def proof_bytes(proof: dict) -> bytes:
    return canonical_json({"v": 1, "credential_id": proof["credential_id"],
                           "nonce": proof["nonce"], "timestamp": proof["timestamp"],
                           "request_id": proof["request_id"],
                           "audience": proof["audience"]})
