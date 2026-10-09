"""Agent Passport = signed payload. Token format:  agp1.<b64u(payload)>.<b64u(sig)>

The verifier parses the payload from the exact bytes that were signed, so there is
no re-serialisation ambiguity. There is no `alg` field: the algorithm is fixed
(Ed25519), which removes algorithm-confusion attacks."""
import hashlib
import json
from dataclasses import dataclass

from ..core.errors import TokenFormatError
from ..crypto.encoding import b64u_decode, b64u_encode, canonical_json

PREFIX = "agp1"
PASSPORT_VERSION = 1

_REQUIRED = {
    "v": int, "credential_id": str, "agent_id": str, "instance_id": str, "org_id": str,
    "issuer": str, "issuer_key_id": str, "iat": int, "nbf": int, "exp": int,
    "agent_name": str, "agent_type": str, "owner": str, "environment": str,
    "capabilities": list, "is_sub_agent": bool, "lineage": list, "public_key": str,
    "key_fingerprint": str, "spiffe_id": str,
}


@dataclass(frozen=True)
class ParsedToken:
    payload_bytes: bytes
    payload: dict
    signature: bytes


def issuer_uri(trust_domain: str, org_id: str, issuer_key_id: str) -> str:
    return f"spiffe://{trust_domain}/org/{org_id}/issuer/{issuer_key_id}"


def spiffe_id(trust_domain: str, org_id: str, agent_id: str, instance_id: str) -> str:
    return f"spiffe://{trust_domain}/org/{org_id}/agent/{agent_id}/instance/{instance_id}"


def encode_token(payload_bytes: bytes, signature: bytes) -> str:
    return f"{PREFIX}.{b64u_encode(payload_bytes)}.{b64u_encode(signature)}"


def payload_digest(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def build_payload(**kw) -> bytes:
    return canonical_json(kw)


def parse_token(token, max_bytes: int) -> ParsedToken:
    if not isinstance(token, str) or len(token) > max_bytes:
        raise TokenFormatError("bad token")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise TokenFormatError("bad token")
    try:
        payload_bytes = b64u_decode(parts[1])
        sig = b64u_decode(parts[2])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TokenFormatError("bad token")
    if not isinstance(payload, dict) or len(sig) != 64:
        raise TokenFormatError("bad token")
    for k, t in _REQUIRED.items():
        v = payload.get(k)
        if not isinstance(v, t) or (t is int and isinstance(v, bool)):
            raise TokenFormatError("bad token")
    if payload["v"] != PASSPORT_VERSION:
        raise TokenFormatError("bad token")
    if not all(isinstance(c, str) for c in payload["capabilities"] + payload["lineage"]):
        raise TokenFormatError("bad token")
    pa = payload.get("parent_agent_id")
    if pa is not None and not isinstance(pa, str):
        raise TokenFormatError("bad token")
    return ParsedToken(payload_bytes, payload, sig)


def token_credential_id(token: str, max_bytes: int = 8192) -> str:
    """Unverified peek at credential_id (for key lookup only; never for trust)."""
    return parse_token(token, max_bytes).payload["credential_id"]
