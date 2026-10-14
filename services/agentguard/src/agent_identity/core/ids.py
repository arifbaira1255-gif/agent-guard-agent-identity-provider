"""Unpredictable identifiers (all from `secrets`, >=64 bits of entropy)."""
import re
import secrets


def new_agent_id() -> str:
    return "agt_" + secrets.token_urlsafe(16)


def new_credential_id() -> str:
    return "crd_" + secrets.token_urlsafe(16)


def new_key_id() -> str:
    return "key_" + secrets.token_urlsafe(12)


def new_nonce() -> str:
    return secrets.token_urlsafe(18)


def new_correlation_id() -> str:
    return "cor_" + secrets.token_hex(8)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:48] or "agent"


def new_instance_id(agent_name: str) -> str:
    return f"{slugify(agent_name)}-instance-{secrets.token_hex(8)}"
