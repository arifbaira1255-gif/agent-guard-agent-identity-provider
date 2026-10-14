"""SPIFFE ID parsing (per the SPIFFE-ID spec) and the deterministic AgentGuard mapping.

Mapping (one-to-one, no wildcards, no free-form paths):
    agent    : spiffe://<td>/org/<org_id>/agent/<agent_id>
    instance : spiffe://<td>/org/<org_id>/agent/<agent_id>/instance/<instance_id>
"""
import re
from dataclasses import dataclass
from typing import Optional

from .errors import SpiffeIdError

_TD = re.compile(r"^[a-z0-9._-]{1,255}$")
_SEG = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")      # AgentGuard ids embedded in paths
MAX_LEN = 2048


@dataclass(frozen=True)
class SpiffeId:
    trust_domain: str
    path: str

    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"


def parse_spiffe_id(value) -> SpiffeId:
    if not isinstance(value, str) or not value or len(value) > MAX_LEN:
        raise SpiffeIdError("invalid spiffe id")
    if not value.startswith("spiffe://"):
        raise SpiffeIdError("scheme must be spiffe")
    rest = value[len("spiffe://"):]
    if any(c in rest for c in "?#@:%\\ \t\r\n") or not rest.isascii():
        raise SpiffeIdError("forbidden character")
    td, sep, path = rest.partition("/")
    if not _TD.match(td):
        raise SpiffeIdError("invalid trust domain")
    if not sep:
        return SpiffeId(td, "")          # trust-domain ID (valid SPIFFE ID, not a workload)
    segs = path.split("/")
    for s in segs:
        if s in ("", ".", "..") or not _SEG.match(s):
            raise SpiffeIdError("invalid path segment")
    return SpiffeId(td, "/" + path)


def agent_spiffe_id(trust_domain: str, org_id: str, agent_id: str,
                    instance_id: Optional[str] = None) -> str:
    for v in (org_id, agent_id) + ((instance_id,) if instance_id else ()):
        if not isinstance(v, str) or not _SAFE.match(v):
            raise SpiffeIdError("id not safe for SPIFFE path")
    sid = f"spiffe://{trust_domain}/org/{org_id}/agent/{agent_id}"
    if instance_id:
        sid += f"/instance/{instance_id}"
    return str(parse_spiffe_id(sid))


@dataclass(frozen=True)
class AgentSpiffeParts:
    trust_domain: str
    org_id: str
    agent_id: str
    instance_id: Optional[str]


def parse_agent_spiffe_id(value) -> AgentSpiffeParts:
    """Strict inverse of agent_spiffe_id(); anything else is rejected (no prefix matching)."""
    sid = parse_spiffe_id(value) if not isinstance(value, SpiffeId) else value
    segs = sid.path.split("/")[1:]
    if len(segs) == 4 and segs[0] == "org" and segs[2] == "agent":
        return AgentSpiffeParts(sid.trust_domain, segs[1], segs[3], None)
    if len(segs) == 6 and segs[0] == "org" and segs[2] == "agent" and segs[4] == "instance":
        return AgentSpiffeParts(sid.trust_domain, segs[1], segs[3], segs[5])
    raise SpiffeIdError("not an AgentGuard agent SPIFFE ID")
