"""SSRF / address-class protection and DNS resolution validation.

This is the SSRF floor of the egress gateway. It answers one question: *is this destination address
one that an agent must never be able to reach?* -- and it answers it BEFORE any policy is consulted,
so no policy misconfiguration can open a hole.

What it blocks (by address class, not by hostname string)
---------------------------------------------------------
* loopback (127.0.0.0/8, ::1)
* private (RFC1918 10/8, 172.16/12, 192.168/16; IPv6 ULA fc00::/7)
* link-local (169.254.0.0/16, fe80::/10) -- which includes the cloud metadata address
* cloud metadata (169.254.169.254, fd00:ec2::254, and the well-known metadata hostnames)
* CGNAT (100.64.0.0/10)
* multicast (224.0.0.0/4, ff00::/8)
* reserved / documentation / benchmarking (0.0.0.0/8, 192.0.2.0/24, 198.18.0.0/15, 240.0.0.0/4, ...)
* unspecified (0.0.0.0, ::)

DNS rebinding protection
------------------------
A hostname is resolved ONCE, every returned address is classified, and the request is pinned to the
validated address set. A hostname that resolves to *any* blocked class is denied outright (a
"mixed" answer is treated as hostile). The gateway re-validates on every redirect hop, so a redirect
to a private address cannot slip through. This defeats the classic TOCTOU rebinding attack where a
name resolves to a public IP at check time and a private IP at connect time -- the gateway connects
to the address it validated, not to a fresh resolution.

Honest limit: this is application-level validation. It does not stop a process that opens a raw
socket directly (see ``docs/PHASE4_SECURITY_LIMITATIONS.md``).
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional, Protocol, Tuple

from .models import BLOCKED_ADDRESS_CLASSES, CLOUD_METADATA_HOSTS, AddressClass


@dataclass(frozen=True)
class AddressVerdict:
    """The classification of one resolved address."""

    address: str
    address_class: AddressClass
    blocked: bool
    reason: str = ""

    def to_dict(self) -> dict:
        return {"address": self.address, "class": self.address_class.value, "blocked": self.blocked,
                "reason": self.reason}


class DnsResolver(Protocol):
    """A pluggable DNS resolver. Implementations MUST be bounded (no unbounded waits)."""

    def resolve(self, host: str) -> List[str]:  # pragma: no cover - protocol
        ...


class SystemDnsResolver:
    """The default resolver: the OS resolver via ``socket.getaddrinfo``.

    It returns the deduplicated set of A/AAAA addresses. A resolution failure raises
    :class:`socket.gaierror`, which the gateway treats as a fail-closed deny.
    """

    def __init__(self, *, timeout_s: float = 3.0):
        self.timeout_s = timeout_s

    def resolve(self, host: str) -> List[str]:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        out: List[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in out:
                out.append(addr)
        return out


class StaticDnsResolver:
    """A deterministic resolver for tests: maps hostnames to fixed address lists."""

    def __init__(self, mapping: dict):
        self._mapping = {k.lower(): list(v) for k, v in mapping.items()}

    def resolve(self, host: str) -> List[str]:
        key = (host or "").lower()
        if key in self._mapping:
            return list(self._mapping[key])
        # fall back to the system resolver for unmapped names (so tests can mix)
        return SystemDnsResolver().resolve(host)


def classify_address(address: str) -> AddressClass:
    """Classify a single IP address string. An unparseable value is ``UNKNOWN`` (blocked).

    Ordering matters: Python's ``is_private`` is deliberately broad (it also covers 240.0.0.0/4,
    the documentation ranges and the benchmarking range), so the more specific classes are tested
    first and the broad ``is_private`` is the fallback for genuine RFC1918/ULA space.
    """
    try:
        ip = ipaddress.ip_address(address.strip())
    except (ValueError, AttributeError):
        return AddressClass.UNKNOWN
    if ip.is_unspecified:
        return AddressClass.UNSPECIFIED
    if ip.is_loopback:
        return AddressClass.LOOPBACK
    if ip.is_link_local:
        return AddressClass.LINK_LOCAL
    if ip.is_multicast:
        return AddressClass.MULTICAST
    # CGNAT 100.64.0.0/10 (not flagged by is_private/is_reserved on all Python versions)
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return AddressClass.CGNAT
    # Documentation / benchmarking / reserved ranges (checked before the broad is_private).
    if ip.version == 4 and (ip in ipaddress.ip_network("192.0.2.0/24")
                            or ip in ipaddress.ip_network("198.18.0.0/15")
                            or ip in ipaddress.ip_network("198.51.100.0/24")
                            or ip in ipaddress.ip_network("203.0.113.0/24")
                            or ip in ipaddress.ip_network("240.0.0.0/4")):
        return AddressClass.RESERVED
    if ip.is_reserved:
        return AddressClass.RESERVED
    if ip.is_private:
        return AddressClass.PRIVATE
    return AddressClass.PUBLIC


def is_cloud_metadata_address(address: str) -> bool:
    """True for the well-known cloud metadata addresses (belt-and-braces over the class check)."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except (ValueError, AttributeError):
        return False
    if ip.version == 4 and ip == ipaddress.ip_address("169.254.169.254"):
        return True
    if ip.version == 4 and ip == ipaddress.ip_address("169.254.170.2"):
        return True
    if ip.version == 6 and ip == ipaddress.ip_address("fd00:ec2::254"):
        return True
    return False


class AddressPolicy:
    """Classifies addresses and decides whether a destination is reachable.

    The policy is stateless and deterministic. It never performs I/O itself; the gateway supplies
    the resolved addresses (so the same validated set is used for the decision AND the connection).
    """

    def __init__(self, *, resolver: Optional[DnsResolver] = None, validate_dns: bool = True):
        self.resolver = resolver or SystemDnsResolver()
        self.validate_dns = validate_dns

    # ------------------------------------------------------------------ hostname checks
    @staticmethod
    def is_metadata_host(host: str) -> bool:
        return (host or "").strip().lower() in CLOUD_METADATA_HOSTS

    def classify_host(self, host: str) -> Tuple[AddressClass, str]:
        """Classify a *literal* IP host. Returns (class, reason). Non-IP hosts are PUBLIC."""
        try:
            ipaddress.ip_address(host.strip())
        except (ValueError, AttributeError):
            return AddressClass.PUBLIC, ""
        cls = classify_address(host)
        if is_cloud_metadata_address(host):
            cls = AddressClass.CLOUD_METADATA
        return cls, ("" if cls is AddressClass.PUBLIC else f"literal_address_{cls.value}")

    # ------------------------------------------------------------------ resolution
    def resolve_and_validate(self, host: str) -> Tuple[List[str], List[AddressVerdict], str]:
        """Resolve ``host`` and classify every address.

        Returns ``(addresses, verdicts, reason)``. ``reason`` is non-empty when the destination must
        be denied. A hostname that resolves to ANY blocked class is denied (a mixed answer is
        treated as hostile -- this is the DNS-rebinding defence).
        """
        if self.is_metadata_host(host):
            return [], [AddressVerdict(host, AddressClass.CLOUD_METADATA, True,
                                       "cloud_metadata_host")], "cloud_metadata_host"
        # A literal IP host needs no resolution.
        try:
            ipaddress.ip_address(host.strip())
            literal = True
        except (ValueError, AttributeError):
            literal = False
        if literal:
            cls, _ = self.classify_host(host)
            blocked = cls in BLOCKED_ADDRESS_CLASSES
            reason = f"blocked_address_{cls.value}" if blocked else ""
            verdict = AddressVerdict(host, cls, blocked, reason)
            if verdict.blocked:
                return [host], [verdict], reason
            return [host], [verdict], ""
        if not self.validate_dns:
            return [], [], ""
        try:
            addresses = self.resolver.resolve(host)
        except Exception as exc:  # noqa: BLE001 - any resolution failure fails closed
            return [], [], f"dns_resolution_failed:{type(exc).__name__}"
        if not addresses:
            return [], [], "dns_no_addresses"
        verdicts: List[AddressVerdict] = []
        blocked_reason = ""
        for addr in addresses:
            cls = classify_address(addr)
            if is_cloud_metadata_address(addr):
                cls = AddressClass.CLOUD_METADATA
            blocked = cls in BLOCKED_ADDRESS_CLASSES
            verdicts.append(AddressVerdict(addr, cls, blocked,
                                           f"blocked_address_{cls.value}" if blocked else ""))
            if blocked and not blocked_reason:
                blocked_reason = f"blocked_address_{cls.value}"
        return addresses, verdicts, blocked_reason

    def validate_redirect(self, host: str) -> Tuple[List[str], List[AddressVerdict], str]:
        """Re-validate a redirect target. Identical to :meth:`resolve_and_validate` (explicit name
        so the redirect path is auditable)."""
        return self.resolve_and_validate(host)
