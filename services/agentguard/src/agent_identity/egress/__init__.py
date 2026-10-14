"""Phase 4: Enterprise Egress Security, DLP, Network Enforcement & Tool Governance.

This package is ADDITIVE to Steps 1-11. It builds on, and does not modify, the Step 11 governance
plane (``agent_identity.governance``) and the Step 10 policy plane (``agent_identity.policy``):

  * ``models``      -- closed vocabularies + immutable records for egress policy, DLP rules and
                       egress decisions. No secrets are ever stored in a record.
  * ``config``      -- fail-closed configuration (env-driven; there is no "allow everything" knob).
  * ``addresses``   -- SSRF / address-class protection: private, loopback, link-local, CGNAT,
                       multicast, reserved and cloud-metadata address blocking, plus DNS resolution
                       validation and DNS-rebinding protection.
  * ``policy``      -- destination/domain/protocol/port policy evaluation (allowlist + deny rules).
  * ``ratelimit``   -- bounded, tenant/agent-aware connection and request rate limiting.
  * ``dlp``         -- the modular Data Loss Prevention pipeline (detectors, redaction, decisions).
  * ``gateway``     -- ``SecureEgressGateway``: the single outbound enforcement chokepoint.
  * ``connectors``  -- ``EgressHttpConnector``: a DLP-aware transport that substitutes for the
                       reference ``HttpApiConnector`` inside a Step 11 ``GuardedConnector``.
  * ``audit``       -- egress/DLP audit fan-out (PostgreSQL + the existing SecurityLogger).
  * ``store``       -- persistence boundary (PostgreSQL authoritative; in-memory for tests).
  * ``service``     -- ``EgressService``: composition root + the supported ``request`` entry point.
  * ``hooks``       -- transport integration for governed outbound requests.

Honest scope: this is an APPLICATION-LEVEL egress control plane. It governs outbound traffic that is
routed through it. It does NOT transparently intercept all machine traffic -- see
``docs/PHASE4_SECURITY_LIMITATIONS.md`` for the exact deployment requirements (network namespace /
proxy / firewall) needed for transparent interception, and for the list of bypass paths.
"""
from .addresses import (AddressPolicy, AddressVerdict, DnsResolver, StaticDnsResolver,
                        SystemDnsResolver)
from .audit import EgressAudit
from .config import EgressConfig
from .connectors import EgressHttpConnector
from .dlp import (DEFAULT_RULES, Detector, DlpEngine, DlpFinding, DlpOutcome, DlpResult, DlpRule,
                  Redactor)
from .errors import (DlpBlockedError, EgressDeniedError, EgressError, EgressValidationError,
                     RateLimitedEgressError)
from .gateway import EgressDecision, EgressRequest, SecureEgressGateway
from .memory_store import MemoryEgressStore
from .models import (AddressClass, DlpAction, DlpSeverity, EgressOutcome, EgressPolicyRecord,
                     Protocol, RateLimitSpec)
from .policy import DestinationPolicy, PolicyVerdict
from .ratelimit import RateLimiter
from .service import EgressService
from .store import EgressStore

__all__ = [
    "EgressConfig", "EgressService", "EgressStore", "MemoryEgressStore", "EgressAudit",
    "SecureEgressGateway", "EgressRequest", "EgressDecision", "EgressHttpConnector",
    "EgressPolicyRecord", "EgressOutcome", "Protocol", "DlpAction", "DlpSeverity", "AddressClass",
    "RateLimitSpec", "DestinationPolicy", "PolicyVerdict", "AddressPolicy", "AddressVerdict",
    "DnsResolver", "SystemDnsResolver", "StaticDnsResolver", "RateLimiter",
    "DlpEngine", "DlpRule", "DlpFinding", "DlpResult", "DlpOutcome", "Detector", "Redactor",
    "DEFAULT_RULES",
    "EgressError", "EgressDeniedError", "EgressValidationError", "DlpBlockedError",
    "RateLimitedEgressError",
]
