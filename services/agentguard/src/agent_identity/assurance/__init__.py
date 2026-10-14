"""Phase 7 -- Self-Healing Policy Intelligence, Tamper-Evident Audit, Compliance & SIEM Integration.

A self-contained assurance plane layered on top of Phases 1-6. It reuses the existing policy engine,
KMS/HSM layer, observability stack, RBAC and audit pipelines -- it introduces no second database, no
second event pipeline and no competing authorization path.

Modules
-------
``config``                fail-closed configuration (signatures required, no auto-activation)
``models``                net-new domain records + closed vocabularies + provenance
``store``                 storage interface (PostgreSQL in production, memory for tests)
``audit``                 tamper-evident hash chain + KMS signatures + signed checkpoints
``recommendation_engine`` explainable policy recommendations from trusted signals
``lifecycle``             safe policy lifecycle (validate/simulate/approve/canary/activate/rollback)
``compliance``            control mapping + evidence reporting (SOC 2 / ISO 27001 / GDPR / EU AI Act)
``siem``                  modular SIEM export (syslog/HTTP/Splunk/Elastic/webhook) with redaction
``correlation``           cross-system event correlation (dedup, severity normalization, provenance)
``service``               composition root
"""
from .audit import (AuditSigner, KmsAuditSigner, LocalEd25519Signer, NullSigner, TamperEvidentAudit,
                    compute_hash)
from .compliance import ComplianceService
from .config import (IMPACT_LEVELS, KNOWN_FRAMEWORKS, PROPOSAL_STATES, SIEM_TRANSPORTS,
                     AssuranceConfig)
from .correlation import CorrelationService, dedup_key
from .errors import (ApprovalRequiredError, AssuranceError, AuditIntegrityError,
                     AuditVerificationError, BackpressureError, CheckpointError, ComplianceError,
                     ProposalConflictError, ProposalError, ProposalValidationError,
                     RecommendationError, RedactionError, SiemConfigError, SiemDeliveryError,
                     SiemError, SigningUnavailableError, UnsafeChangeError, UnknownFrameworkError)
from .lifecycle import PolicyLifecycleService, static_security_check
from .memory_store import MemoryAssuranceStore
from .models import (SEVERITIES, AuditChainRecord, AuditCheckpoint, ComplianceControlMapping,
                     CorrelationFinding, DeliveryStatus, EvidenceKind, ImpactLevel, PolicyProposal,
                     PolicyRecommendation, ProposalApproval, ProposalStatus, Provenance,
                     RecommendationKind, SecurityEvidence, SiemDelivery, SiemEvent,
                     VerificationStatus, normalize_severity, severity_rank)
from .recommendation_engine import RecommendationEngine
from .service import AssuranceService
from .siem import (ElasticBulkTransport, FakeTransport, HttpTransport, SiemDestination, SiemService,
                   SyslogTransport, Transport, build_transport, redact_fields)
from .store import AssuranceStore

__all__ = [
    "AssuranceConfig", "IMPACT_LEVELS", "PROPOSAL_STATES", "KNOWN_FRAMEWORKS", "SIEM_TRANSPORTS",
    "AssuranceError", "RecommendationError", "ProposalError", "ProposalValidationError",
    "ProposalConflictError", "UnsafeChangeError", "ApprovalRequiredError", "AuditIntegrityError",
    "AuditVerificationError", "CheckpointError", "SigningUnavailableError", "ComplianceError",
    "UnknownFrameworkError", "SiemError", "SiemConfigError", "SiemDeliveryError",
    "BackpressureError", "RedactionError",
    "Provenance", "EvidenceKind", "RecommendationKind", "ImpactLevel", "ProposalStatus",
    "VerificationStatus", "DeliveryStatus", "SEVERITIES", "normalize_severity", "severity_rank",
    "SecurityEvidence", "PolicyRecommendation", "ProposalApproval", "PolicyProposal",
    "AuditChainRecord", "AuditCheckpoint", "ComplianceControlMapping", "SiemEvent", "SiemDelivery",
    "CorrelationFinding",
    "AssuranceStore", "MemoryAssuranceStore",
    "AuditSigner", "KmsAuditSigner", "LocalEd25519Signer", "NullSigner", "TamperEvidentAudit",
    "compute_hash", "RecommendationEngine", "PolicyLifecycleService", "static_security_check",
    "ComplianceService", "SiemService", "SiemDestination", "Transport", "FakeTransport",
    "SyslogTransport", "HttpTransport", "ElasticBulkTransport", "build_transport", "redact_fields",
    "CorrelationService", "dedup_key", "AssuranceService",
]
