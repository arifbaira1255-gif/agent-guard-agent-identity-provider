"""Phase 7 assurance-plane exception hierarchy.

Every message is a fixed, non-secret code or a short human string. Nothing here ever carries key
material, tokens, payloads or credentials.
"""
from __future__ import annotations

from ..core.errors import IdentityError


class AssuranceError(IdentityError):
    code = "assurance_error"


# --------------------------------------------------------------------------- policy intelligence
class RecommendationError(AssuranceError):
    code = "recommendation_error"


class SignalError(AssuranceError):
    code = "signal_error"


# --------------------------------------------------------------------------- policy lifecycle
class ProposalError(AssuranceError):
    code = "proposal_error"


class ProposalValidationError(ProposalError):
    code = "proposal_validation_error"


class ProposalConflictError(ProposalError):
    code = "proposal_conflict"


class UnsafeChangeError(ProposalError):
    """A proposed change would broaden privilege, weaken tenant isolation or disable a control."""

    code = "unsafe_change"


class ApprovalRequiredError(ProposalError):
    code = "approval_required"


# --------------------------------------------------------------------------- audit integrity
class AuditIntegrityError(AssuranceError):
    code = "audit_integrity_error"


class AuditVerificationError(AuditIntegrityError):
    code = "audit_verification_failed"


class CheckpointError(AuditIntegrityError):
    code = "checkpoint_error"


class SigningUnavailableError(AuditIntegrityError):
    """The signing key/KMS is unavailable. Audit writes that require a signature fail closed."""

    code = "signing_unavailable"


# --------------------------------------------------------------------------- compliance
class ComplianceError(AssuranceError):
    code = "compliance_error"


class UnknownFrameworkError(ComplianceError):
    code = "unknown_framework"


# --------------------------------------------------------------------------- SIEM
class SiemError(AssuranceError):
    code = "siem_error"


class SiemConfigError(SiemError):
    code = "siem_config_error"


class SiemDeliveryError(SiemError):
    code = "siem_delivery_error"


class BackpressureError(SiemError):
    """The delivery queue is full and the configured policy is to reject rather than drop."""

    code = "backpressure"


class RedactionError(SiemError):
    code = "redaction_error"
