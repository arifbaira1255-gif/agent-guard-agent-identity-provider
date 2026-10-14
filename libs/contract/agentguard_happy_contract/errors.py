"""Structured errors for the AgentGuard x Happy LANG integration contract.

Every failure carries a stable machine-readable ``code`` and, for validation problems, the full
list of field-level errors -- so a caller can act on the failure programmatically and a human can
see every problem at once instead of one per attempt.

Errors NEVER carry credential material: the contract models keep secrets out of ``to_dict()`` and
this module never receives them.
"""
from __future__ import annotations

from typing import Dict, List, Optional


class ContractError(Exception):
    """Base class for every contract failure."""

    code = "contract_error"

    def __init__(self, message: str = "", *, errors: Optional[List[str]] = None,
                 field: Optional[str] = None) -> None:
        self.message = message or self.code
        self.errors: List[str] = list(errors or [])
        self.field = field
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.errors:
            return f"{self.message}: " + "; ".join(self.errors)
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, field={self.field!r})"

    def to_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {"code": self.code, "message": self.message}
        if self.field:
            out["field"] = self.field
        if self.errors:
            out["errors"] = list(self.errors)
        return out


class ValidationError(ContractError):
    """A request/response/model was malformed, incomplete or out of bounds."""

    code = "validation_error"


class UnsupportedContractVersion(ContractError):
    """The peer announced a contract version this build cannot speak."""

    code = "unsupported_contract_version"


class SerializationError(ContractError):
    """A payload could not be (de)serialised safely."""

    code = "serialization_error"


class TargetTypeError(ContractError):
    """A field held the wrong Python/JSON type on the way in."""

    code = "target_type_error"


__all__ = [
    "ContractError",
    "ValidationError",
    "UnsupportedContractVersion",
    "SerializationError",
    "TargetTypeError",
]
