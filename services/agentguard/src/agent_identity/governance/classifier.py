"""Resource type classification.

The AUTHORITATIVE type and sensitivity of a resource come from its registry record. This module
provides the *best-effort* pre-classification used to:

* validate a descriptor before a registry lookup,
* give a registry entry a default type when the administrator did not state one, and
* give a newly registered resource a conservative default sensitivity when none was supplied.

An unrecognised type string is reported as ``None`` — the guard treats that as **unclassified** and
applies ``GovernanceConfig.unclassified_type_policy`` (deny by default). There is no "guessing" path
that turns an unknown class into a trusted one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import ResourceType, Sensitivity

#: Prefix → type inference for well-known resource-id conventions. Purely advisory: it never decides
#: sensitivity or permissions, and an explicit registered type always wins.
_PREFIX_TYPES = (
    ("tool:", ResourceType.TOOL),
    ("tool_server:", ResourceType.TOOL_SERVER),
    ("https:", ResourceType.HTTP_API),
    ("http:", ResourceType.HTTP_API),
    ("api:", ResourceType.HTTP_API),
    ("db:", ResourceType.DATABASE),
    ("database:", ResourceType.DATABASE),
    ("postgres:", ResourceType.DATABASE),
    ("fs:", ResourceType.FILESYSTEM),
    ("file:", ResourceType.FILESYSTEM),
    ("s3:", ResourceType.FILESYSTEM),
    ("shell:", ResourceType.SHELL),
    ("process:", ResourceType.SHELL),
    ("exec:", ResourceType.SHELL),
    ("cloud:", ResourceType.CLOUD),
    ("aws:", ResourceType.CLOUD),
    ("gcp:", ResourceType.CLOUD),
    ("azure:", ResourceType.CLOUD),
    ("svc:", ResourceType.INTERNAL_SERVICE),
    ("service:", ResourceType.INTERNAL_SERVICE),
    ("custom:", ResourceType.CUSTOM),
)

#: Conservative default sensitivity per type, used ONLY when a registry entry omits a sensitivity.
#: Execution surfaces default higher because a misjudged shell/cloud binding is destructive.
_DEFAULT_SENSITIVITY = {
    ResourceType.TOOL: Sensitivity.INTERNAL,
    ResourceType.TOOL_SERVER: Sensitivity.INTERNAL,
    ResourceType.HTTP_API: Sensitivity.INTERNAL,
    ResourceType.DATABASE: Sensitivity.CONFIDENTIAL,
    ResourceType.FILESYSTEM: Sensitivity.CONFIDENTIAL,
    ResourceType.SHELL: Sensitivity.RESTRICTED,
    ResourceType.CLOUD: Sensitivity.RESTRICTED,
    ResourceType.INTERNAL_SERVICE: Sensitivity.CONFIDENTIAL,
    ResourceType.CUSTOM: Sensitivity.INTERNAL,
}


@dataclass(frozen=True)
class Classification:
    """The outcome of classifying a descriptor. ``known`` False == unclassified (deny)."""

    resource_type: Optional[ResourceType]
    known: bool
    source: str            # "explicit" | "prefix" | "none"

    @property
    def value(self) -> Optional[str]:
        return self.resource_type.value if self.resource_type else None


class ResourceClassifier:
    """Stateless, deterministic classifier. No I/O, no external calls."""

    def classify_descriptor(self, *, resource_id: str, declared_type=None) -> Classification:
        """Classify a *request*. Prefers the declared type, then the id prefix, else unclassified."""
        explicit = ResourceType.coerce(declared_type) if declared_type is not None else None
        if explicit is not None:
            return Classification(explicit, True, "explicit")
        if isinstance(declared_type, str) and declared_type.strip():
            # a non-empty but unrecognised type string is explicitly UNCLASSIFIED
            return Classification(None, False, "none")
        inferred = self.infer_from_id(resource_id)
        if inferred is not None:
            return Classification(inferred, True, "prefix")
        return Classification(None, False, "none")

    @staticmethod
    def infer_from_id(resource_id: Optional[str]) -> Optional[ResourceType]:
        if not isinstance(resource_id, str):
            return None
        low = resource_id.strip().lower()
        for prefix, rtype in _PREFIX_TYPES:
            if low.startswith(prefix):
                return rtype
        return None

    @staticmethod
    def default_sensitivity(resource_type: ResourceType) -> Sensitivity:
        return _DEFAULT_SENSITIVITY.get(resource_type, Sensitivity.INTERNAL)

    @staticmethod
    def is_known_type(resource_type) -> bool:
        return ResourceType.coerce(resource_type) is not None
