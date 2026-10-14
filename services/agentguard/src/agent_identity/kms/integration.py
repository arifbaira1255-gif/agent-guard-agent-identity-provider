"""Composition helper: an ``IdentityService`` whose signing keys are held by a KMS/HSM provider.

This is the Step 5 <-> Step 1-4 boundary. Nothing in the identity engine changes: the service keeps
calling the ``KeyStore`` contract, and every call is served by ``KmsKeyStore`` -> provider. Callers
that already build a service with PostgreSQL/Redis storage simply pass those stores through
unchanged.

    svc, rt = build_identity_service(IdentityConfig(), KmsConfig.from_env(), root_key_id=ROOT_ID,
                                     keystore=... )   # or rely on the KMS-backed keystore
"""
from __future__ import annotations

from typing import Optional, Tuple

from ..api.service import IdentityService
from ..core.config import IdentityConfig
from .config import KmsConfig
from .factory import KmsRuntime, build_kms


def build_identity_service(identity_cfg: Optional[IdentityConfig] = None,
                           kms_cfg: Optional[KmsConfig] = None, *, root_key_id: Optional[str] = None,
                           kms_kwargs: Optional[dict] = None,
                           service_kwargs: Optional[dict] = None) -> Tuple[IdentityService, KmsRuntime]:
    """Build an ``(IdentityService, KmsRuntime)`` pair sharing one KMS key store.

    ``service_kwargs`` may carry the existing ``agents``/``credentials``/``revocations``/``trust``/
    ``replay``/``clock``/``logger`` arguments (e.g. from PostgreSQL + Redis wiring). A ``keystore``
    there is overridden by the KMS one: key custody belongs to Step 5.
    """
    identity_cfg = identity_cfg or IdentityConfig()
    kms_cfg = kms_cfg or KmsConfig.from_env()
    rt = build_kms(kms_cfg, **(kms_kwargs or {}))
    # A caller-supplied root key id must already exist (kept across restarts). If this is the first
    # run, bootstrap it in the provider so the service - which only reads the root public key - can
    # start. Never overwrite an existing root key.
    if root_key_id and not rt.keystore.has_key(root_key_id):
        rt.keystore.generate_key(root_key_id)
    kw = dict(service_kwargs or {})
    kw["keystore"] = rt.keystore                       # KMS is authoritative for key material
    svc = IdentityService(identity_cfg, root_key_id=root_key_id, **kw)
    return svc, rt