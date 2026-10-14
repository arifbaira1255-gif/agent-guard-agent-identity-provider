"""AWS KMS provider: real cloud KMS with non-exportable Ed25519 signing keys.

Why AWS KMS: the repository already targets PostgreSQL + Redis as its external infrastructure and
configures credentials "by reference" (env / ``_FILE`` / secret manager). AWS KMS is the natural
cloud KMS for that stack and supports Ed25519 (``ECC_NIST_EDWARDS25519``) asymmetric keys, which
is the single algorithm AgentGuard uses. Commercially equivalent GCP KMS / Azure Key Vault / HashiCorp
Vault adapters implement the same ``KeyManagementProvider`` contract; this module is the reference
cloud adapter and is deliberately isolated behind the interface.

Private keys NEVER leave AWS KMS: ``sign`` calls the KMS ``Sign`` API and only the raw public key
is fetchable (KMS does not offer export for this key spec). AgentGuard's own metadata (key id,
version, lifecycle state) is carried as KMS *tags* because AWS KMS has no first-class key versions.

IMPORTANT / UNVERIFIED: the streaming request/response shapes here follow the documented AWS KMS
API (``CreateKey``/``GetPublicKey``/``Sign``/``Verify``/``TagResource``) and the botocore client
surface, and are exercised in unit tests only against an injected fake client. No live AWS account
was available in the build environment, so **live integration has NOT been verified**. See
``docs/KMS.md`` for the exact IAM permissions and how to run the gated integration test.

Note on domain separation: AWS KMS signs the exact bytes handed to it (no domain prefix), so this
provider signs ``domain + data`` as the message and verification is performed over ``domain + data``
via the existing Ed25519 primitives - preserving AgentGuard's cross-protocol separation.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization

from ..crypto import keys
from ..crypto.encoding import b64u_encode
from .errors import (KmsAccessDeniedError, KmsConfigError, KmsKeyNotFoundError, KmsKeyStateError,
                     KmsKeyUsageError, KmsProviderError, KmsUnavailableError)
from .interfaces import KeyManagementProvider
from .models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType,
                     KmsKeyUsage, check_transition, coerce_algorithm, coerce_state,
                     coerce_usages)

SIGNING_ALGORITHM = "ED25519_SHA_512"
KEY_SPEC = "ECC_NIST_EDWARDS25519"
MANAGED_BY = "agentguard-agent-identity"

#: tag keys this provider owns. Kept namespaced so it never collides with operator tags.
_T_KEY_ID = "ag-key-id"
_T_VERSION = "ag-version"
_T_STATE = "ag-state"
_T_USAGES = "ag-usages"
_T_CREATED = "ag-created-at"
_T_PURPOSE = "ag-purpose"
_T_ORG = "ag-org"
_T_MANAGED = "ag-managed-by"

_ACCESS_DENIED = {"AccessDeniedException", "NotAuthorizedException", "InvalidCiphertextException",
                  "KMSInvalidStateException"}
_NOT_FOUND = {"NotFoundException", "KMSInvalidStateException"}
_TRANSIENT = {"ThrottlingException", "KMSInternalException", "LimitExceededException",
              "DependencyTimeoutException", "InternalFailure", "ServiceUnavailableException",
              "ConnectionError", "EndpointConnectionError", "ReadTimeoutError", "ConnectTimeoutError",
              "SSLError"}
_RETIRED_IN_USE = {"DisabledException", "KMSInvalidStateException", "InvalidKeyUsageException"}


def _exc_names(exc: BaseException) -> set:
    return {c.__name__ for c in type(exc).__mro__}


def _now() -> float:
    return time.time()


class AwsKmsProvider(KeyManagementProvider):
    name = "aws-kms"
    is_development = False
    supports_export = False

    def __init__(self, cfg, client=None):
        """``cfg`` is a :class:`agent_identity.kms.config.KmsConfig`. ``client`` may be injected
        (tests / shared session); otherwise botocore is imported lazily so the dependency is
        optional."""
        self.cfg = cfg
        self._lock = threading.RLock()
        self._cache: Dict[str, KeyMetadata] = {}
        if client is not None:
            self._client = client
        else:
            self._client = self._build_client(cfg)

    # ------------------------------------------------------------------ client
    @staticmethod
    def _build_client(cfg):
        try:
            import boto3  # type: ignore
            from botocore.config import Config  # type: ignore
        except ImportError:
            raise KmsUnavailableError(
                "boto3 is not installed (pip install 'agentguard-agent-identity[aws]')")
        bc = Config(retries={"max_attempts": cfg.retry_max_attempts, "mode": "standard"},
                    connect_timeout=cfg.connect_timeout_seconds, read_timeout=cfg.command_timeout_seconds,
                    user_agent_extra=MANAGED_BY)
        kw = {"region_name": cfg.region, "config": bc}
        if cfg.endpoint_url:
            kw["endpoint_url"] = cfg.endpoint_url
        return boto3.client("kms", **kw)

    def _call(self, op: str, **kw):
        """Bounded-retry API call. Transient errors retry; access-denied / not-found never do.
        Provider exception text is never surfaced (it can echo ARNs / request details)."""
        attempts = max(1, int(self.cfg.retry_max_attempts))
        delay = self.cfg.retry_initial_backoff_seconds
        last = None
        for i in range(attempts):
            try:
                return getattr(self._client, op)(**kw)
            except Exception as e:                                    # noqa: BLE001
                names = _exc_names(e)
                if names & {"KmsError"}:
                    raise
                if names & _ACCESS_DENIED:
                    raise KmsAccessDeniedError("key operation denied by KMS policy") from None
                if names & _NOT_FOUND:
                    raise KmsKeyNotFoundError("key not found in KMS") from None
                transient = bool(names & _TRANSIENT) or isinstance(e, (TimeoutError, ConnectionError))
                if names & _RETIRED_IN_USE:
                    # a disabled/pending-deletion key: report as key-state, not as availability
                    raise KmsKeyStateError("key is not usable in its current KMS state") from None
                last = e
                if transient and i + 1 < attempts:
                    time.sleep(min(delay, self.cfg.retry_max_backoff_seconds))
                    delay *= 2
                    continue
                if transient:
                    raise KmsUnavailableError("KMS temporarily unavailable") from None
                raise KmsProviderError("KMS operation failed") from None
        raise KmsUnavailableError("KMS temporarily unavailable") from last

    # ------------------------------------------------------------------ capability / health
    def capabilities(self) -> Tuple[KmsAlgorithm, ...]:
        return (KmsAlgorithm.ED25519,)

    def health_check(self) -> bool:
        try:
            self._call("list_keys", Limit=1)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ tag helpers
    @staticmethod
    def _tags_to_map(tag_list) -> Dict[str, str]:
        return {t.get("TagKey"): t.get("TagValue") for t in (tag_list or [])}

    def _list_managed_keys(self) -> List[str]:
        key_ids: List[str] = []
        token = None
        while True:
            kw = {"Limit": 100}
            if token:
                kw["Marker"] = token
            page = self._call("list_keys", **kw)
            for k in page.get("Keys", []):
                key_ids.append(k["KeyId"])
            token = page.get("NextMarker")
            if not page.get("Truncated") or not token:
                break
        return key_ids

    def _discover(self, key_id: str) -> KeyMetadata:
        """Reconstruct logical key metadata from KMS tags (KMS has no native versions)."""
        versions: List[KeyVersion] = []
        for kid in self._list_managed_keys():
            tags = self._tags_to_map(self._call("list_resource_tags", KeyId=kid).get("Tags"))
            if tags.get(_T_MANAGED) != MANAGED_BY or tags.get(_T_KEY_ID) != key_id:
                continue
            pub_b64, fp = self._public_of(kid) if self._is_sign_verify(tags) else (None, "")
            versions.append(self._version_from_tags(key_id, kid, tags, pub_b64, fp))
        if not versions:
            raise KmsKeyNotFoundError("unknown key")
        versions.sort(key=lambda v: v.version)
        meta = KeyMetadata(key_id, self.name, KmsAlgorithm.ED25519, KmsKeyType.ASYMMETRIC_SIGNATURE,
                           versions[-1].usages, versions[-1].org_id, versions[-1].purpose,
                           versions[0].created_at, "aws-kms")
        for v in versions:
            meta = meta.with_version(v)
        return meta

    @staticmethod
    def _is_sign_verify(tags) -> bool:
        return tags.get(_T_STATE) in (KmsKeyState.ENABLED.value, KmsKeyState.RETIRING.value,
                                      KmsKeyState.DISABLED.value)

    def _version_from_tags(self, key_id, provider_key_id, tags, pub_b64, fp) -> KeyVersion:
        def num(name, default):
            try:
                return int(tags.get(name, default))
            except (TypeError, ValueError):
                return int(default)
        usages = [u for u in (tags.get(_T_USAGES) or "").split(",") if u]
        return KeyVersion(key_id=key_id, version=num(_T_VERSION, 1), provider=self.name,
                          provider_key_id=provider_key_id, algorithm=KmsAlgorithm.ED25519,
                          key_type=KmsKeyType.ASYMMETRIC_SIGNATURE, usages=coerce_usages(usages),
                          state=coerce_state(tags.get(_T_STATE, KmsKeyState.ENABLED.value)),
                          public_key_b64=pub_b64, fingerprint=fp,
                          created_at=float(num(_T_CREATED, 0)), org_id=tags.get(_T_ORG) or None,
                          purpose=tags.get(_T_PURPOSE, ""), exportable=False)

    def _public_of(self, provider_key_id) -> Tuple[str, str]:
        resp = self._call("get_public_key", KeyId=provider_key_id)
        der = resp.get("PublicKey")
        if not isinstance(der, (bytes, bytearray)):
            raise KmsProviderError("KMS returned no public key")
        try:
            pub = serialization.load_der_public_key(bytes(der))
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except Exception:                                             # noqa: BLE001
            raise KmsProviderError("KMS public key could not be parsed") from None
        if len(raw) != 32:
            raise KmsProviderError("unexpected public key length from KMS")
        return b64u_encode(raw), keys.fingerprint(raw)

    def _set_tags(self, provider_key_id, mapping: Dict[str, str]) -> None:
        tags = [{"TagKey": k, "TagValue": v} for k, v in mapping.items() if v is not None]
        if tags:
            self._call("tag_resource", KeyId=provider_key_id, Tags=tags)

    # ------------------------------------------------------------------ creation
    def create_key(self, key_id, *, algorithm=KmsAlgorithm.ED25519, usages=(), exportable=False,
                   org_id=None, purpose="", created_by="system") -> KeyVersion:
        if exportable:
            raise KmsProviderError("AWS KMS keys are non-exportable")
        alg = coerce_algorithm(algorithm)
        if alg not in self.capabilities():
            raise KmsProviderError("unsupported algorithm")
        us = coerce_usages(usages)
        try:
            existing = self._discover(key_id)
            raise KmsProviderError("key id collision")
        except KmsKeyNotFoundError:
            pass
        resp = self._call("create_key", KeyUsage="SIGN_VERIFY", KeySpec=KEY_SPEC,
                          Description=f"AgentGuard {purpose or key_id}")
        provider_key_id = resp.get("KeyMetadata", {}).get("KeyId")
        if not provider_key_id:
            raise KmsProviderError("KMS returned no key id")
        now = _now()
        self._set_tags(provider_key_id, {
            _T_MANAGED: MANAGED_BY, _T_KEY_ID: key_id, _T_VERSION: "1",
            _T_STATE: KmsKeyState.ENABLED.value,
            _T_USAGES: ",".join(u.value for u in us), _T_CREATED: str(int(now)),
            _T_PURPOSE: purpose, _T_ORG: org_id or ""})
        pub_b64, fp = self._public_of(provider_key_id)
        return KeyVersion(key_id=key_id, version=1, provider=self.name,
                          provider_key_id=provider_key_id, algorithm=KmsAlgorithm.ED25519,
                          key_type=KmsKeyType.ASYMMETRIC_SIGNATURE, usages=us,
                          state=KmsKeyState.ENABLED, public_key_b64=pub_b64, fingerprint=fp,
                          created_at=now, enabled_at=now, org_id=org_id, purpose=purpose)

    def describe(self, key_id) -> KeyMetadata:
        meta = self._discover(key_id)
        with self._lock:
            self._cache[key_id] = meta
        return meta

    def get_version(self, key_id, version) -> KeyVersion:
        meta = self.describe(key_id)
        v = meta.version(version)
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        return v

    def public_key(self, key_id, version=None):
        meta = self.describe(key_id)
        v = meta.version(version) if version is not None else meta.active()
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        if not v.can_verify():
            raise KmsKeyStateError("key is not available for public-key retrieval")
        return keys.b64u_decode(v.public_key_b64), v.public_key_b64, v.version

    # ------------------------------------------------------------------ crypto operations
    def sign(self, key_id, domain, data, *, usage=None, version=None) -> bytes:
        meta = self.describe(key_id)
        v = meta.version(version) if version is not None else meta.active()
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        if v.state != KmsKeyState.ENABLED:
            raise KmsKeyStateError("key is not enabled for signing")
        if usage is not None and KmsKeyUsage(usage) not in v.usages:
            raise KmsKeyUsageError("key not permitted for this operation")
        resp = self._call("sign", KeyId=v.provider_key_id, Message=domain + data,
                          MessageType="RAW", SigningAlgorithm=SIGNING_ALGORITHM)
        sig = resp.get("Signature")
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            raise KmsProviderError("KMS returned an invalid signature")
        return bytes(sig)

    def verify(self, public_key_b64, domain, data, signature) -> bool:
        # KMS signs the raw bytes it is given (domain + data), so verify over the same bytes.
        return keys.verify(public_key_b64, domain, data, signature)

    # ------------------------------------------------------------------ lifecycle
    def rotate(self, key_id, *, purpose="") -> KeyVersion:
        meta = self.describe(key_id)
        for v in meta.versions:
            if v.state == KmsKeyState.ENABLED:
                self.set_state(key_id, v.version, KmsKeyState.RETIRING)
        n = max(v.version for v in meta.versions) + 1
        us = meta.usages
        resp = self._call("create_key", KeyUsage="SIGN_VERIFY", KeySpec=KEY_SPEC,
                          Description=f"AgentGuard {purpose or key_id} v{n}")
        provider_key_id = resp.get("KeyMetadata", {}).get("KeyId")
        if not provider_key_id:
            raise KmsProviderError("KMS returned no key id")
        now = _now()
        self._set_tags(provider_key_id, {
            _T_MANAGED: MANAGED_BY, _T_KEY_ID: key_id, _T_VERSION: str(n),
            _T_STATE: KmsKeyState.ENABLED.value, _T_USAGES: ",".join(u.value for u in us),
            _T_CREATED: str(int(now)), _T_PURPOSE: purpose or meta.purpose,
            _T_ORG: meta.org_id or ""})
        pub_b64, fp = self._public_of(provider_key_id)
        return KeyVersion(key_id=key_id, version=n, provider=self.name,
                          provider_key_id=provider_key_id, algorithm=KmsAlgorithm.ED25519,
                          key_type=KmsKeyType.ASYMMETRIC_SIGNATURE,
                          usages=us, state=KmsKeyState.ENABLED, public_key_b64=pub_b64,
                          fingerprint=fp, created_at=now, enabled_at=now, org_id=meta.org_id,
                          purpose=purpose or meta.purpose)

    def set_state(self, key_id, version, state, **fields) -> KeyVersion:
        v = self.get_version(key_id, version)
        check_transition(v.state, coerce_state(state))
        target = coerce_state(state)
        if target == KmsKeyState.DISABLED:
            self._call("disable_key", KeyId=v.provider_key_id)
        elif target == KmsKeyState.ENABLED and v.state == KmsKeyState.DISABLED:
            self._call("enable_key", KeyId=v.provider_key_id)
        if target in (KmsKeyState.RETIRED, KmsKeyState.REVOKED, KmsKeyState.DESTROYED):
            # schedule deletion (min 7-day window) so the key can never sign again; the logical
            # state is authoritative for verification immediately.
            try:
                self._call("schedule_key_deletion", KeyId=v.provider_key_id,
                           PendingWindowInDays=self.cfg.pending_deletion_days)
            except KmsProviderError:
                pass
        tags = {_T_STATE: target.value}
        if fields.get("retire_at") is not None:
            tags[_T_CREATED] = tags.get(_T_CREATED, str(int(v.created_at)))
        self._set_tags(v.provider_key_id, tags)
        updated = KeyVersion(**{**v.__dict__, "state": target,
                                **{k: fields[k] for k in
                                   ("retire_at", "retired_at", "revoked_at", "revoke_reason")
                                   if k in fields and fields[k] is not None}})
        with self._lock:
            self._cache.pop(key_id, None)
        return updated

    def revoke(self, key_id, version, reason) -> KeyVersion:
        return self.set_state(key_id, version, KmsKeyState.REVOKED, revoked_at=_now(),
                              revoke_reason=str(reason)[:128])

    def delete_key(self, key_id, version=None) -> None:
        if version is None:
            meta = self.describe(key_id)
            for v in meta.versions:
                try:
                    self._call("schedule_key_deletion", KeyId=v.provider_key_id,
                               PendingWindowInDays=self.cfg.pending_deletion_days)
                except KmsProviderError:
                    pass
        else:
            v = self.get_version(key_id, version)
            self._call("schedule_key_deletion", KeyId=v.provider_key_id,
                       PendingWindowInDays=self.cfg.pending_deletion_days)
        with self._lock:
            self._cache.pop(key_id, None)

    def __repr__(self) -> str:
        return f"AwsKmsProvider(region={self.cfg.region!r})"