"""PKCS#11 (HSM) provider: real hardware-backed, non-exportable Ed25519 signing.

The private key is generated *inside* the token and marked non-exportable
(``CKA_EXTRACTABLE = False``, ``CKA_SENSITIVE = True``); it can be used to sign but never read
out. This is the strongest at-rest/in-use guarantee AgentGuard can offer: the key never exists in
process memory.

``python-pkcs11`` is imported lazily and the low-level module may be injected, so this adapter is
testable against a fake module without hardware. Real operation requires a PKCS#11 library (e.g.
SoftHSM2 for CI, or a vendor .so for a real HSM) plus a token whose PIN is supplied by reference
(``AGENTGUARD_KMS_PKCS11_PIN`` / ``..._PIN_FILE``).

IMPORTANT / UNVERIFIED: no HSM was available in the build environment. The attribute/mechanism
usage follows the PKCS#11 v2.40/v3.0 EdDSA profile (``CKK_EC_EDWARDS`` + ``CKM_EDDSA``) and is
exercised only against an injected fake module. **Live HSM integration has NOT been verified.**
See ``docs/KMS.md``. SoftHSM2 note: SoftHSM2 exposes ``EDDSA`` only from v2.6 with Ed25519 enabled;
verify your vendor supports Ed25519 before relying on HSM-held passport keys.

PKCS#11 has no native key versions and no lifecycle state machine, so here the AgentGuard
``KeyMetadataStore`` is the authoritative ledger: when one is supplied, ``describe``/``get_version``
/``public_key``/``set_state`` delegate to it; otherwise the provider can only locate token objects
by label (``"<key_id>#v<version>"``) and version discovery is by probe.
"""
from __future__ import annotations

import contextlib
import threading
import time
from typing import Optional, Tuple

from ..crypto import keys
from ..crypto.encoding import b64u_encode
from .errors import (KmsConfigError, KmsKeyNotFoundError, KmsKeyStateError, KmsProviderError,
                     KmsUnavailableError)
from .interfaces import KeyManagementProvider
from .models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState, KmsKeyType,
                     coerce_algorithm, coerce_state, coerce_usages, check_transition)

MAX_PROBE_VERSIONS = 64


def _label(key_id: str, version: int) -> str:
    return f"{key_id}#v{version}"


def _der_point_to_raw(der_point: bytes) -> bytes:
    """Uncompressed EC point DER (04 || X || Y, 65 bytes) -> raw 32-byte Ed25519 public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(der_point)[-32:])
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception:                                                # noqa: BLE001
        raise KmsProviderError("token returned an unusable public key") from None
    if len(raw) != 32:
        raise KmsProviderError("unexpected public key length from token")
    return raw


class Pkcs11Provider(KeyManagementProvider):
    name = "pkcs11"
    is_development = False
    supports_export = False

    def __init__(self, cfg, module=None, metadata_store=None):
        self.cfg = cfg
        self.metadata_store = metadata_store
        self._lock = threading.RLock()
        if module is None:
            try:
                import pkcs11  # type: ignore
            except ImportError:
                raise KmsUnavailableError(
                    "python-pkcs11 is not installed (pip install 'agentguard-agent-identity[pkcs11]')")
            module = pkcs11
        self._p11 = module
        try:
            self.lib = module.lib(self.cfg.module_path)
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("PKCS#11 library could not be loaded") from None
        if not hasattr(module, "Mechanism") or getattr(module.Mechanism, "EDDSA", None) is None:
            raise KmsProviderError("PKCS#11 module does not expose CKM_EDDSA")
        self._pin = self._resolve_pin()

    # ------------------------------------------------------------------ config
    def _resolve_pin(self) -> str:
        import os
        if self.cfg.pin_file:
            try:
                with open(self.cfg.pin_file, "r", encoding="utf-8") as fh:
                    return fh.read().strip()
            except OSError:
                raise KmsConfigError("PKCS#11 PIN file could not be read")
        pin = os.environ.get("AGENTGUARD_KMS_PKCS11_PIN", "")
        if not pin:
            raise KmsConfigError("PKCS#11 PIN is required (AGENTGUARD_KMS_PKCS11_PIN / _PIN_FILE)")
        return pin

    # ------------------------------------------------------------------ session helpers
    @contextlib.contextmanager
    def _session(self):
        try:
            token = self._find_token()
            sess = token.open(user_pin=self._pin, rw=True)
        except KmsUnavailableError:
            raise
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("could not open PKCS#11 session") from None
        try:
            yield sess
        finally:
            try:
                sess.close()
            except Exception:                                        # noqa: BLE001
                pass

    def _find_token(self):
        try:
            if getattr(self.cfg, "slot", None) is not None:
                return self.lib.get_token(self.cfg.slot)
            if self.cfg.token_label:
                for slot in self.lib.get_slots():
                    t = slot.get_token()
                    if getattr(t, "label", "").strip() == self.cfg.token_label:
                        return t
            return self.lib.get_token()
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("PKCS#11 token not available") from None

    def _find_object(self, sess, label, private):
        M = self._p11
        cls = M.ObjectClass.PRIVATE_KEY if private else M.ObjectClass.PUBLIC_KEY
        try:
            objs = list(sess.get_objects({M.Attribute.CLASS: cls, M.Attribute.LABEL: label}))
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("PKCS#11 object lookup failed") from None
        if not objs:
            raise KmsKeyNotFoundError("no such key on token")
        return objs[0]

    def _templates(self, label):
        M = self._p11
        pub = {M.Attribute.CLASS: M.ObjectClass.PUBLIC_KEY, M.Attribute.KEY_TYPE: M.KeyType.EC_EDWARDS,
               M.Attribute.LABEL: label, M.Attribute.TOKEN: True, M.Attribute.VERIFY: True}
        priv = {M.Attribute.CLASS: M.ObjectClass.PRIVATE_KEY, M.Attribute.KEY_TYPE: M.KeyType.EC_EDWARDS,
                M.Attribute.LABEL: label, M.Attribute.TOKEN: True, M.Attribute.PRIVATE: True,
                M.Attribute.SENSITIVE: True, M.Attribute.EXTRACTABLE: False, M.Attribute.SIGN: True}
        return pub, priv

    def _generate(self, key_id, n) -> KeyVersion:
        M = self._p11
        label = _label(key_id, n)
        pub_t, priv_t = self._templates(label)
        try:
            with self._session() as s:
                pub, _ = s.generate_key_pair(mechanism=M.Mechanism.EDDSA, public_template=pub_t,
                                             private_template=priv_t)
                raw = _der_point_to_raw(bytes(pub[M.Attribute.EC_POINT]))
        except KmsProviderError:
            raise
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("token key generation failed") from None
        now = time.time()
        return KeyVersion(key_id=key_id, version=n, provider=self.name, provider_key_id=label,
                          algorithm=KmsAlgorithm.ED25519, key_type=KmsKeyType.ASYMMETRIC_SIGNATURE,
                          usages=(), state=KmsKeyState.ENABLED, public_key_b64=b64u_encode(raw),
                          fingerprint=keys.fingerprint(raw), created_at=now, enabled_at=now,
                          exportable=False)

    # ------------------------------------------------------------------ capability / health
    def capabilities(self) -> Tuple[KmsAlgorithm, ...]:
        return (KmsAlgorithm.ED25519,)

    def health_check(self) -> bool:
        try:
            with self._session() as s:
                s.get_objects({self._p11.Attribute.CLASS: self._p11.ObjectClass.PUBLIC_KEY})
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ discovery
    def _probe(self, key_id, version: Optional[int] = None) -> Optional[KeyVersion]:
        M = self._p11
        nums = (version,) if version is not None else range(1, MAX_PROBE_VERSIONS + 1)
        try:
            with self._session() as s:
                for n in nums:
                    try:
                        pub = self._find_object(s, _label(key_id, n), private=False)
                    except KmsKeyNotFoundError:
                        continue
                    raw = _der_point_to_raw(bytes(pub[M.Attribute.EC_POINT]))
                    return KeyVersion(key_id=key_id, version=n, provider=self.name,
                                      provider_key_id=_label(key_id, n),
                                      algorithm=KmsAlgorithm.ED25519,
                                      key_type=KmsKeyType.ASYMMETRIC_SIGNATURE, usages=(),
                                      state=KmsKeyState.ENABLED, public_key_b64=b64u_encode(raw),
                                      fingerprint=keys.fingerprint(raw), created_at=0.0)
        except KmsUnavailableError:
            raise
        return None

    def describe(self, key_id) -> KeyMetadata:
        if self.metadata_store is not None:
            meta = self.metadata_store.get_key(key_id)
            if meta is None:
                raise KmsKeyNotFoundError("unknown key")
            return meta
        raise KmsProviderError("PKCS#11 exposes no native versions; supply a KeyMetadataStore")

    def get_version(self, key_id, version) -> KeyVersion:
        if self.metadata_store is not None:
            meta = self.metadata_store.get_key(key_id)
            v = meta.version(version) if meta else None
            if v is not None:
                return v
        probed = self._probe(key_id, version)
        if probed is None:
            raise KmsKeyNotFoundError("unknown key version")
        return probed

    def public_key(self, key_id, version=None):
        if version is not None:
            v = self.get_version(key_id, version)
        else:
            meta = self.metadata_store.get_key(key_id) if self.metadata_store else None
            v = meta.active() if meta else self._probe(key_id)
        if v is None:
            raise KmsKeyNotFoundError("unknown key version")
        if not v.can_verify():
            raise KmsKeyStateError("key is not available for public-key retrieval")
        if v.public_key_b64:
            return keys.b64u_decode(v.public_key_b64), v.public_key_b64, v.version
        probed = self._probe(key_id, v.version)
        if probed is None:
            raise KmsKeyNotFoundError("unknown key version")
        return keys.b64u_decode(probed.public_key_b64), probed.public_key_b64, probed.version

    # ------------------------------------------------------------------ creation
    def create_key(self, key_id, *, algorithm=KmsAlgorithm.ED25519, usages=(), exportable=False,
                   org_id=None, purpose="", created_by="system") -> KeyVersion:
        if exportable:
            raise KmsProviderError("PKCS#11 keys are generated non-exportable")
        alg = coerce_algorithm(algorithm)
        if alg not in self.capabilities():
            raise KmsProviderError("unsupported algorithm")
        try:
            if self.metadata_store is not None and self.metadata_store.get_key(key_id) is not None:
                raise KmsProviderError("key id collision")
            if self._probe(key_id, 1) is not None:
                raise KmsProviderError("key id collision")
        except KmsKeyNotFoundError:
            pass
        v = self._generate(key_id, 1)
        return KeyVersion(**{**v.__dict__, "usages": coerce_usages(usages), "org_id": org_id,
                             "purpose": purpose})

    def rotate(self, key_id, *, purpose="") -> KeyVersion:
        if self.metadata_store is not None:
            meta = self.metadata_store.get_key(key_id)
            if meta is None:
                raise KmsKeyNotFoundError("unknown key")
            n = (meta.latest().version if meta.latest() else 0) + 1
        else:
            v = self._probe(key_id)
            n = (v.version if v else 0) + 1
        if n == 1:
            return self.create_key(key_id, purpose=purpose)
        v = self._generate(key_id, n)
        return KeyVersion(**{**v.__dict__, "purpose": purpose})

    # ------------------------------------------------------------------ crypto operations
    def sign(self, key_id, domain, data, *, usage=None, version=None) -> bytes:
        M = self._p11
        label = _label(key_id, version or 1)
        try:
            with self._session() as s:
                priv = self._find_object(s, label, private=True)
                sig = bytes(s.sign(priv, domain + data, mechanism=M.Mechanism.EDDSA))
        except KmsKeyNotFoundError:
            raise
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("token signing failed") from None
        if len(sig) != 64:
            raise KmsProviderError("token returned an invalid signature")
        return sig

    def verify(self, public_key_b64, domain, data, signature) -> bool:
        return keys.verify(public_key_b64, domain, data, signature)

    # ------------------------------------------------------------------ lifecycle
    def set_state(self, key_id, version, state, **fields) -> KeyVersion:
        v = self.get_version(key_id, version)
        target = coerce_state(state)
        check_transition(v.state, target)
        if self.metadata_store is not None:
            self.metadata_store.transition(key_id, version, expected_states=(v.state,),
                                           new_state=target, **fields)
            return self.get_version(key_id, version)
        return KeyVersion(**{**v.__dict__, "state": target,
                             **{k: fields[k] for k in
                                ("retire_at", "retired_at", "revoked_at", "revoke_reason")
                                if k in fields and fields[k] is not None}})

    def revoke(self, key_id, version, reason) -> KeyVersion:
        return self.set_state(key_id, version, KmsKeyState.REVOKED, revoked_at=time.time(),
                             revoke_reason=str(reason)[:128])

    def delete_key(self, key_id, version=None) -> None:
        nums = range(1, MAX_PROBE_VERSIONS + 1) if version is None else (version,)
        try:
            with self._session() as s:
                for n in nums:
                    label = _label(key_id, n)
                    for private in (False, True):
                        try:
                            self._find_object(s, label, private).destroy()
                        except KmsKeyNotFoundError:
                            pass
        except KmsUnavailableError:
            raise
        except Exception:                                            # noqa: BLE001
            raise KmsUnavailableError("token object destruction failed") from None

    def __repr__(self) -> str:
        return f"Pkcs11Provider(module={self.cfg.module_path!r}, token={self.cfg.token_label!r})"