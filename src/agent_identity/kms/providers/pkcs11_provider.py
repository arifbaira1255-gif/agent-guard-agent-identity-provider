"""PKCS#11 HSM provider (Ed25519 via CKM_EDDSA).

STATUS: validated against a REAL PKCS#11 token — SoftHSM2 (a software token implementing
the PKCS#11 interface) — see docs/KMS_HSM.md and tests/test_kms_pkcs11.py. It has NOT been
exercised against a production hardware HSM; EdDSA support is HSM-vendor-dependent
(PKCS#11 v3 standardised CKM_EDDSA; some v2.40 devices expose it as a vendor extension).

Custody model
-------------
The keypair is generated ON the token with CKA_SENSITIVE=True and CKA_EXTRACTABLE=False.
Only the public point is read back; signing goes through C_SignInit/C_Sign (CKM_EDDSA), so
the private key never enters this process. SoftHSM2 emits standard 64-byte Ed25519
signatures, which is what makes the HSM a drop-in trust anchor for the existing passports.

python-pkcs11 is imported lazily so the rest of the package works without it installed.
"""
import base64
import threading
import time
from typing import Optional, Tuple

from ..errors import (KeyCollisionError, KeyNotFoundError, KmsConfigError,
                      ProviderPermissionError, ProviderResponseError,
                      UnsupportedAlgorithmError)
from ..interfaces import CryptoBackend
from ..models import KeyAlgorithm, ProviderHealth

_ED25519_PUB_LEN = 32
_ED25519_SIG_LEN = 64
# DER SubjectPublicKeyInfo algorithm identifier for id-Ed25519 (RFC 8410): 06 03 2B 65 70
_ED25519_EC_PARAMS = bytes((0x06, 0x03, 0x2B, 0x65, 0x70))


def _strip_point(point: bytes) -> bytes:
    """CKA_EC_POINT is a DER OCTET STRING wrapping the raw point (04 || X). Unwrap it."""
    if len(point) == 2 + _ED25519_PUB_LEN and point[0] == 0x04:
        point = point[2:]
    if len(point) != _ED25519_PUB_LEN:
        raise ProviderResponseError("token returned a non-Ed25519 public point")
    return point


class Pkcs11Backend(CryptoBackend):
    name = "pkcs11"
    exportable = False

    def __init__(self, *, library: str, token_label: str, pin, key_label_prefix: str = "agentguard",
                 slot: Optional[int] = None, session_factory=None):
        if not library:
            raise KmsConfigError("pkcs11 provider requires a module library path")
        if not token_label and slot is None:
            raise KmsConfigError("pkcs11 provider requires a token label (or a slot)")
        if not pin:
            raise KmsConfigError("pkcs11 provider requires a user PIN")
        self._library = library
        self._token_label = token_label
        self._pin = pin
        self._prefix = key_label_prefix
        self._slot = slot
        self._factory = session_factory or self._default_session
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ sessions
    def _default_session(self):
        import pkcs11                             # lazy: optional dependency
        lib = pkcs11.lib(self._library)
        if self._slot is not None:
            token = lib.get_token(slot_id=self._slot)
        else:
            token = lib.get_token(token_label=self._token_label)
        return token.open(user_pin=self._pin, rw=True)

    # ------------------------------------------------------------------ backend
    def generate(self, key_id: str, algorithm: KeyAlgorithm) -> Tuple[bytes, dict]:
        self._require(algorithm)
        import pkcs11
        from pkcs11 import Attribute, Mechanism, ObjectClass, KeyType
        cka_id = key_id.encode()
        label = f"{self._prefix}-{key_id}"
        with self._lock, self._factory() as session:
            if next(session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                                        Attribute.ID: cka_id}), None) is not None:
                raise KeyCollisionError("key id already exists on the token")
            pub, _priv = session.generate_keypair(
                KeyType.EC_EDWARDS,
                id=cka_id, label=label, store=True,
                mechanism=Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                public_template={Attribute.EC_PARAMS: _ED25519_EC_PARAMS, Attribute.VERIFY: True},
                private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True,
                                  Attribute.EXTRACTABLE: False},
            )
            raw = _strip_point(bytes(pub[Attribute.EC_POINT]))
        return raw, {"ref": base64.b64encode(cka_id).decode("ascii")}

    def public(self, key_id, external_ref, algorithm) -> bytes:
        self._require(algorithm)
        cka_id = self._ka_id(key_id, external_ref)
        with self._factory() as session:
            pub = self._find_public(session, cka_id)
            return _strip_point(bytes(pub[Attribute.EC_POINT]))

    def sign(self, key_id, external_ref, algorithm, data: bytes) -> bytes:
        self._require(algorithm)
        import pkcs11
        cka_id = self._ka_id(key_id, external_ref)
        with self._factory() as session:
            priv = self._find_private(session, cka_id)
            sig = bytes(priv.sign(data, mechanism=pkcs11.Mechanism.EDDSA))
        if len(sig) != _ED25519_SIG_LEN:
            raise ProviderResponseError("token returned a non-Ed25519 signature")
        return sig

    def destroy(self, key_id, external_ref) -> None:
        from pkcs11 import Attribute, ObjectClass
        cka_id = self._ka_id(key_id, external_ref)
        with self._lock, self._factory() as session:
            for cls in (ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY):
                obj = next(session.get_objects({Attribute.CLASS: cls, Attribute.ID: cka_id}), None)
                if obj is not None:
                    obj.destroy()

    def health(self) -> ProviderHealth:
        start = time.time()
        try:
            with self._factory() as session:
                session.get_objects({})
            return ProviderHealth(healthy=True, provider=self.name, checked_at=time.time(),
                                  latency_ms=round((time.time() - start) * 1000, 2),
                                  detail="token session established")
        except Exception as e:  # noqa: BLE001 - health must never raise
            return ProviderHealth(healthy=False, provider=self.name, checked_at=time.time(),
                                  detail=type(e).__name__)

    # ----------------------------------------------------------------- internals
    @staticmethod
    def _ka_id(key_id: str, external_ref: Optional[str]) -> bytes:
        if external_ref:
            try:
                return base64.b64decode(external_ref, validate=True)
            except Exception:
                pass
        return key_id.encode()

    def _find_public(self, session, cka_id: bytes):
        from pkcs11 import Attribute, ObjectClass
        obj = next(session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                                        Attribute.ID: cka_id}), None)
        if obj is None:
            raise KeyNotFoundError("public key not found on the token")
        return obj

    def _find_private(self, session, cka_id: bytes):
        from pkcs11 import Attribute, ObjectClass
        obj = next(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                        Attribute.ID: cka_id}), None)
        if obj is None:
            raise KeyNotFoundError("private key not found on the token")
        return obj

    @staticmethod
    def _require(algorithm: KeyAlgorithm) -> None:
        if algorithm is not KeyAlgorithm.ED25519:
            raise UnsupportedAlgorithmError(f"pkcs11 provider does not support {algorithm}")

    def __repr__(self) -> str:
        return (f"Pkcs11Backend(library={self._library!r}, "
                f"token={self._token_label!r}, <redacted>)")
