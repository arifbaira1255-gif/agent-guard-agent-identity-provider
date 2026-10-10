"""PKCS#11 HSM provider tests (Ed25519 / CKM_EDDSA).

  * `Pkcs11Mocked`      — MOCKED session: asserts the adapter's attribute/point handling and
    error paths without any token. Runs always.
  * `Pkcs11RealSoftHSM` — REAL: generates keys ON a real PKCS#11 token and signs there.
    Skipped unless the module path + token + PIN are provided.

The real suite is validated against SoftHSM2 (a software token that speaks real PKCS#11).
It has NOT been run against a hardware HSM — EdDSA availability is vendor/version dependent.
See docs/KMS_HSM.md.

Set up SoftHSM2:
    apt-get install -y softhsm2
    mkdir -p /tmp/softhsm/tokens
    printf 'directories.tokendir = /tmp/softhsm/tokens\\nobjectstore.backend = file\\n' \
      > /etc/softhsm/softhsm2.conf
    export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
    softhsm2-util --init-token --slot 0 --label agentguard --pin 1234 --so-pin 1234
    export AGENTGUARD_TEST_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
    export AGENTGUARD_TEST_PKCS11_TOKEN_LABEL=agentguard AGENTGUARD_TEST_PKCS11_PIN=1234
"""
import base64
import os
import unittest
import uuid

from agent_identity.core.clock import FixedClock
from agent_identity.crypto import keys as K
from agent_identity.kms import DefaultKeyManager, KeyNotFoundError, ProviderResponseError
from agent_identity.kms.models import KeyAlgorithm
from agent_identity.kms.providers.pkcs11_provider import Pkcs11Backend, _strip_point

LIBRARY = os.environ.get("AGENTGUARD_TEST_PKCS11_LIBRARY", "")
TOKEN_LABEL = os.environ.get("AGENTGUARD_TEST_PKCS11_TOKEN_LABEL", "")
PIN = os.environ.get("AGENTGUARD_TEST_PKCS11_PIN", "")


# =============================================================== MOCKED (no token)
class _FakePublicKey:
    def __init__(self, point):
        self._point = point

    def __getitem__(self, attr):
        return self._point


class _FakePrivateKey:
    def __init__(self, sig):
        self._sig = sig

    def sign(self, data, mechanism=None):
        return self._sig


class _FakeSession:
    def __init__(self, outer):
        self.outer = outer

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def generate_keypair(self, *a, **kw):
        self.outer.generated.append(kw)
        self.outer.has_key = True
        return _FakePublicKey(self.outer.point), object()

    def get_objects(self, template):
        # emulate the "not found -> empty" contract used by the adapter. The token starts
        # empty so the collision probe returns nothing; after a keypair is generated the
        # objects exist and a second generate() must collide.
        from pkcs11 import Attribute, ObjectClass
        cls = template.get(Attribute.CLASS)
        if not self.outer.has_key:
            return iter([])
        if cls is ObjectClass.PUBLIC_KEY and self.outer.public_obj is not None:
            return iter([self.outer.public_obj])
        if cls is ObjectClass.PRIVATE_KEY and self.outer.private_obj is not None:
            return iter([self.outer.private_obj])
        return iter([])


class Pkcs11Mocked(unittest.TestCase):
    """Attribute handling with a fake PKCS#11 session. No real token, no signing."""

    def _backend(self, point=b"\x33" * 32, sig=b"\x44" * 64):
        outer = self

        class B(Pkcs11Backend):
            def __init__(self):
                super().__init__(library="/fake/lib.so", token_label="t", pin="1")
                self.generated = []
                self.has_key = False
                self.point = b"\x04\x20" + point          # DER OCTET STRING wrapper
                self.public_obj = _FakePublicKey(b"\x04\x20" + point)
                self.private_obj = _FakePrivateKey(sig)

            def _default_session(self):
                return _FakeSession(self)
        return B()

    def test_der_wrapped_public_point_is_unwrapped(self):
        be = self._backend()
        raw, refs = be.generate("k1", KeyAlgorithm.ED25519)
        self.assertEqual(raw, b"\x33" * 32)                # 2-byte wrapper removed
        self.assertIn("ref", refs)

    def test_private_template_is_non_exportable(self):
        be = self._backend()
        be.generate("k1", KeyAlgorithm.ED25519)
        from pkcs11 import Attribute
        priv = be.generated[0]["private_template"]
        self.assertTrue(priv[Attribute.SENSITIVE])
        self.assertFalse(priv[Attribute.EXTRACTABLE])       # custody never leaves the token
        self.assertTrue(priv[Attribute.SIGN])

    def test_signature_length_enforced(self):
        be = self._backend(sig=b"\x00" * 10)
        be.has_key = True                                  # pretend the token holds the key
        with self.assertRaises(ProviderResponseError):
            be.sign("k1", None, KeyAlgorithm.ED25519, b"data")

    def test_bad_public_point_rejected(self):
        with self.assertRaises(ProviderResponseError):
            _strip_point(b"\x00" * 7)

    def test_pin_never_in_repr(self):
        class B(Pkcs11Backend):
            def __init__(self):
                super().__init__(library="/usr/lib/softhsm/libsofthsm2.so",
                                 token_label="agentguard", pin="top-secret-pin")
        self.assertNotIn("top-secret-pin", repr(B()))
        self.assertIn("<redacted>", repr(B()))

    def test_config_requires_pin(self):
        from agent_identity.kms import KmsConfigError
        with self.assertRaises(KmsConfigError):
            Pkcs11Backend(library="/x.so", token_label="t", pin="")


# ============================================================ REAL (a live token)
@unittest.skipUnless(LIBRARY and TOKEN_LABEL and PIN,
                     "set AGENTGUARD_TEST_PKCS11_* to run the real PKCS#11 tests")
class Pkcs11RealSoftHSM(unittest.TestCase):
    """REAL PKCS#11: keys are generated ON the token and signing happens there."""

    @classmethod
    def setUpClass(cls):
        cls.be = Pkcs11Backend(library=LIBRARY, token_label=TOKEN_LABEL, pin=PIN,
                               key_label_prefix="agkms-it")

    def _id(self):
        return "it" + uuid.uuid4().hex[:16]

    def test_health_check_against_real_token(self):
        h = self.be.health()
        self.assertTrue(h.healthy, h.detail)

    def test_real_keygen_sign_verify(self):
        key_id = self._id()
        raw, refs = self.be.generate(key_id, KeyAlgorithm.ED25519)
        self.assertEqual(len(raw), 32)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        msg = b"agentguard-real-pkcs11"
        sig = self.be.sign(key_id, refs["ref"], KeyAlgorithm.ED25519, msg)
        self.assertEqual(len(sig), 64)
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, msg)   # standard Ed25519 sig
        # a tampered message must not verify
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(raw).verify(sig, b"tampered")
        self.be.destroy(key_id, refs["ref"])

    def test_manager_end_to_end_on_real_token(self):
        km = DefaultKeyManager(self.be, clock=FixedClock())
        key_id = self._id()
        meta = km.create_key(key_id)
        self.assertEqual(meta.provider, "pkcs11")
        self.assertFalse(meta.exportable)
        sig = km.sign(key_id, K.DOMAIN_PASSPORT, b"payload")
        self.assertTrue(K.verify(km.get_public_key(key_id), K.DOMAIN_PASSPORT, b"payload", sig))
        # revocation must make the verification material disappear immediately
        km.revoke_key(key_id, reason="test-teardown")
        self.assertIsNone(km.verification_material(key_id))
        km.destroy_key(key_id)

    def test_destroyed_token_key_is_gone(self):
        key_id = self._id()
        _raw, refs = self.be.generate(key_id, KeyAlgorithm.ED25519)
        self.be.destroy(key_id, refs["ref"])
        with self.assertRaises(KeyNotFoundError):
            self.be.public(key_id, refs["ref"], KeyAlgorithm.ED25519)

    def test_collision_on_existing_token_key(self):
        key_id = self._id()
        _raw, refs = self.be.generate(key_id, KeyAlgorithm.ED25519)
        try:
            from agent_identity.kms import KeyCollisionError
            with self.assertRaises(KeyCollisionError):
                self.be.generate(key_id, KeyAlgorithm.ED25519)
        finally:
            self.be.destroy(key_id, refs["ref"])


if __name__ == "__main__":
    unittest.main()
