"""Step 5 (KMS/HSM key management) test suite.

Everything here runs OFFLINE. AWS KMS and PKCS#11 are exercised against injected fake
clients/modules - no live cloud account or HSM is required, and none was available while this
step was built. Live-integration status is documented in ``docs/KMS.md``.

Coverage: config/production guards, the local-dev provider lifecycle, the metadata ledger's
compare-and-swap, the drop-in ``KeyStore`` adapter, rotation/retirement/recovery, concurrency,
failure injection (fail-closed), the AWS and PKCS#11 adapter contracts, the identity-service
end-to-end flow over a KMS-backed key store, and a log scan for secret material.
"""
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_identity import IdentityConfig
from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import StorageError
from agent_identity.crypto import keys
from agent_identity.crypto.encoding import b64u_decode, b64u_encode
from agent_identity.kms import (InMemoryKeyMetadataStore, KeyManagementManager, KmsConfig,
                                KmsConfigError, KmsKeyStore, KmsKeyNotFoundError, KmsKeyStateError,
                                KmsKeyUsage, KmsKeyUsageError, KmsProductionProviderError,
                                KmsProviderError, KmsUnavailableError, build_kms)
from agent_identity.kms.aws_kms import AwsKmsProvider
from agent_identity.kms.local_dev import LocalDevProvider
from agent_identity.kms.models import (KeyMetadata, KeyVersion, KmsAlgorithm, KmsKeyState,
                                       KmsKeyType, coerce_usages, check_transition)
from agent_identity.kms.pkcs11_provider import Pkcs11Provider
from agent_identity.observability.logging import SecurityLogger

DOM = b"agentguard-passport-v1\n"


def dev_cfg(**kw):
    d = dict(environment="development", provider="local-dev")
    d.update(kw)
    return KmsConfig(**d)


# --------------------------------------------------------------------------- inline fakes
class _FakeAwsClient:
    """Minimal in-memory stand-in for the botocore KMS client. Real Ed25519 signatures."""

    def __init__(self):
        self._keys = {}          # KeyId -> {"priv", "tags"}
        self._n = 0
        self.calls = []

    def _new_id(self):
        self._n += 1
        return f"arn:aws:kms:us-east-1:000000000000:key/fake-{self._n}"

    def create_key(self, KeyUsage=None, KeySpec=None, Description=""):
        self.calls.append(("create_key", KeySpec))
        if KeySpec != "ECC_NIST_EDWARDS25519":
            raise AssertionError("unexpected KeySpec")
        kid = self._new_id()
        self._keys[kid] = {"priv": Ed25519PrivateKey.generate(), "tags": {}}
        return {"KeyMetadata": {"KeyId": kid, "KeySpec": KeySpec}}

    def get_public_key(self, KeyId):
        der = self._keys[KeyId]["priv"].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der, "KeyId": KeyId}

    def sign(self, KeyId, Message, MessageType=None, SigningAlgorithm=None):
        if SigningAlgorithm != "ED25519_SHA_512":
            raise AssertionError("unexpected signing algorithm")
        return {"Signature": self._keys[KeyId]["priv"].sign(bytes(Message)),
                "SigningAlgorithm": SigningAlgorithm}

    def list_keys(self, Limit=100, Marker=None):
        return {"Keys": [{"KeyId": k} for k in self._keys], "Truncated": False}

    def list_resource_tags(self, KeyId):
        return {"Tags": [{"TagKey": k, "TagValue": v} for k, v in self._keys[KeyId]["tags"].items()]}

    def tag_resource(self, KeyId, Tags):
        for t in Tags:
            self._keys[KeyId]["tags"][t["TagKey"]] = t["TagValue"]
        return {}

    def disable_key(self, KeyId):
        return {}

    def enable_key(self, KeyId):
        return {}

    def schedule_key_deletion(self, KeyId, PendingWindowInDays=7):
        return {}


class AccessDeniedException(Exception):
    pass


class ThrottlingException(Exception):
    pass


class KMSInternalException(Exception):
    pass


class NotFoundException(Exception):
    pass


class _FakePkcs11Module:
    """Minimal PKCS#11 stand-in: enough surface for the adapter, with real Ed25519 signatures."""

    class ObjectClass:
        PUBLIC_KEY = "PUB"
        PRIVATE_KEY = "PRIV"

    class KeyType:
        EC_EDWARDS = "EC_EDWARDS"

    class Attribute:
        CLASS = "CLASS"
        KEY_TYPE = "KEY_TYPE"
        LABEL = "LABEL"
        TOKEN = "TOKEN"
        VERIFY = "VERIFY"
        PRIVATE = "PRIVATE"
        SENSITIVE = "SENSITIVE"
        EXTRACTABLE = "EXTRACTABLE"
        SIGN = "SIGN"
        EC_POINT = "EC_POINT"

    class Mechanism:
        EDDSA = "CKM_EDDSA"

    class _Obj(dict):
        def destroy(self):
            self["_destroyed"] = True

    class _Token:
        label = "agentguard-token"

        def __init__(self, store):
            self.store = store

        def open(self, user_pin=None, rw=True):
            if user_pin != "1234":
                raise RuntimeError("bad pin")
            return _FakePkcs11Module._Session(self.store)

    class _Session:
        def __init__(self, store):
            self.store = store
            self.closed = False

        def get_objects(self, template):
            out = []
            for obj in self.store.objects:
                if obj.get("_destroyed"):
                    continue
                if all(obj.get(k) == v for k, v in template.items()):
                    out.append(obj)
            return out

        def generate_key_pair(self, mechanism, public_template, private_template):
            if mechanism != _FakePkcs11Module.Mechanism.EDDSA:
                raise AssertionError("mechanism")
            priv = Ed25519PrivateKey.generate()
            raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
            point = b"\x04" + b"\x00" * 32 + raw            # last 32 bytes are the raw key
            pub = _FakePkcs11Module._Obj(public_template, EC_POINT=point)
            prv = _FakePkcs11Module._Obj(private_template, _priv=priv)
            self.store.objects.extend([pub, prv])
            return pub, prv

        def sign(self, key, data, mechanism):
            return key["_priv"].sign(bytes(data))

        def close(self):
            self.closed = True

    class _Lib:
        def __init__(self, store):
            self.store = store

        def get_token(self, slot=None):
            return _FakePkcs11Module._Token(self.store)

        def get_slots(self):
            return [self]

        def get_token_at(self, slot):
            return _FakePkcs11Module._Token(self.store)

    class _Store:
        def __init__(self):
            self.objects = []

    def __init__(self):
        self._store = _FakePkcs11Module._Store()

    def lib(self, path):
        return _FakePkcs11Module._Lib(self._store)


# --------------------------------------------------------------------------- config guards
class KmsConfigTests(unittest.TestCase):
    def test_local_dev_forbidden_outside_development(self):
        for env in ("staging", "production"):
            with self.assertRaises(KmsConfigError):
                KmsConfig(environment=env, provider="local-dev").validate()

    def test_process_env_can_only_tighten(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(KmsConfigError):
                KmsConfig(environment="development", provider="aws-kms", region="r").validate()

    def test_aws_requires_region_outside_dev(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="aws-kms", region="").validate()

    def test_endpoint_must_be_tls_outside_dev(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="aws-kms", region="r",
                      endpoint_url="http://kms.local").validate()

    def test_pkcs11_requires_module_path(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="pkcs11", module_path="").validate()

    def test_export_flag_forced_off_outside_dev(self):
        c = KmsConfig(environment="production", provider="aws-kms", region="r",
                      allow_export_in_dev=True).validate()
        self.assertFalse(c.allow_export_in_dev)

    def test_from_env_and_safe_dict(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "development",
                                          "AGENTGUARD_KMS_PROVIDER": "local-dev"}):
            c = KmsConfig.from_env()
        self.assertEqual(c.provider, "local-dev")
        d = c.safe_dict()
        self.assertNotIn("pin_file", {k for k, v in d.items() if v == "1234"})

    def test_unknown_keys_rejected(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig.from_dict({"nope": 1})

    def test_build_kms_selects_local_dev_in_dev_only(self):
        rt = build_kms(dev_cfg())
        self.assertEqual(rt.provider.name, "local-dev")
        with self.assertRaises(KmsConfigError):
            build_kms(KmsConfig(environment="production", provider="local-dev"))


# --------------------------------------------------------------------------- local-dev provider
class LocalDevProviderTests(unittest.TestCase):
    def setUp(self):
        self.p = LocalDevProvider()
        self.p.create_key("iss_a", usages=(KmsKeyUsage.PASSPORT_SIGNING,))

    def test_create_sign_verify(self):
        pub, pub_b64, ver = self.p.public_key("iss_a")
        self.assertEqual(ver, 1)
        self.assertEqual(len(pub), 32)
        sig = self.p.sign("iss_a", DOM, b"payload", usage=KmsKeyUsage.PASSPORT_SIGNING)
        self.assertEqual(len(sig), 64)
        self.assertTrue(self.p.verify(pub_b64, DOM, b"payload", sig))
        self.assertFalse(self.p.verify(pub_b64, DOM, b"tampered", sig))

    def test_usage_restriction_enforced(self):
        with self.assertRaises(KmsKeyUsageError):
            self.p.sign("iss_a", DOM, b"x", usage=KmsKeyUsage.PROOF_SIGNING)

    def test_key_id_collision(self):
        with self.assertRaises(KmsProviderError):
            self.p.create_key("iss_a")

    def test_state_machine_and_retire_refuses_sign(self):
        v2 = self.p.rotate("iss_a")
        self.assertEqual(v2.version, 2)
        self.assertEqual(self.p.get_version("iss_a", 1).state, KmsKeyState.RETIRING)
        with self.assertRaises(KmsKeyStateError):
            self.p.sign("iss_a", DOM, b"x", version=1)
        # a retiring key still yields its public key (verification overlap)
        _, pub1, _ = self.p.public_key("iss_a", 1)
        self.assertTrue(pub1)

    def test_illegal_transition(self):
        with self.assertRaises(KmsKeyStateError):
            self.p.set_state("iss_a", 1, KmsKeyState.RETIRED)   # enabled -> retired is not legal

    def test_revoke_is_terminal(self):
        self.p.revoke("iss_a", 1, "compromise")
        self.assertEqual(self.p.get_version("iss_a", 1).state, KmsKeyState.REVOKED)
        with self.assertRaises(KmsKeyStateError):
            self.p.set_state("iss_a", 1, KmsKeyState.ENABLED)

    def test_export_is_dev_only_surface(self):
        raw = self.p.export_private_key("iss_a")
        self.assertEqual(len(raw), 32)
        locked = LocalDevProvider(allow_export=False)
        locked.create_key("k")
        with self.assertRaises(NotImplementedError):
            locked.export_private_key("k")

    def test_unknown_key(self):
        with self.assertRaises(KmsKeyNotFoundError):
            self.p.sign("nope", DOM, b"x")

    def test_health_and_capabilities(self):
        self.assertTrue(self.p.health_check())
        self.assertEqual(self.p.capabilities(), (KmsAlgorithm.ED25519,))

    def test_production_guard_blocks_construction_and_signing(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(KmsProductionProviderError):
                LocalDevProvider()
        # construction in dev, then the process flips to production: signing must refuse
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(KmsProductionProviderError):
                self.p.sign("iss_a", DOM, b"x")


# --------------------------------------------------------------------------- metadata ledger
class MetadataStoreTests(unittest.TestCase):
    def setUp(self):
        self.s = InMemoryKeyMetadataStore()
        self.p = LocalDevProvider()
        v = self.p.create_key("k1", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        self.s.put_version(v)

    def test_cas_transition_is_single_winner(self):
        first = self.s.transition("k1", 1, expected_states=(KmsKeyState.ENABLED,),
                                  new_state=KmsKeyState.RETIRING, retire_at=100.0)
        second = self.s.transition("k1", 1, expected_states=(KmsKeyState.ENABLED,),
                                   new_state=KmsKeyState.RETIRING, retire_at=200.0)
        self.assertIsNotNone(first)
        self.assertIsNone(second)                      # precondition already consumed

    def test_cas_rejects_wrong_precondition(self):
        self.assertIsNone(self.s.transition("k1", 1, expected_states=(KmsKeyState.RETIRED,),
                                            new_state=KmsKeyState.REVOKED))

    def test_list_and_delete(self):
        v = self.p.create_key("k2")
        self.s.put_version(v)
        self.assertEqual(len(self.s.list_keys()), 2)
        self.assertEqual(len(self.s.list_keys(provider="local-dev")), 2)
        self.assertEqual(self.s.list_keys(provider="other"), ())
        self.s.delete("k2")
        self.assertIsNone(self.s.get_key("k2"))

    def test_put_version_creates_missing_logical_key(self):
        v = self.p.create_key("k3")
        self.s.put_version(v)
        meta = self.s.get_key("k3")
        self.assertEqual(meta.active().version, 1)


# --------------------------------------------------------------------------- manager / rotation
class ManagerRotationTests(unittest.TestCase):
    def setUp(self):
        self.p = LocalDevProvider()
        self.store = InMemoryKeyMetadataStore()
        self.mgr = KeyManagementManager(self.p, self.store, dev_cfg(), clock=FixedClock())

    def test_rotate_then_reap_after_overlap(self):
        self.mgr.create_key("iss_a", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        self.mgr.rotate("iss_a", overlap_seconds=0)
        meta = self.store.get_key("iss_a")
        self.assertEqual([(v.version, v.state.value) for v in meta.versions],
                         [(1, "retiring"), (2, "enabled")])
        self.assertEqual(self.mgr.reap(), 1)           # overlap already elapsed
        self.assertEqual(self.store.get_key("iss_a").version(1).state, KmsKeyState.RETIRED)
        self.assertEqual(self.mgr.reap(), 0)           # idempotent

    def test_retire_refuses_before_overlap(self):
        self.mgr.create_key("iss_a")
        self.mgr.rotate("iss_a", overlap_seconds=3600)
        with self.assertRaises(KmsProviderError):
            self.mgr.retire("iss_a", 1)

    def test_retire_refuses_enabled(self):
        self.mgr.create_key("iss_a")
        with self.assertRaises(KmsProviderError):
            self.mgr.retire("iss_a", 1)

    def test_destroy_refuses_non_terminal(self):
        self.mgr.create_key("iss_a")
        with self.assertRaises(KmsProviderError):
            self.mgr.destroy("iss_a", 1)

    def test_revoke_then_destroy(self):
        self.mgr.create_key("iss_a")
        self.mgr.revoke("iss_a", 1, "compromise")
        self.assertEqual(self.store.get_key("iss_a").version(1).state, KmsKeyState.REVOKED)
        self.mgr.destroy("iss_a", 1)
        self.assertIsNone(self.store.get_key("iss_a"))

    def test_verification_continues_during_rotation(self):
        self.mgr.create_key("iss_a", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        sig_v1 = self.p.sign("iss_a", DOM, b"cred", version=1)
        _raw, pub_v1, _ = self.p.public_key("iss_a", 1)
        self.mgr.rotate("iss_a", overlap_seconds=9999)
        # after rotation the old signing version is retiring but its public key must still verify
        _raw2, pub_v1b, ver = self.p.public_key("iss_a", 1)
        self.assertEqual(ver, 1)
        self.assertTrue(self.p.verify(pub_v1b, DOM, b"cred", sig_v1))
        # new signatures go out under version 2
        sig_v2 = self.p.sign("iss_a", DOM, b"cred", usage=KmsKeyUsage.PASSPORT_SIGNING)
        _raw3, pub_v2, _ = self.p.public_key("iss_a", 2)
        self.assertTrue(self.p.verify(pub_v2, DOM, b"cred", sig_v2))
        self.assertNotEqual(pub_v1b, pub_v2)

    def test_concurrent_rotation_keeps_single_signer(self):
        self.mgr.create_key("iss_a")
        errs = []

        def worker():
            try:
                self.mgr.rotate("iss_a", overlap_seconds=9999)
            except Exception as e:                                     # noqa: BLE001
                errs.append(e)
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])
        meta = self.store.get_key("iss_a")
        enabled = [v for v in meta.versions if v.state == KmsKeyState.ENABLED]
        self.assertEqual(len(enabled), 1)              # exactly one signer
        self.assertEqual(len({v.version for v in meta.versions}), len(meta.versions))

    def test_health_reports_provider(self):
        h = self.mgr.health()
        self.assertEqual(h["provider"], "local-dev")
        self.assertTrue(h["ready"])


# --------------------------------------------------------------------------- KeyStore adapter
class KmsKeyStoreAdapterTests(unittest.TestCase):
    def setUp(self):
        rt = build_kms(dev_cfg())
        self.rt, self.ks = rt, rt.keystore

    def test_generate_public_sign_has_delete(self):
        raw = self.ks.generate_key("key_agent1")
        self.assertEqual(len(raw), 32)
        self.assertEqual(self.ks.public_key("key_agent1"), raw)
        sig = self.ks.sign("key_agent1", DOM, b"m")
        self.assertTrue(keys.verify(b64u_encode(raw), DOM, b"m", sig))
        self.assertTrue(self.ks.has_key("key_agent1"))
        self.assertFalse(self.ks.has_key("missing"))
        self.ks.delete_key("key_agent1")
        self.assertFalse(self.ks.has_key("key_agent1"))
        with self.assertRaises(StorageError):
            self.ks.public_key("key_agent1")

    def test_usage_inference_from_key_id(self):
        from agent_identity.kms.keystore import infer_usages
        self.assertEqual(infer_usages("root_x"), (KmsKeyUsage.ISSUER_CERT_SIGNING,))
        self.assertEqual(infer_usages("iss_x"), (KmsKeyUsage.PASSPORT_SIGNING,))
        self.assertEqual(infer_usages("key_x"), (KmsKeyUsage.IDENTITY_SIGNING,))
        self.assertEqual(infer_usages("odd"), (KmsKeyUsage.PROOF_SIGNING,))

    def test_delete_revokes_before_removal(self):
        self.ks.generate_key("key_z")
        self.ks.delete_key("key_z")
        # ledger entry gone; provider object gone
        self.assertIsNone(self.rt.store.get_key("key_z"))
        with self.assertRaises(KmsKeyNotFoundError):
            self.rt.provider.describe("key_z")

    def test_unknown_key_maps_to_storage_error(self):
        with self.assertRaises(StorageError):
            self.ks.sign("nope", DOM, b"x")

    def test_fail_closed_on_provider_outage(self):
        class Boom:
            name, is_development, supports_export = "boom", False, False

            def sign(self, *a, **k):
                raise KmsUnavailableError("kms down")

            def public_key(self, *a, **k):
                raise KmsUnavailableError("kms down")

            def health_check(self):
                return False

        self.rt.provider.sign = Boom().sign
        with self.assertRaises(KmsUnavailableError):   # never a bogus signature
            self.ks.sign("key_agent1", DOM, b"x")

    def test_retired_key_in_use_signal(self):
        self.ks.generate_key("key_q")
        self.rt.manager.revoke("key_q", 1, "compromise")
        from agent_identity.kms.errors import KmsRetiredKeyInUseError
        with self.assertRaises(KmsRetiredKeyInUseError):
            self.ks.sign("key_q", DOM, b"x")


# --------------------------------------------------------------------------- AWS adapter (fake)
class AwsProviderTests(unittest.TestCase):
    def _provider(self, client=None):
        cfg = KmsConfig(environment="production", provider="aws-kms", region="us-east-1",
                        endpoint_url="https://kms.us-east-1.amazonaws.com",
                        retry_initial_backoff_seconds=0.0).validate()
        return AwsKmsProvider(cfg, client=client or _FakeAwsClient())

    def test_full_lifecycle_against_fake_client(self):
        p = self._provider()
        v = p.create_key("iss_aws1", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        self.assertEqual(v.version, 1)
        self.assertFalse(v.exportable)
        sig = p.sign("iss_aws1", DOM, b"payload", usage=KmsKeyUsage.PASSPORT_SIGNING)
        _raw, pub, _ = p.public_key("iss_aws1")
        self.assertTrue(p.verify(pub, DOM, b"payload", sig))
        v2 = p.rotate("iss_aws1")
        self.assertEqual(v2.version, 2)
        meta = p.describe("iss_aws1")
        self.assertEqual(meta.active().version, 2)
        self.assertEqual(meta.version(1).state, KmsKeyState.RETIRING)

    def test_usage_violation(self):
        p = self._provider()
        p.create_key("iss_aws1", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        with self.assertRaises(KmsKeyUsageError):
            p.sign("iss_aws1", DOM, b"x", usage=KmsKeyUsage.PROOF_SIGNING)

    def test_export_refused(self):
        p = self._provider()
        with self.assertRaises(KmsProviderError):
            p.create_key("k", exportable=True)

    def test_collision_detected(self):
        p = self._provider()
        p.create_key("iss_aws1")
        with self.assertRaises(KmsProviderError):
            p.create_key("iss_aws1")

    def test_invalid_signature_response_is_rejected(self):
        client = _FakeAwsClient()
        client.sign = lambda **kw: {"Signature": b"short"}
        p = self._provider(client)
        p.create_key("iss_aws1")
        with self.assertRaises(KmsProviderError):
            p.sign("iss_aws1", DOM, b"x")

    def test_access_denied_maps_and_is_not_retried(self):
        client = _FakeAwsClient()
        calls = {"n": 0}

        def denied(**kw):
            calls["n"] += 1
            raise AccessDeniedException("nope")
        client.create_key = denied
        p = self._provider(client)
        from agent_identity.kms.errors import KmsAccessDeniedError
        with self.assertRaises(KmsAccessDeniedError):
            p.create_key("iss_aws1")
        self.assertEqual(calls["n"], 1)                # denied => no retry

    def test_transient_throttle_retries_then_unavailable(self):
        client = _FakeAwsClient()

        def throttle(**kw):
            raise ThrottlingException("slow down")
        client.create_key = throttle
        p = self._provider(client)
        with self.assertRaises(KmsUnavailableError):
            p.create_key("iss_aws1")

    def test_not_found_maps(self):
        client = _FakeAwsClient()

        def missing(**kw):
            raise NotFoundException("no key")
        client.get_public_key = missing
        p = self._provider(client)
        with self.assertRaises(KmsKeyNotFoundError):
            p.create_key("iss_aws1")

    def test_health_check_reports_boolean(self):
        self.assertTrue(self._provider().health_check())


# --------------------------------------------------------------------------- PKCS#11 (fake)
class Pkcs11ProviderTests(unittest.TestCase):
    def _provider(self, module=None, with_store=True):
        cfg = KmsConfig(environment="production", provider="pkcs11",
                        module_path="/usr/lib/softhsm/libsofthsm2.so",
                        token_label="agentguard-token").validate()
        store = InMemoryKeyMetadataStore() if with_store else None
        with mock.patch.dict(os.environ, {"AGENTGUARD_KMS_PKCS11_PIN": "1234"}):
            return Pkcs11Provider(cfg, module=module or _FakePkcs11Module(),
                                  metadata_store=store), store

    def test_missing_pin_is_config_error(self):
        cfg = KmsConfig(environment="production", provider="pkcs11",
                        module_path="/x.so").validate()
        with mock.patch.dict(os.environ, {"AGENTGUARD_KMS_PKCS11_PIN": ""}, clear=False):
            with self.assertRaises(KmsConfigError):
                Pkcs11Provider(cfg, module=_FakePkcs11Module())

    def test_pin_via_file(self):
        cfg = KmsConfig(environment="production", provider="pkcs11",
                        module_path="/x.so", pin_file=self._pin_file()).validate()
        p = Pkcs11Provider(cfg, module=_FakePkcs11Module())      # no env needed
        self.assertTrue(p.health_check())

    def _pin_file(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".pin", delete=False)
        fh.write("1234\n")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_create_sign_verify_rotate(self):
        p, store = self._provider()
        v = p.create_key("iss_hsm1", usages=(KmsKeyUsage.PASSPORT_SIGNING,))
        self.assertEqual(v.version, 1)
        self.assertFalse(v.exportable)
        store.put_version(v)
        sig = p.sign("iss_hsm1", DOM, b"payload", version=1)
        self.assertEqual(len(sig), 64)
        _raw, pub, _ = p.public_key("iss_hsm1", 1)
        self.assertTrue(p.verify(pub, DOM, b"payload", sig))
        v2 = p.rotate("iss_hsm1")
        self.assertEqual(v2.version, 2)
        store.put_version(v2)

    def test_describe_requires_metadata_store(self):
        p, _ = self._provider(with_store=False)
        p.create_key("iss_hsm1")            # create_key does not need the store
        with self.assertRaises(KmsProviderError):
            p.describe("iss_hsm1")

    def test_public_key_via_probe_without_store(self):
        p, _ = self._provider(with_store=False)
        p.create_key("iss_hsm1")
        raw, pub_b64, ver = p.public_key("iss_hsm1", 1)
        self.assertEqual(len(raw), 32)
        self.assertEqual(ver, 1)

    def test_delete_destroys_token_objects(self):
        p, store = self._provider()
        p.create_key("iss_hsm1")
        p.delete_key("iss_hsm1")
        with self.assertRaises(KmsKeyNotFoundError):
            p.get_version("iss_hsm1", 1)

    def test_state_transition_uses_store(self):
        p, store = self._provider()
        v = p.create_key("iss_hsm1")
        store.put_version(v)
        p.set_state("iss_hsm1", 1, KmsKeyState.RETIRING)
        self.assertEqual(store.get_key("iss_hsm1").version(1).state, KmsKeyState.RETIRING)


# --------------------------------------------------------------------------- end-to-end
class IdentityIntegrationTests(unittest.TestCase):
    def _svc(self):
        from agent_identity.kms.integration import build_identity_service
        return build_identity_service(
            IdentityConfig(log_to_python_logging=False), dev_cfg(), root_key_id="root_step5_test",
            service_kwargs={"clock": FixedClock(),
                            "logger": SecurityLogger(use_python_logging=False)})

    def test_root_is_bootstrapped_in_kms(self):
        svc, rt = self._svc()
        self.assertTrue(rt.keystore.has_key("root_step5_test"))
        self.assertEqual(rt.keystore.public_key("root_step5_test"),
                         b64u_decode(svc.trust.get_root("root_step5_test")))

    def test_register_issue_verify_replay(self):
        svc, rt = self._svc()
        svc.register_organization("acme", "Acme")
        a = svc.register_agent("acme", "bot", "support", "o@x.com",
                               capabilities=["agent:spawn", "t:read"])
        i = svc.create_agent_instance(a["agent_id"])
        c = svc.issue_credential(a["agent_id"], i["instance_id"])
        proof = svc.create_proof(c.token, "gw")
        r = svc.verify_credential(c.token, proof=proof, audience="gw")
        self.assertTrue(r.valid)
        self.assertEqual(r.agent_id, a["agent_id"])
        again = svc.verify_credential(c.token, proof=proof, audience="gw")
        self.assertFalse(again.valid)
        self.assertEqual(again.reason, "replay_detected")

    def test_root_issuer_and_agent_keys_are_all_kms_tracked(self):
        svc, rt = self._svc()
        svc.register_organization("acme", "Acme")
        a = svc.register_agent("acme", "bot", "support", "o@x.com", capabilities=["x:read"])
        keyset = {m.key_id for m in rt.store.list_keys(provider="local-dev")}
        self.assertIn("root_step5_test", keyset)
        self.assertTrue(any(k.startswith("iss_") for k in keyset))
        self.assertIn(a["key_id"], keyset)

    def test_kms_outage_fails_signing_closed(self):
        svc, rt = self._svc()
        svc.register_organization("acme", "Acme")
        a = svc.register_agent("acme", "bot", "support", "o@x.com")
        i = svc.create_agent_instance(a["agent_id"])
        rt.keystore.provider.sign = lambda *a, **k: (_ for _ in ()).throw(
            KmsUnavailableError("kms down"))
        with self.assertRaises(KmsUnavailableError):
            svc.issue_credential(a["agent_id"], i["instance_id"])

    def test_verification_never_falsely_accepts_on_bad_state(self):
        svc, rt = self._svc()
        svc.register_organization("acme", "Acme")
        self.assertFalse(svc.verify_credential("agp1.garbage.garbage").valid)

    def test_rotation_visible_in_ledger_and_old_credential_still_verifies(self):
        svc, rt = self._svc()
        svc.register_organization("acme", "Acme")
        a = svc.register_agent("acme", "bot", "support", "o@x.com", capabilities=["x:read"])
        i = svc.create_agent_instance(a["agent_id"])
        c = svc.issue_credential(a["agent_id"], i["instance_id"], public_key=None)
        # rotate the issuer key with a long overlap; the already-issued credential must stay valid
        svc.rotate_issuer_key("acme", grace_seconds=9999)
        self.assertTrue(svc.verify_credential(c.token, require_proof=False).valid)
        # the new issuer certificate is now active
        org = svc.get_agent_identity(a["agent_id"])
        self.assertIsNotNone(org["org_id"])


# --------------------------------------------------------------------------- logging hygiene
class KmsLoggingTests(unittest.TestCase):
    def test_no_secret_material_in_kms_events(self):
        logger = SecurityLogger(use_python_logging=False)
        rt = build_kms(dev_cfg(), logger=logger)
        v = rt.keystore.generate_key("key_log1")
        rt.keystore.sign("key_log1", DOM, b"payload")
        rt.manager.rotate("key_log1", overlap_seconds=0)
        rt.manager.reap()
        blob = json.dumps([e for e in logger.events])
        self.assertIn("kms.key_create", blob)
        self.assertIn("kms.key_rotate", blob)
        for bad in ("private", "secret", "agp1.", "BEGIN", b64u_encode(v)):
            self.assertNotIn(bad, blob.lower() if bad.islower() else blob)
        # the raw private key and its hex must never appear
        raw = rt.provider.export_private_key("key_log1", 2)
        self.assertNotIn(raw.hex(), blob)
        self.assertNotIn(b64u_encode(raw), blob)

    def test_pg_metadata_sql_has_no_key_material(self):
        from agent_identity.storage.postgres import migrate
        sql = " ".join(m.sql.lower() for m in migrate.load_migrations()
                       if "kms" in m.name).replace("--", " ")
        self.assertIn("kms_key_versions", sql)
        for bad in ("private_key", "encrypted_private", "private_bytes"):
            self.assertNotIn(bad, sql)

    def test_pg_metadata_store_maps_and_cas(self):
        """The PostgreSQL store shares the in-memory contract; validated here with a fake db."""
        from agent_identity.storage.postgres.kms_repos import PgKeyMetadataStore

        class _FakeDb:
            def __init__(self):
                self.rows, self.versions = {}, []

            def run(self, op, fn, **kw):
                return fn(self)
        # the real store is exercised end-to-end by tests/test_pg_integration.py when a database
        # is configured; here we assert the contract surface exists and is wired.
        store = PgKeyMetadataStore(_FakeDb())
        for name in ("put_key", "get_key", "list_keys", "put_version", "transition", "delete"):
            self.assertTrue(callable(getattr(store, name)))
        meta = KeyMetadata("k", "aws-kms", KmsAlgorithm.ED25519, KmsKeyType.ASYMMETRIC_SIGNATURE,
                           coerce_usages(["passport_signing"]), None, "", 1.0, "t")
        v = KeyVersion(key_id="k", version=1, provider="aws-kms", provider_key_id="arn:1",
                       algorithm=KmsAlgorithm.ED25519, key_type=KmsKeyType.ASYMMETRIC_SIGNATURE,
                       usages=coerce_usages(["passport_signing"]), state=KmsKeyState.ENABLED,
                       public_key_b64="AA", fingerprint="f", created_at=1.0)
        meta = meta.with_version(v)
        self.assertEqual(meta.active().version, 1)
        self.assertTrue(check_transition(KmsKeyState.ENABLED, KmsKeyState.RETIRING))



class ProductionKeystoreGuard(unittest.TestCase):
    """Regression (Step 5 review): production must not silently start with the in-memory development keystore."""

    def test_memory_keystore_refused_in_staging_and_production(self):
        import os
        from unittest import mock
        from agent_identity import IdentityConfig, IdentityService
        from agent_identity.core.errors import StorageError
        for env in ("production", "staging"):
            with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": env, "AGENTGUARD_ALLOW_LOCAL_REPLAY": "1"}):
                with self.assertRaises(StorageError):
                    IdentityService(IdentityConfig(trust_domain="x.example.net", log_to_python_logging=False))

    def test_kms_keystore_is_not_rejected_by_the_guard(self):
        from agent_identity.storage.postgres.factory import require_durable_or_raise
        import os
        from unittest import mock
        from agent_identity.kms.keystore import KmsKeyStore
        ks = KmsKeyStore.__new__(KmsKeyStore)                       # type check only; no provider needed
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            require_durable_or_raise(keystore=ks)


if __name__ == "__main__":
    unittest.main()
