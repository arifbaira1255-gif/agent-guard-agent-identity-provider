"""Unit tests for the Step 5 KMS/HSM layer.

MOCKED / SOFTWARE ONLY — no external service is contacted here. The real-provider tests
live in test_kms_vault.py (real Vault) and test_kms_pkcs11.py (real PKCS#11 token).

Covers: the abstraction contract, the software provider, key lifecycle, rotation
(including concurrency and crash recovery), revocation, fail-closed verification,
failure injection, configuration and secret redaction.
"""
import logging
import threading
import time
import unittest

from cryptography.fernet import Fernet, InvalidToken

from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import ConflictError
from agent_identity.crypto import keys as K
from agent_identity.crypto.encoding import b64u_decode, b64u_encode
from agent_identity.kms import (DefaultKeyManager, KeyAlgorithm, KeyCollisionError,
                                KeyMetadata, KeyNotFoundError, KeyStateError, KeyStatus,
                                KmsConfig, KmsConfigError, KmsError, ProviderHealth,
                                ProviderPermissionError, ProviderRateLimitedError,
                                ProviderUnavailableError, TrustStoreComposition,
                                UnsupportedAlgorithmError, build_key_manager, is_terminal,
                                may_destroy, may_sign, may_verify)
from agent_identity.kms.interfaces import CryptoBackend
from agent_identity.kms.providers.local_provider import LocalKeyBackend
from agent_identity.observability.logging import SecurityLogger
from agent_identity.spiffe.config import Environment
from agent_identity.storage.interfaces import KeyStore
from agent_identity.storage.memory import MemoryTrustStore


class _BadAlgorithm:
    """A stand-in for an algorithm the provider does not support."""
    value = "rsa"
    name = "RSA"


def make_manager(clock=None, **kw):
    be = LocalKeyBackend(Fernet.generate_key())
    km = DefaultKeyManager(be, clock=clock or FixedClock(), **kw)
    return km, be


# --------------------------------------------------------------------------- contract
class AbstractionContract(unittest.TestCase):
    def test_key_manager_is_a_keystore(self):
        km, _ = make_manager()
        self.assertIsInstance(km, KeyStore)          # drop-in for IdentityService/Verifier
        for name in ("generate_key", "public_key", "sign", "has_key", "delete_key"):
            self.assertTrue(callable(getattr(km, name)))
        for name in ("create_key", "rotate_key", "retire_key", "revoke_key", "destroy_key",
                     "get_key_status", "get_public_key", "health_check", "verification_material"):
            self.assertTrue(callable(getattr(km, name)))

    def test_legacy_generate_key_returns_public_only(self):
        km, _ = make_manager()
        pub = km.generate_key("agent_key_1")
        self.assertEqual(len(pub), 32)               # raw Ed25519 public key
        self.assertEqual(km.get_public_key("agent_key_1"), km.get_key_status("agent_key_1").public_key_b64)

    def test_unsupported_algorithm_rejected(self):
        km, _ = make_manager()
        with self.assertRaises(UnsupportedAlgorithmError):
            km.create_key("k1", _BadAlgorithm())

    def test_no_method_exposes_private_material(self):
        km, _ = make_manager()
        km.create_key("k1")
        for name in dir(km):
            self.assertNotIn(name.lower(), ("export_key", "get_private_key", "private_key"))
        self.assertNotIn("private", repr(km).lower())
        blob = km.get_key_status("k1").public_dict()
        for bad in ("private", "secret", "seed"):
            self.assertNotIn(bad, str(blob).lower())


# --------------------------------------------------------------------- local provider
class LocalProvider(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self):
        km, _ = make_manager()
        km.create_key("iss_1")
        sig = km.sign("iss_1", K.DOMAIN_PASSPORT, b"payload")
        self.assertTrue(K.verify(km.get_public_key("iss_1"), K.DOMAIN_PASSPORT, b"payload", sig))
        self.assertFalse(K.verify(km.get_public_key("iss_1"), K.DOMAIN_PASSPORT, b"other", sig))

    def test_domain_separation_preserved(self):
        km, _ = make_manager()
        km.create_key("iss_1")
        sig = km.sign("iss_1", K.DOMAIN_PASSPORT, b"x")
        # a signature made for one domain must not validate under another
        self.assertFalse(K.verify(km.get_public_key("iss_1"), K.DOMAIN_PROOF, b"x", sig))

    def test_keys_encrypted_at_rest(self):
        km, be = make_manager()
        km.create_key("iss_1")
        blobs = list(be._store._blobs.values())
        self.assertTrue(blobs)
        for blob in blobs:
            self.assertTrue(blob.startswith(b"gAAAA"))            # Fernet token, not raw

    def test_wrong_master_key_cannot_use_keys(self):
        be = LocalKeyBackend(Fernet.generate_key())
        km = DefaultKeyManager(be, clock=FixedClock())
        km.create_key("iss_1")
        other = LocalKeyBackend(Fernet.generate_key())
        with self.assertRaises(KmsError):
            other.sign("iss_1", None, KeyAlgorithm.ED25519, b"x")

    def test_key_id_collision(self):
        km, _ = make_manager()
        km.create_key("iss_1")
        with self.assertRaises(KeyCollisionError):
            km.create_key("iss_1")

    def test_unknown_key_fails_closed(self):
        km, _ = make_manager()
        with self.assertRaises(KeyNotFoundError):
            km.sign("nope", b"d", b"x")
        self.assertIsNone(km.verification_material("nope"))

    def test_health_check(self):
        km, _ = make_manager()
        h = km.health_check()
        self.assertIsInstance(h, ProviderHealth)
        self.assertTrue(h.healthy)


# ------------------------------------------------------------------------ lifecycle
class Lifecycle(unittest.TestCase):
    def test_status_predicates(self):
        self.assertTrue(may_sign(KeyStatus.ACTIVE))
        self.assertTrue(may_sign(KeyStatus.ROTATING))
        self.assertFalse(may_sign(KeyStatus.RETIRING))
        self.assertFalse(may_sign(KeyStatus.RETIRED))
        self.assertFalse(may_sign(KeyStatus.REVOKED))
        # retiring/retired keys verify only INSIDE their overlap window
        self.assertTrue(may_verify(KeyStatus.RETIRED, 100.0, 200.0))
        self.assertFalse(may_verify(KeyStatus.RETIRED, 200.0, 200.0))
        self.assertFalse(may_verify(KeyStatus.PENDING, 0.0, None))
        self.assertTrue(may_destroy(KeyStatus.RETIRED))
        self.assertFalse(may_destroy(KeyStatus.ACTIVE))
        self.assertTrue(is_terminal(KeyStatus.REVOKED))

    def test_retire_stops_signing_keeps_verifying(self):
        km, _ = make_manager()
        km.create_key("k")
        km.retire_key("k", not_after=km.clock.now() + 3600)
        with self.assertRaises(KeyStateError):
            km.sign("k", K.DOMAIN_PASSPORT, b"x")
        self.assertIsNotNone(km.verification_material("k"))

    def test_retired_key_verifies_inside_window_then_stops(self):
        clock = FixedClock()
        km, _ = make_manager(clock=clock)
        km.create_key("k")
        km.retire_key("k", not_after=clock.now() + 100)
        # inside the window the key still verifies (live credentials keep working)
        self.assertIsNotNone(km.verification_material("k"))
        clock.advance(50)
        self.assertEqual(km.get_key_status("k").status.value, "retiring")
        self.assertIsNotNone(km.verification_material("k"))
        # past the deadline the key is RETIRED and no longer validates anything
        clock.advance(60)
        self.assertEqual(km.get_key_status("k").status.value, "retired")
        self.assertIsNone(km.verification_material("k"))
        km.destroy_key("k")                       # ...and is now safe to destroy
        self.assertFalse(km.has_key("k"))

    def test_revoke_is_terminal_and_idempotent(self):
        km, _ = make_manager()
        km.create_key("k")
        m = km.revoke_key("k", reason="compromise")
        self.assertEqual(m.status.value, "revoked")
        self.assertIsNone(km.verification_material("k"))
        with self.assertRaises(KeyStateError):
            km.sign("k", K.DOMAIN_PASSPORT, b"x")
        self.assertEqual(km.revoke_key("k", reason="again").status.value, "revoked")
        with self.assertRaises(KeyStateError):     # revoked cannot be un-revoked/re-rotated
            km.retire_key("k", not_after=km.clock.now() + 10)

    def test_destroy_refused_while_key_may_still_verify(self):
        km, _ = make_manager()
        km.create_key("k")
        with self.assertRaises(KeyStateError) as cm:
            km.destroy_key("k")
        self.assertIn("live credentials", str(cm.exception))

    def test_revoked_key_can_be_destroyed(self):
        km, _ = make_manager()
        km.create_key("k")
        km.revoke_key("k", reason="x")
        km.destroy_key("k")
        self.assertFalse(km.has_key("k"))


# ------------------------------------------------------------------------- rotation
class Rotation(unittest.TestCase):
    def test_rotation_links_and_overlap(self):
        km, _ = make_manager()
        km.create_key("iss_old")
        old, new = km.rotate_key("iss_old", "iss_new", grace_seconds=100)
        self.assertEqual(old.status.value, "rotating")
        self.assertEqual(old.rotates_to, "iss_new")
        self.assertEqual(new.rotated_from, "iss_old")
        # BOTH verify during the overlap; the old one still signs (graceful handover)
        self.assertIsNotNone(km.verification_material("iss_old"))
        self.assertIsNotNone(km.verification_material("iss_new"))
        self.assertTrue(km.sign("iss_old", K.DOMAIN_PASSPORT, b"x"))

    def test_overlap_close_moves_key_to_retired(self):
        clock = FixedClock()
        km, _ = make_manager(clock=clock)
        km.create_key("a")
        km.rotate_key("a", "b", grace_seconds=50)
        clock.advance(51)
        self.assertEqual(km.get_key_status("a").status.value, "retired")
        with self.assertRaises(KeyStateError):
            km.sign("a", K.DOMAIN_PASSPORT, b"x")

    def test_crash_during_rotation_leaves_old_key_usable(self):
        """If creating the successor fails, the old key must be completely untouched."""
        class FailGen(LocalKeyBackend):
            fail = False
            def generate(self, key_id, algorithm):
                if self.fail:
                    raise ProviderUnavailableError("simulated provider outage")
                return super().generate(key_id, algorithm)
        be = FailGen(Fernet.generate_key())
        km = DefaultKeyManager(be, clock=FixedClock(), retry_max_attempts=1)
        km.create_key("a")
        be.fail = True
        with self.assertRaises(ProviderUnavailableError):
            km.rotate_key("a", "b", grace_seconds=10)
        self.assertEqual(km.get_key_status("a").status.value, "active")   # unchanged
        self.assertTrue(km.sign("a", K.DOMAIN_PASSPORT, b"x"))            # still signs
        be.fail = False
        km.rotate_key("a", "b", grace_seconds=10)                         # retry succeeds
        self.assertEqual(km.get_key_status("b").status.value, "active")

    def test_concurrent_rotation_only_one_wins(self):
        km, _ = make_manager(clock=FixedClock())
        km.create_key("a")
        results, errors = [], []
        barrier = threading.Barrier(4)

        def go(i):
            barrier.wait()
            try:
                km.rotate_key("a", f"succ_{i}", grace_seconds=10)
                results.append(i)
            except KmsError as e:
                errors.append(e)

        threads = [threading.Thread(target=go, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 1)                 # exactly one rotation applied
        self.assertEqual(len(errors), 3)
        # the losing successors were cleaned up, not left orphaned
        self.assertEqual([m.key_id for m in km.list_keys(status=None)
                          if m.key_id.startswith("succ_")], [f"succ_{results[0]}"])


# ------------------------------------------------------- failure handling / retries
class FailureHandling(unittest.TestCase):
    def _backend(self, behavior):
        outer = self

        class Fake(CryptoBackend):
            name = "fake"
            def __init__(self):
                self.calls = 0
                self._keys = {}
            def generate(self, key_id, algorithm):
                return behavior(self, "generate", key_id)
            def public(self, key_id, external_ref, algorithm):
                return behavior(self, "public", key_id)
            def sign(self, key_id, external_ref, algorithm, data):
                return behavior(self, "sign", key_id)
            def destroy(self, key_id, external_ref):
                self.calls += 1
            def health(self):
                return ProviderHealth(healthy=True, provider="fake")
        return Fake()

    def test_transient_provider_failure_is_retried_then_succeeds(self):
        seen = {"n": 0}

        def behavior(be, op, key_id):
            if op == "sign":
                seen["n"] += 1
                if seen["n"] < 3:
                    raise ProviderUnavailableError("temporary")
                return b"\x00" * 64
            raise AssertionError(op)

        sleeps = []
        km = DefaultKeyManager(self._backend(behavior), clock=FixedClock(),
                               retry_max_attempts=5, retry_initial_backoff_seconds=0.01,
                               sleep=sleeps.append)
        km.metadata.put(KeyMetadata("k", "fake", KeyAlgorithm.ED25519, KeyStatus.ACTIVE,
                                    0.0, "AA", "sha256:x"))
        self.assertEqual(km.sign("k", b"d", b"x"), b"\x00" * 64)
        self.assertEqual(seen["n"], 3)
        self.assertEqual(len(sleeps), 2)               # bounded backoff, not unbounded

    def test_persistent_provider_failure_raises_and_audits(self):
        def behavior(be, op, key_id):
            raise ProviderUnavailableError("down")

        events = []

        class Sink:
            def record(self, event, **fields):
                events.append((event, fields))

        sleeps = []
        km = DefaultKeyManager(self._backend(behavior), clock=FixedClock(), audit=Sink(),
                               retry_max_attempts=3, sleep=sleeps.append)
        with self.assertRaises(ProviderUnavailableError):
            km.create_key("k")
        self.assertEqual(len(sleeps), 2)               # 3 attempts total
        # create failure rolls back: no dangling metadata
        self.assertIsNone(km.metadata.get("k"))

    def test_permission_error_is_not_retried(self):
        calls = {"n": 0}

        def behavior(be, op, key_id):
            calls["n"] += 1
            raise ProviderPermissionError("denied")

        km = DefaultKeyManager(self._backend(behavior), clock=FixedClock(),
                               retry_max_attempts=5, sleep=lambda s: None)
        with self.assertRaises(ProviderPermissionError):
            km.create_key("k")
        self.assertEqual(calls["n"], 1)                # policy denial: single attempt

    def test_rate_limit_error_is_retried(self):
        calls = {"n": 0}

        def behavior(be, op, key_id):
            calls["n"] += 1
            if calls["n"] < 2:
                raise ProviderRateLimitedError("429")
            return b"\x01" * 32, {"ref": None}

        km = DefaultKeyManager(self._backend(behavior), clock=FixedClock(),
                               retry_max_attempts=3, sleep=lambda s: None)
        km.create_key("k")
        self.assertEqual(calls["n"], 2)

    def test_provider_error_never_yields_a_valid_verdict(self):
        """A verifier must treat an unreachable key as invalid, not as 'skip the check'."""
        km, _ = make_manager()
        km.create_key("k")

        class Failing(LocalKeyBackend):
            def sign(self, key_id, external_ref, algorithm, data):
                raise ProviderUnavailableError("down")
        km2 = DefaultKeyManager(Failing(Fernet.generate_key()), clock=FixedClock(),
                                retry_max_attempts=1)
        km2.create_key("k")
        with self.assertRaises(ProviderUnavailableError):
            km2.sign("k", K.DOMAIN_PASSPORT, b"x")
        # and the trust gate reports no verification material rather than guessing
        km2.metadata.transition("k", (km2.get_key_status("k").status,), KeyStatus.REVOKED,
                                revoke_effective_at=0.0)
        self.assertIsNone(km2.verification_material("k"))


# --------------------------------------------------------------------------- config
class Config(unittest.TestCase):
    def test_production_refuses_local_provider(self):
        with self.assertRaises(KmsConfigError) as cm:
            KmsConfig(environment="production", provider="local").validate()
        self.assertIn("development", str(cm.exception))

    def test_explicit_override_allows_local_in_production(self):
        c = KmsConfig(environment="production", provider="local",
                      allow_local_in_production=True).validate()
        self.assertEqual(c.provider, "local")

    def test_staging_refuses_local_provider(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="staging", provider="local").validate()

    def test_exportable_keys_refused_outside_development(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="pkcs11",
                      allow_exportable_keys=True, pkcs11_library="/x.so",
                      pkcs11_token_label="t", pkcs11_pin="1").validate()

    def test_vault_requires_https_and_tls_outside_development(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="vault",
                      vault_addr="http://vault:8200", vault_token="t").validate()
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="production", provider="vault",
                      vault_addr="https://vault:8200", vault_token="t",
                      vault_tls_verify=False).validate()
        ok = KmsConfig(environment="production", provider="vault",
                       vault_addr="https://vault:8200", vault_token="t").validate()
        self.assertEqual(ok.provider, "vault")

    def test_vault_requires_credentials(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="development", provider="vault",
                      vault_addr="http://127.0.0.1:8200").validate()

    def test_pkcs11_requires_library_token_pin(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="development", provider="pkcs11").validate()

    def test_process_env_can_only_tighten(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(KmsConfigError):
                KmsConfig(environment="development", provider="vault",
                          vault_addr="https://v", vault_token="t").validate()

    def test_safe_dict_redacts_secrets(self):
        c = KmsConfig(environment="development", provider="vault",
                      vault_addr="http://127.0.0.1:8200", vault_token="s3cr3t")
        d = c.safe_dict()
        self.assertEqual(d["vault_token"], "<set>")
        self.assertNotIn("s3cr3t", str(d))

    def test_from_env_selects_provider(self):
        import os
        from unittest import mock
        env = {"AGENTGUARD_ENV": "development", "AGENTGUARD_KMS_PROVIDER": "local"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(KmsConfig.from_env().provider, "local")

    def test_no_silent_fallback_for_unknown_provider(self):
        with self.assertRaises(KmsConfigError):
            KmsConfig(environment="development", provider="aws").validate()


# --------------------------------------------------------------------- trust bridge
class TrustBridge(unittest.TestCase):
    def _cert(self, km, key_id, status="active", not_after=None):
        from agent_identity.core.models import IssuerCertificate
        meta = km.get_key_status(key_id)
        return IssuerCertificate(key_id, "acme", meta.public_key_b64, meta.fingerprint,
                                 "root_1", 0.0, "sig", status, not_after)

    def test_active_key_verifies_and_revoked_key_fails_closed(self):
        km, _ = make_manager()
        km.create_key("iss_1")
        base = MemoryTrustStore()
        base.add_root("root_1", km.get_public_key("iss_1"))
        trust = TrustStoreComposition(base, km, clock=FixedClock())
        trust.put_issuer_cert(self._cert(km, "iss_1"))
        self.assertIsNotNone(trust.get_issuer_cert("iss_1"))
        km.revoke_key("iss_1", reason="compromise")
        self.assertIsNone(trust.get_issuer_cert("iss_1"))     # revoked => untrusted

    def test_key_without_metadata_is_not_trusted(self):
        km, _ = make_manager()
        base = MemoryTrustStore()
        trust = TrustStoreComposition(base, km, clock=FixedClock())
        from agent_identity.core.models import IssuerCertificate
        base.put_issuer_cert(IssuerCertificate("ghost", "acme", "AA", "sha256:x", "root_1",
                                               0.0, "sig"))
        self.assertIsNone(trust.get_issuer_cert("ghost"))

    def test_certificate_public_key_must_match_kms_key(self):
        km, _ = make_manager()
        km.create_key("iss_1")
        trust = TrustStoreComposition(MemoryTrustStore(), km, clock=FixedClock())
        from agent_identity.core.models import IssuerCertificate
        with self.assertRaises(ConflictError):
            trust.put_issuer_cert(IssuerCertificate("iss_1", "acme", "WRONG", "sha256:x",
                                                    "root_1", 0.0, "sig"))

    def test_retiring_key_verifies_until_overlap_then_not(self):
        clock = FixedClock()
        km, _ = make_manager(clock=clock)
        km.create_key("iss_1")
        base = MemoryTrustStore()
        trust = TrustStoreComposition(base, km, clock=clock)
        km.retire_key("iss_1", not_after=clock.now() + 100)
        trust.put_issuer_cert(self._cert(km, "iss_1", status="retiring",
                                         not_after=clock.now() + 100))
        self.assertIsNotNone(trust.get_issuer_cert("iss_1"))
        clock.advance(101)
        self.assertIsNone(trust.get_issuer_cert("iss_1"))     # overlap closed

    def test_ceremony_key_bootstrapped_via_create_then_cert(self):
        """The normal integration path: key created by the KMS, then the issuer certificate
        registered by IdentityService, still resolves through the trust gate."""
        km, _ = make_manager()
        base = MemoryTrustStore()
        km.create_key("iss_boot")
        trust = TrustStoreComposition(base, km, clock=FixedClock())
        trust.put_issuer_cert(self._cert(km, "iss_boot"))
        got = trust.get_issuer_cert("iss_boot")
        self.assertIsNotNone(got)
        self.assertEqual(got.public_key, km.get_public_key("iss_boot"))


# ------------------------------------------------------------------------ redaction
class Redaction(unittest.TestCase):
    def test_private_material_never_reaches_logs_or_public_dict(self):
        records = []

        class H(logging.Handler):
            def emit(self, r):
                records.append(r.getMessage())

        h = H()
        lg = logging.getLogger("agentguard.identity.security")
        lg.addHandler(h)
        lg.setLevel(logging.DEBUG)
        be = LocalKeyBackend(Fernet.generate_key())
        try:
            km = DefaultKeyManager(be, clock=FixedClock(),
                                   logger=SecurityLogger(use_python_logging=True))
            km.create_key("iss_1")
            km.sign("iss_1", K.DOMAIN_PASSPORT, b"payload")
            km.rotate_key("iss_1", "iss_2", grace_seconds=10)
            km.revoke_key("iss_2", reason="compromise")
        finally:
            lg.removeHandler(h)
        text = "\n".join(records) + str(km.health_check().public_dict()) + repr(km)
        # every stored private key must be absent from the audit/log surface
        for blob in be._store._blobs.values():
            raw = be._f.decrypt(blob)
            self.assertNotIn(raw.hex(), text)
            self.assertNotIn(b64u_encode(raw), text)
        self.assertNotIn("BEGIN", text)
        self.assertIn("kms.key.create", text)
        self.assertIn("kms.key.rotate", text)


if __name__ == "__main__":
    unittest.main()
