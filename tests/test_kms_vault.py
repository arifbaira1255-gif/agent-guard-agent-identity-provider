"""HashiCorp Vault Transit provider tests.

Two clearly separated layers:

  * `VaultMockedTransport` — MOCKED. The adapter's HTTP error mapping, signature parsing and
    response validation are exercised with a fake transport and NO network. These run always.
  * `VaultRealIntegration` — REAL. Talks to an actual Vault server with the `transit` secrets
    engine. Skipped unless AGENTGUARD_TEST_VAULT_ADDR(+TOKEN) are set, so CI without a Vault
    is unaffected and nobody mistakes a mock for the real thing.

Bring a Vault up with:
    docker run -d --name ag-vault --cap-add=IPC_LOCK -p 8200:8200 \
      -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.15
    docker exec ag-vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
      vault secrets enable transit'
    export AGENTGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 AGENTGUARD_TEST_VAULT_TOKEN=root
"""
import base64
import json
import os
import unittest
import uuid

from agent_identity.core.clock import FixedClock
from agent_identity.crypto import keys as K
from agent_identity.kms import DefaultKeyManager, KeyNotFoundError, ProviderPermissionError, \
    ProviderRateLimitedError, ProviderResponseError, ProviderUnavailableError
from agent_identity.kms.providers.vault_provider import VaultTransitBackend
from agent_identity.kms.models import KeyAlgorithm

VAULT_ADDR = os.environ.get("AGENTGUARD_TEST_VAULT_ADDR", "")
VAULT_TOKEN = os.environ.get("AGENTGUARD_TEST_VAULT_TOKEN", "")
MOUNT = os.environ.get("AGENTGUARD_TEST_VAULT_MOUNT", "transit")
PREFIX = os.environ.get("AGENTGUARD_TEST_VAULT_PREFIX", "agentguard-it")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# =============================================================== MOCKED (no network)
class FakeTransport:
    """Scripted transport: lets us assert error mapping without touching a network."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def request(self, url, method, headers, body, timeout):
        self.calls.append((method, url))
        status, payload = self.script.pop(0)
        return status, payload


class VaultMockedTransport(unittest.TestCase):
    def _backend(self, script, **kw):
        return VaultTransitBackend(addr="http://vault:8200", token="t", transport=FakeTransport(script), **kw)

    def test_generate_reads_public_key_and_records_ref(self):
        pub = b"\x11" * 32
        t = FakeTransport([
            (404, {"errors": ["not found"]}),                                   # existence probe
            (200, {}),                                                          # create
            (200, {"data": {"latest_version": 1, "keys": {"1": {"public_key": _b64(pub)}}}}),
        ])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        raw, refs = be.generate("k1", KeyAlgorithm.ED25519)
        self.assertEqual(raw, pub)
        self.assertEqual(refs["ref"], "agentguard-k1")

    def test_collision_detected_without_creating(self):
        t = FakeTransport([(200, {"data": {}})])                                # probe says exists
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        from agent_identity.kms import KeyCollisionError
        with self.assertRaises(KeyCollisionError):
            be.generate("k1", KeyAlgorithm.ED25519)
        self.assertEqual(len(t.calls), 1)                                       # no create call

    def test_signature_prefix_stripped(self):
        raw_sig = b"\x22" * 64
        t = FakeTransport([(200, {"data": {"signature": "vault:v1:" + _b64(raw_sig)}})])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        self.assertEqual(be.sign("k", "agentguard-k", KeyAlgorithm.ED25519, b"data"), raw_sig)

    def test_undersized_signature_is_rejected(self):
        t = FakeTransport([(200, {"data": {"signature": "vault:v1:" + _b64(b"\x00" * 10)}})])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        with self.assertRaises(ProviderResponseError):
            be.sign("k", "agentguard-k", KeyAlgorithm.ED25519, b"d")

    def test_missing_signature_field_is_rejected(self):
        t = FakeTransport([(200, {"data": {}})])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        with self.assertRaises(ProviderResponseError):
            be.sign("k", "agentguard-k", KeyAlgorithm.ED25519, b"d")

    def test_error_status_mapping(self):
        cases = [(403, ProviderPermissionError), (429, ProviderRateLimitedError),
                 (500, ProviderUnavailableError), (418, ProviderResponseError)]
        for status, exc in cases:
            t = FakeTransport([(status, {"errors": ["nope"]})])
            be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
            with self.assertRaises(exc, msg=str(status)):
                be.sign("k", "agentguard-k", KeyAlgorithm.ED25519, b"d")

    def test_404_on_read_maps_to_key_not_found(self):
        t = FakeTransport([(404, {"errors": ["missing"]})])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        with self.assertRaises(KeyNotFoundError):
            be.public("k", "agentguard-k", KeyAlgorithm.ED25519)

    def test_destroy_is_idempotent_for_absent_key(self):
        t = FakeTransport([(404, {"errors": ["missing"]})])
        be = VaultTransitBackend(addr="http://vault:8200", token="t", transport=t)
        be.destroy("k", "agentguard-k")                                        # must not raise
        self.assertEqual(len(t.calls), 1)

    def test_token_never_leaks_through_repr(self):
        # the adapter itself allows http (dev); the config layer forbids it in production.
        # What matters here is that no secret leaks through repr().
        be = VaultTransitBackend(addr="http://vault:8200", token="super-secret-token",
                                 transport=FakeTransport([(200, {})]))
        self.assertNotIn("super-secret-token", repr(be))
        self.assertIn("<redacted>", repr(be))


# ================================================================ REAL (a live Vault)
@unittest.skipUnless(VAULT_ADDR and VAULT_TOKEN,
                     "set AGENTGUARD_TEST_VAULT_ADDR/TOKEN to run the real Vault tests")
class VaultRealIntegration(unittest.TestCase):
    """Runs against a REAL Vault transit engine. Verifies non-exportable Ed25519 keys,
    real server-side signing, and that our signatures validate with standard Ed25519."""

    @classmethod
    def setUpClass(cls):
        cls.be = VaultTransitBackend(addr=VAULT_ADDR, token=VAULT_TOKEN, mount=MOUNT,
                                     prefix=PREFIX, timeout=5.0)

    def _id(self):
        return "it" + uuid.uuid4().hex[:16]

    def test_health_check_against_real_vault(self):
        h = self.be.health()
        self.assertTrue(h.healthy, h.detail)
        self.assertIsNotNone(h.latency_ms)

    def test_real_keygen_sign_verify_and_nonexportable(self):
        key_id = self._id()
        raw, refs = self.be.generate(key_id, KeyAlgorithm.ED25519)
        self.assertEqual(len(raw), 32)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        msg = b"agentguard-real-vault"
        sig = self.be.sign(key_id, refs["ref"], KeyAlgorithm.ED25519, msg)
        self.assertEqual(len(sig), 64)
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, msg)      # standard Ed25519 sig
        self.assertEqual(self.be.public(key_id, refs["ref"], KeyAlgorithm.ED25519), raw)
        self.be.destroy(key_id, refs["ref"])
        with self.assertRaises(KeyNotFoundError):
            self.be.public(key_id, refs["ref"], KeyAlgorithm.ED25519)

    def test_key_is_not_exportable_over_the_api(self):
        """The custody claim must hold: Vault must refuse to hand back the private key."""
        key_id = self._id()
        _raw, refs = self.be.generate(key_id, KeyAlgorithm.ED25519)
        try:
            status, _ = self.be._call("GET", f"/v1/{MOUNT}/export/private-key/{refs['ref']}",
                                      None, ok=(200, 400, 403, 404))
            self.assertIn(status, (400, 403, 404))     # never a 200 with key material
        finally:
            self.be.destroy(key_id, refs["ref"])

    def test_manager_end_to_end_on_real_vault(self):
        km = DefaultKeyManager(self.be, clock=FixedClock())
        key_id = self._id()
        meta = km.create_key(key_id)
        self.assertEqual(meta.provider, "vault")
        self.assertFalse(meta.exportable)                       # non-exportable custody
        sig = km.sign(key_id, K.DOMAIN_PASSPORT, b"payload")
        self.assertTrue(K.verify(km.get_public_key(key_id), K.DOMAIN_PASSPORT, b"payload", sig))
        old, new = km.rotate_key(key_id, key_id + "b", grace_seconds=60)
        self.assertEqual(old.status.value, "rotating")
        # BOTH keys verify during the overlap — the property rotation exists for
        sig2 = km.sign(key_id + "b", K.DOMAIN_PASSPORT, b"payload")
        self.assertTrue(K.verify(km.get_public_key(key_id + "b"), K.DOMAIN_PASSPORT, b"payload", sig2))
        orig = km.sign(key_id, K.DOMAIN_PASSPORT, b"payload")
        self.assertTrue(K.verify(km.get_public_key(key_id), K.DOMAIN_PASSPORT, b"payload", orig))
        km.revoke_key(key_id + "b", reason="test-teardown")
        for k in (key_id, key_id + "b"):
            m = km.metadata.get(k)
            km.metadata.delete(k)
            try:
                self.be.destroy(k, m.external_ref if m else None)
            except Exception:
                pass

    def test_real_provider_failure_is_not_masked(self):
        """A wrong token must surface as a provider error, never as a valid operation."""
        bad = VaultTransitBackend(addr=VAULT_ADDR, token="definitely-not-a-token",
                                  mount=MOUNT, prefix=PREFIX, timeout=5.0)
        with self.assertRaises((ProviderPermissionError, KeyNotFoundError)):
            bad.sign("x", f"{PREFIX}-x", KeyAlgorithm.ED25519, b"d")


if __name__ == "__main__":
    unittest.main()
