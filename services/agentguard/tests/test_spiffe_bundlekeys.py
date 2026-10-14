"""Regression for a bug found only against a REAL SPIRE agent: bundle maps are keyed by 'spiffe://<td>',
not the bare trust domain. Both forms are accepted; anything else is ignored and counted."""
import unittest

from agent_identity.spiffe import metrics as M
from agent_identity.spiffe import wire
from agent_identity.spiffe.workload_api import normalize_bundle_key
from tests.spiffe_env import TD, Env


class Normalise(unittest.TestCase):
    def test_accepted_and_rejected_forms(self):
        self.assertEqual(normalize_bundle_key("spiffe://agentguard-it.internal"), "agentguard-it.internal")
        self.assertEqual(normalize_bundle_key("agentguard-it.internal"), "agentguard-it.internal")
        for bad in ("", None, 5, "spiffe://", "spiffe://td/path", "spiffe://td?x=1", "spiffe://u@td", "td:8080",
                    "spiffe://TD.Example", "spiffe://a b", "spiffe://td\x00", "https://td", "spiffe://td/"):
            self.assertIsNone(normalize_bundle_key(bad), repr(bad))


class RealSpireWireShape(unittest.TestCase):
    def test_uri_keyed_bundles_are_accepted_for_own_domain(self):
        e = Env()
        self.assertEqual(wire.decode_jwt_bundles_response(
            wire.encode_jwt_bundles_response({"spiffe://" + TD: b"{}"})), {"spiffe://" + TD: b"{}"})
        e.p.refresh_bundles()                                  # dev Workload API now emits URI keys like SPIRE
        self.assertTrue(e.p.bundles.has_fresh(TD))
        r = e.p.verify(e.jwt(), audience="gateway")
        self.assertTrue(r.valid, r.reason)

    def test_uri_keyed_unknown_domain_is_still_rejected_and_counted(self):
        e = Env()
        before = e.p.metrics.total(M.BUNDLE_REJECTED)
        e.p.client._normalize_keys({"spiffe://evil.example.net": b"x"})      # normaliser alone keeps the key ...
        raw = wire.encode_x509_bundles_response({"spiffe://evil.example.net": b"x", "spiffe://" + TD + "/x": b"y"})
        out = e.p.client._decode_bundles(wire.decode_x509_bundles_response, raw)
        self.assertEqual(set(out), {"evil.example.net"})                     # path-bearing key dropped
        self.assertGreater(e.p.metrics.total(M.BUNDLE_REJECTED), before)
        e.p.refresh_bundles()
        self.assertFalse(e.p.bundles.is_allowed("evil.example.net"))         # ... but allow-listing still decides

    def test_duplicate_keys_in_one_response_cannot_override_trust(self):
        e = Env()
        raw = wire.encode_x509_bundles_response({"spiffe://" + TD: b"A"}) + \
              wire.encode_x509_bundles_response({TD: b"B"})                  # same domain twice (two spellings)
        out = e.p.client._decode_bundles(wire.decode_x509_bundles_response, raw)
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
