import base64
import json
import os
import unittest
from unittest import mock

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from agent_identity.core.clock import FixedClock
from agent_identity.spiffe import metrics as M, wire
from agent_identity.spiffe.bundle import TrustBundleStore, split_der
from agent_identity.spiffe.config import Environment, SpireConfig
from agent_identity.spiffe.dev import DevSpireCA, DevWorkloadTransport
from agent_identity.spiffe.errors import (ConfigError, DevModeError, R, SpiffeIdError, SvidError,
                                          UnknownTrustDomainError, WorkloadApiUnavailable)
from agent_identity.spiffe.factory import build_identity_provider
from agent_identity.spiffe.ids import agent_spiffe_id, parse_agent_spiffe_id, parse_spiffe_id
from agent_identity.spiffe.jwtsvid import verify_jwt_svid
from agent_identity.spiffe.x509svid import parse_x509_svid, verify_x509_svid
from tests.spiffe_env import TD, cfg

SID = f"spiffe://{TD}/org/acme/agent/agt_1/instance/ins_1"
ALGS = ("ES256",)


def store(clock, ca, td=TD, max_age=3600):
    s = TrustBundleStore(td, clock=clock, max_age_seconds=max_age, metrics=M.Metrics())
    s.update(td, x509_der=ca.bundle_der(), jwks=ca.jwks())
    return s


class SpiffeIdTests(unittest.TestCase):
    def test_roundtrip_and_determinism(self):
        a = agent_spiffe_id(TD, "acme", "agt_1", "ins_1")
        self.assertEqual(a, agent_spiffe_id(TD, "acme", "agt_1", "ins_1"))
        p = parse_agent_spiffe_id(a)
        self.assertEqual((p.org_id, p.agent_id, p.instance_id), ("acme", "agt_1", "ins_1"))

    def test_adversarial_ids_rejected(self):
        bad = ["", "http://x/y", f"spiffe://{TD}/org/acme/agent/a/../b", f"spiffe://{TD}/a//b",
               f"spiffe://{TD}/a?x=1", f"spiffe://{TD}/a#f", f"spiffe://user@{TD}/a",
               f"spiffe://{TD}:443/a", "spiffe://UPPER.case/a", f"spiffe://{TD}/a b",
               f"spiffe://{TD}/./a", f"spiffe://{TD}/a%2fb", "spiffe://" + "a" * 300 + "/x", None, 5]
        for b in bad:
            with self.assertRaises(SpiffeIdError, msg=str(b)):
                parse_spiffe_id(b)

    def test_agent_parser_is_strict_no_prefix_matching(self):
        for v in [f"spiffe://{TD}/org/acme/agent/a/instance/i/extra", f"spiffe://{TD}/org/acme",
                  f"spiffe://{TD}/org/acme/agent/a/instance", f"spiffe://{TD}/x/acme/agent/a",
                  f"spiffe://{TD}"]:
            with self.assertRaises(SpiffeIdError, msg=v):
                parse_agent_spiffe_id(v)
        with self.assertRaises(SpiffeIdError):
            agent_spiffe_id(TD, "ac/me", "a")


class ConfigTests(unittest.TestCase):
    def prod(self, **kw):
        d = dict(environment="production", provider="spire", trust_domain="corp.example.net")
        d.update(kw)
        return SpireConfig.from_dict(d)

    def test_production_ok_and_defaults_are_strict(self):
        c = self.prod()
        self.assertEqual(c.environment, Environment.PRODUCTION)
        self.assertTrue(c.require_instance_identity)
        self.assertEqual(c.tls_min_version, "TLSv1.3")

    def test_dev_provider_forbidden_outside_dev(self):
        for env in ("production", "staging"):
            with self.assertRaises(ConfigError):
                SpireConfig.from_dict(dict(environment=env, provider="dev", trust_domain="x.example.net"))

    def test_unsafe_production_settings_rejected(self):
        for kw in (dict(trust_domain="agentguard.local"), dict(trust_domain=""),
                   dict(socket_path="tcp://10.0.0.1:8081"), dict(clock_skew_seconds=120),
                   dict(require_instance_identity=False), dict(jwt_allowed_algorithms=("HS256",)),
                   dict(jwt_allowed_algorithms=("none",)), dict(rotation_threshold_fraction=1.5),
                   dict(unknown_key=1), dict(federated_trust_domains=("corp.example.net",))):
            with self.assertRaises(ConfigError, msg=str(kw)):
                self.prod(**kw)

    def test_process_env_can_only_tighten(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(ConfigError):
                cfg()                                   # development config under production process
            with self.assertRaises(ConfigError):
                SpireConfig.from_dict(dict(environment="staging", trust_domain="x.example.net"))
            self.prod()
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "bogus"}):
            with self.assertRaises(ConfigError):
                self.prod()

    def test_dev_transport_refuses_non_dev(self):
        clock = FixedClock()
        ca = DevSpireCA(TD, clock)
        with self.assertRaises(ConfigError):
            DevWorkloadTransport(SpireConfig(environment=Environment.PRODUCTION, provider="dev",
                                             trust_domain=TD), ca)
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "staging"}):
            with self.assertRaises(ConfigError):
                DevWorkloadTransport(cfg(), ca)
        DevWorkloadTransport(cfg(), ca)                 # allowed in development

    def test_factory_never_builds_dev_in_production(self):
        from tests.spiffe_env import Env
        e = Env()
        c = SpireConfig(environment=Environment.PRODUCTION, provider="dev", trust_domain=TD)
        with self.assertRaises(ConfigError):
            build_identity_provider(e.svc, c)

    def test_from_env_requires_trust_domain(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigError):
                SpireConfig.from_env()
        with mock.patch.dict(os.environ, {"AGENTGUARD_SPIFFE_TRUST_DOMAIN": "corp.example.net"}, clear=True):
            self.assertEqual(SpireConfig.from_env().environment, Environment.PRODUCTION)

    def test_grpc_transport_fails_closed_without_grpc(self):
        try:
            import grpc  # noqa
            self.skipTest("grpcio installed")
        except ImportError:
            from agent_identity.spiffe.workload_api import GrpcTransport
            with self.assertRaises(WorkloadApiUnavailable):
                GrpcTransport("unix:///nonexistent.sock")


class WireTests(unittest.TestCase):
    def test_malformed_protobuf_rejected(self):
        for b in (b"\x0a\xff", b"\x0a", b"\x80", b"\x00\x01", b"\x0b\x00", b"\x0a\x05abc"):
            with self.assertRaises(SvidError, msg=b):
                wire.decode_x509_svid_response(b)

    def test_roundtrip(self):
        enc = wire.encode_jwt_svid_response([{"spiffe_id": SID, "svid": "tok"}])
        self.assertEqual(wire.decode_jwt_svid_response(enc)[0]["svid"], "tok")
        aud, sid = wire.decode_jwt_svid_request(wire.encode_jwt_svid_request(["a", "b"], SID))
        self.assertEqual((aud, sid), (["a", "b"], SID))

    def test_split_der_rejects_garbage(self):
        for b in (b"", b"\x31\x00", b"\x30", b"\x30\x82\x10\x00abc"):
            with self.assertRaises(SvidError):
                split_der(b)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock()
        self.ca = DevSpireCA(TD, self.clock)

    def test_valid_bundle_and_isolation(self):
        s = store(self.clock, self.ca)
        self.assertTrue(s.has_fresh(TD))
        with self.assertRaises(UnknownTrustDomainError):
            s.get("other.example.net")
        with self.assertRaises(UnknownTrustDomainError):
            s.update("other.example.net", x509_der=self.ca.bundle_der())

    def test_non_ca_or_leaf_or_corrupt_roots_rejected_and_old_bundle_kept(self):
        s = store(self.clock, self.ca)
        leaf, _ = self.ca.issue_x509(SID)
        before = s.get(TD).x509_roots
        for bad in (split_der(leaf)[0], b"garbage", self.ca.bundle_der()[:-5], b""):
            with self.assertRaises(SvidError):
                s.update(TD, x509_der=bad)
        self.assertEqual(s.get(TD).x509_roots, before)

    def test_expired_root_rejected(self):
        s = store(self.clock, self.ca)
        self.clock.advance(11 * 365 * 86400)
        with self.assertRaises(SvidError):
            s.update(TD, x509_der=self.ca.bundle_der())

    def test_malformed_jwks_rejected(self):
        s = store(self.clock, self.ca)
        for bad in (b"{}", b"not json", json.dumps({"keys": [{"kty": "oct", "kid": "a", "k": "AA"}]}).encode(),
                    json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "kid": "k"}]}).encode(),
                    json.dumps({"keys": [{"kty": "EC", "crv": "P-256"}]}).encode()):
            with self.assertRaises(SvidError):
                s.update(TD, jwks=bad)

    def test_staleness_denies(self):
        s = store(self.clock, self.ca, max_age=100)
        self.clock.advance(101)
        with self.assertRaises(SvidError) as cm:
            s.get(TD)
        self.assertEqual(cm.exception.reason, R.BUNDLE_STALE)

    def test_rotation_overlap_then_retire(self):
        s = store(self.clock, self.ca)
        old_chain, _ = self.ca.issue_x509(SID)
        self.ca.rotate_root(keep_old=True)
        s.update(TD, x509_der=self.ca.bundle_der())
        new_chain, _ = self.ca.issue_x509(SID)
        for c in (old_chain, new_chain):
            verify_x509_svid(split_der(c), s, self.clock.now())
        self.ca.drop_old_roots()
        s.update(TD, x509_der=self.ca.bundle_der())
        verify_x509_svid(split_der(new_chain), s, self.clock.now())
        with self.assertRaises(SvidError) as cm:
            verify_x509_svid(split_der(old_chain), s, self.clock.now())
        self.assertEqual(cm.exception.reason, R.BAD_CHAIN)


class X509Tests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock()
        self.ca = DevSpireCA(TD, self.clock)
        self.s = store(self.clock, self.ca)

    def chain(self, sid=SID, ttl=None, ca=None):
        c, k = (ca or self.ca).issue_x509(sid, ttl)
        return c, k

    def test_parse_and_verify(self):
        c, k = self.chain()
        p = parse_x509_svid(c, k)
        self.assertEqual(str(p.spiffe_id), SID)
        self.assertTrue(p.has_private_key())
        v = verify_x509_svid(split_der(c), self.s, self.clock.now())
        self.assertEqual(str(v.spiffe_id), SID)

    def test_expired_and_not_yet_valid(self):
        c, _ = self.chain(ttl=60)
        self.clock.advance(61 + 30)
        with self.assertRaises(SvidError) as cm:
            verify_x509_svid(split_der(c), self.s, self.clock.now(), skew_seconds=30)
        self.assertEqual(cm.exception.reason, R.EXPIRED)
        c2, _ = self.ca.issue_x509(SID, not_before=self.clock.now() + 10_000)
        with self.assertRaises(SvidError) as cm:
            verify_x509_svid(split_der(c2), self.s, self.clock.now())
        self.assertEqual(cm.exception.reason, R.NOT_YET_VALID)

    def test_certificate_substitution_attacker_ca_same_id_denied(self):
        evil = DevSpireCA(TD, self.clock, name="evil")
        c, _ = self.chain(ca=evil)
        with self.assertRaises(SvidError) as cm:
            verify_x509_svid(split_der(c), self.s, self.clock.now())
        self.assertEqual(cm.exception.reason, R.BAD_CHAIN)

    def test_other_trust_domain_ca_cannot_vouch_for_ours_or_be_trusted(self):
        other = DevSpireCA("other.example.net", self.clock)
        c, _ = other.issue_x509(f"spiffe://other.example.net/org/acme/agent/a")
        with self.assertRaises(UnknownTrustDomainError):
            verify_x509_svid(split_der(c), self.s, self.clock.now())
        c2, _ = other.issue_x509(SID)                  # claims OUR id, signed by foreign CA
        with self.assertRaises(SvidError) as cm:
            verify_x509_svid(split_der(c2), self.s, self.clock.now())
        self.assertEqual(cm.exception.reason, R.BAD_CHAIN)

    def test_tampered_certificate_denied(self):
        c, _ = self.chain()
        der = bytearray(split_der(c)[0])
        der[60] ^= 0xFF
        with self.assertRaises(SvidError):
            verify_x509_svid([bytes(der)] + split_der(c)[1:], self.s, self.clock.now())

    def test_chain_without_intermediate_denied(self):
        c, _ = self.chain()
        with self.assertRaises(SvidError):
            verify_x509_svid(split_der(c)[:1], self.s, self.clock.now())

    def test_key_mismatch_and_garbage_key(self):
        c, _ = self.chain()
        other_key = self.chain()[1]
        with self.assertRaises(SvidError) as cm:
            parse_x509_svid(c, other_key)
        self.assertEqual(cm.exception.reason, R.BINDING_MISMATCH)
        with self.assertRaises(SvidError):
            parse_x509_svid(c, b"\x30\x03abc")

    def test_ca_certificate_cannot_be_used_as_svid(self):
        with self.assertRaises(SvidError):
            parse_x509_svid(self.ca.roots[0].public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))

    def test_malformed_input(self):
        for b in ([], [b"x"], [b"\x30\x03abc"]):
            with self.assertRaises(SvidError):
                verify_x509_svid(b, self.s, self.clock.now())


class JwtTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock()
        self.ca = DevSpireCA(TD, self.clock)
        self.s = store(self.clock, self.ca)

    def v(self, tok, aud="gw", **kw):
        kw.setdefault("allowed_algs", ALGS)
        kw.setdefault("skew_seconds", 30)
        return verify_jwt_svid(tok, aud, self.s, self.clock.now(), **kw)

    def deny(self, tok, reason, aud="gw", **kw):
        with self.assertRaises(SvidError) as cm:
            self.v(tok, aud, **kw)
        self.assertEqual(cm.exception.reason, reason)

    def test_valid(self):
        j = self.v(self.ca.issue_jwt(SID, "gw"))
        self.assertEqual(str(j.spiffe_id), SID)
        self.assertNotIn(j.token, repr(j))

    def test_expiry(self):
        t = self.ca.issue_jwt(SID, "gw", ttl=60)
        self.clock.advance(61 + 31)
        self.deny(t, R.EXPIRED)

    def test_audience(self):
        t = self.ca.issue_jwt(SID, ["other"])
        self.deny(t, R.BAD_AUDIENCE)
        self.deny(self.ca.issue_jwt(SID, "gw"), R.BAD_AUDIENCE, aud="")
        self.v(self.ca.issue_jwt(SID, ["x", "gw"]))

    def test_issuer_pinning(self):
        self.deny(self.ca.issue_jwt(SID, "gw", claims={"iss": "evil"}), R.BAD_ISSUER, expected_issuer="spire")
        self.deny(self.ca.issue_jwt(SID, "gw"), R.BAD_ISSUER, expected_issuer="spire")
        self.v(self.ca.issue_jwt(SID, "gw", claims={"iss": "spire"}), expected_issuer="spire")

    def test_untrusted_issuer_key(self):
        evil = DevSpireCA(TD, self.clock, name="evil")
        self.deny(evil.issue_jwt(SID, "gw", kid="evil-kid"), R.UNKNOWN_KEY)
        self.deny(evil.issue_jwt(SID, "gw"), R.BAD_SIGNATURE)       # colliding kid, wrong key

    def test_signature_forgery_with_legit_kid(self):
        atk = ec.generate_private_key(ec.SECP256R1())
        self.deny(self.ca.issue_jwt(SID, "gw", key=atk), R.BAD_SIGNATURE)

    def test_payload_tampering(self):
        h, p, s = self.ca.issue_jwt(SID, "gw").split(".")
        forged = base64.urlsafe_b64encode(json.dumps(
            {"sub": SID.replace("ins_1", "ins_2"), "aud": "gw", "exp": int(self.clock.now()) + 100}
        ).encode()).rstrip(b"=").decode()
        self.deny(f"{h}.{forged}.{s}", R.BAD_SIGNATURE)

    def test_algorithm_confusion(self):
        base = {"sub": SID, "aud": "gw", "exp": int(self.clock.now()) + 100}
        none_tok = pyjwt.encode(base, key=None, algorithm="none", headers={"kid": self.ca.active_kid})
        self.deny(none_tok, R.BAD_ALG)
        hs = pyjwt.encode(base, "x" * 40, algorithm="HS256", headers={"kid": self.ca.active_kid})
        self.deny(hs, R.BAD_ALG)

    def test_unknown_trust_domain(self):
        other = DevSpireCA("other.example.net", self.clock)
        with self.assertRaises(UnknownTrustDomainError):
            self.v(other.issue_jwt("spiffe://other.example.net/org/a/agent/b", "gw"))

    def test_lifetime_policy_and_missing_claims(self):
        self.deny(self.ca.issue_jwt(SID, "gw", ttl=100_000), R.TTL_TOO_LONG)
        base = {"sub": SID, "aud": "gw"}
        no_exp = pyjwt.encode(base, self.ca.jwt_keys[self.ca.active_kid], algorithm="ES256",
                              headers={"kid": self.ca.active_kid})
        self.deny(no_exp, R.MALFORMED)
        self.deny(self.ca.issue_jwt(SID, "gw", claims={"nbf": int(self.clock.now()) + 5000}), R.NOT_YET_VALID)

    def test_garbage_tokens(self):
        for t in ("", "a.b.c", "x" * 9000, None, 5, "a.b"):
            with self.assertRaises(SvidError):
                self.v(t)

    def test_bad_sub(self):
        for sub in ("http://x", f"spiffe://{TD}", "nonsense"):
            with self.assertRaises(SvidError):
                self.v(self.ca.issue_jwt(sub, "gw"))

    def test_replay_cache(self):
        from agent_identity.storage.memory import MemoryReplayCache
        rc, t = MemoryReplayCache(1000), self.ca.issue_jwt(SID, "gw")
        self.v(t, replay_cache=rc)
        self.deny(t, R.REPLAY, replay_cache=rc)


if __name__ == "__main__":
    unittest.main()
