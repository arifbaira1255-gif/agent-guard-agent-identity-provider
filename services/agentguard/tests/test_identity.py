import json
import logging
import unittest

from agent_identity import (AgentSideKey, IdentityConfig, IdentityService, Reason,
                            RevocationReason, SPAWN_AUDIENCE)
from agent_identity.core.errors import (UnauthorizedError, ValidationError)
from agent_identity.crypto import keys
from agent_identity.crypto.encoding import b64u_decode, b64u_encode
from agent_identity.observability.logging import SecurityLogger
from tests.helpers import make_agent, make_service


def tamper_payload(token, **changes):
    pre, p, s = token.split(".")
    d = json.loads(b64u_decode(p))
    d.update(changes)
    return f"{pre}.{b64u_encode(json.dumps(d, sort_keys=True).encode())}.{s}"


class Registration(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()

    def test_01_register_valid_agent(self):
        a = self.svc.register_agent("acme", "support-bot", "support", "ops@acme.com",
                                    "desc", ["tickets:read"], "production", {"k": "v"})
        self.assertTrue(a["agent_id"].startswith("agt_"))
        self.assertEqual(a["status"], "active")
        self.assertFalse(a["is_sub_agent"])

    def test_02_reject_malformed_registration(self):
        bad = [dict(agent_name="../etc/passwd"), dict(agent_name=""), dict(agent_type="X Y"),
               dict(owner="a\nb"), dict(capabilities=["ok", "BAD CAP"]),
               dict(capabilities="tickets:read"), dict(environment="PROD!"),
               dict(metadata={"__proto__": 1}), dict(metadata={"k": "x\u202e"}),
               dict(metadata={"k": {"nested": {"too": {"deep": 1}}}}),
               dict(description="x" * 2000)]
        for over in bad:
            kw = dict(org_id="acme", agent_name="ok", agent_type="t", owner="o@x.com")
            kw.update(over)
            with self.assertRaises(ValidationError, msg=str(over)):
                self.svc.register_agent(**kw)
        with self.assertRaises(Exception):   # unknown org
            self.svc.register_agent("nope", "ok", "t", "o@x.com")

    def test_03_cryptographic_identity_and_ids_unpredictable(self):
        a1, _, _ = make_agent(self.svc)
        a2, _, _ = make_agent(self.svc)
        self.assertNotEqual(a1["agent_id"], a2["agent_id"])
        self.assertNotEqual(a1["key_fingerprint"], a2["key_fingerprint"])
        self.assertEqual(keys.fingerprint_b64(a1["public_key"]), a1["key_fingerprint"])
        self.assertGreaterEqual(len(a1["agent_id"]), 20)

    def test_18_fingerprints_verify(self):
        a, _, c = make_agent(self.svc)
        self.assertEqual(c.passport["key_fingerprint"], keys.fingerprint_b64(c.passport["public_key"]))
        msg = b"hello"
        priv = keys.generate_private_key()
        pub = b64u_encode(keys.public_bytes(priv))
        sig = keys.sign(priv, keys.DOMAIN_PASSPORT, msg)
        self.assertTrue(keys.verify(pub, keys.DOMAIN_PASSPORT, msg, sig))
        self.assertFalse(keys.verify(pub, keys.DOMAIN_PROOF, msg, sig))   # domain separation
        self.assertFalse(keys.verify(pub, keys.DOMAIN_PASSPORT, b"hellO", sig))

    def test_register_with_parent_rejected(self):
        a, _, _ = make_agent(self.svc)
        with self.assertRaises(UnauthorizedError):
            self.svc.register_agent("acme", "fake-child", "t", "o@x.com",
                                    parent_agent_id=a["agent_id"])

    def test_org_capability_allowlist(self):
        self.svc.register_organization("strict", "Strict", allowed_capabilities=["a:read"])
        with self.assertRaises(UnauthorizedError):
            self.svc.register_agent("strict", "x", "t", "o@x.com", capabilities=["a:write"])


class Credentials(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        self.a, self.i, self.c = make_agent(self.svc)

    def verify(self, token=None, **kw):
        token = token or self.c.token
        kw.setdefault("proof", self.svc.create_proof(token, "gw"))
        kw.setdefault("audience", "gw")
        return self.svc.verify_credential(token, **kw)

    def test_04_05_passport_contents_and_valid(self):
        p = self.c.passport
        for k in ("agent_id", "instance_id", "org_id", "owner", "issuer", "iat", "nbf", "exp",
                  "capabilities", "is_sub_agent", "credential_id", "public_key"):
            self.assertIn(k, p)
        self.assertEqual(p["exp"] - p["iat"], 900)
        r = self.verify()
        self.assertTrue(r.valid, r.reason)
        d = r.to_dict()
        self.assertEqual(d["agent_id"], self.a["agent_id"])
        self.assertIsNone(d["reason"])

    def test_06_modified_passport(self):
        for field, val in [("agent_id", "agt_attacker"), ("capabilities", ["admin:*"]),
                           ("exp", 9_999_999_999), ("org_id", "evil")]:
            t = tamper_payload(self.c.token, **{field: val})
            r = self.svc.verify_credential(t, require_proof=False)
            self.assertFalse(r.valid, field)
            self.assertIn(r.reason, (Reason.INVALID_SIGNATURE, Reason.UNKNOWN_ISSUER))

    def test_07_invalid_signature(self):
        pre, p, s = self.c.token.split(".")
        bad = b64u_decode(s)
        bad = bytes([bad[0] ^ 1]) + bad[1:]
        r = self.svc.verify_credential(f"{pre}.{p}.{b64u_encode(bad)}", require_proof=False)
        self.assertEqual(r.reason, Reason.INVALID_SIGNATURE)
        # forged by an attacker-controlled key with a spoofed issuer id
        evil = keys.generate_private_key()
        payload = json.loads(b64u_decode(p))
        pb = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        forged = f"agp1.{b64u_encode(pb)}.{b64u_encode(keys.sign(evil, keys.DOMAIN_PASSPORT, pb))}"
        self.assertEqual(self.svc.verify_credential(forged, require_proof=False).reason,
                         Reason.INVALID_SIGNATURE)

    def test_malformed_tokens(self):
        for t in ["", "x", "agp1.a.b", "agp1..", None, 123, "agp1." + "A" * 20000,
                  "agp2." + ".".join(self.c.token.split(".")[1:])]:
            r = self.svc.verify_credential(t, require_proof=False)
            self.assertFalse(r.valid)
            self.assertEqual(r.reason, Reason.MALFORMED_TOKEN)

    def test_08_expired(self):
        self.clock.advance(901)
        self.assertEqual(self.svc.verify_credential(self.c.token, require_proof=False).reason,
                         Reason.EXPIRED)

    def test_ttl_policy(self):
        for ttl in (0, 5, 99999, True, "60"):
            with self.assertRaises(ValidationError):
                self.svc.issue_credential(self.a["agent_id"], self.i["instance_id"], ttl_seconds=ttl)

    def test_09_revoked(self):
        self.assertTrue(self.verify().valid)
        self.svc.revoke_credential(self.c.credential_id, RevocationReason.COMPROMISE, "sec-admin",
                                   "key leaked")
        self.assertEqual(self.svc.verify_credential(self.c.token, require_proof=False).reason,
                         Reason.REVOKED)
        st = self.svc.get_credential_status(self.c.credential_id)
        self.assertEqual(st["status"], "revoked")
        self.assertEqual(st["revocation"]["revoked_by"], "sec-admin")
        self.assertEqual(st["revocation"]["reason"], "compromise")

    def test_invalid_revocation_reason(self):
        with self.assertRaises(ValidationError):
            self.svc.revoke_credential(self.c.credential_id, "because", "admin")

    def test_10_11_12_rotation(self):
        new = self.svc.rotate_credential(self.c.credential_id, grace_seconds=60)
        self.assertNotEqual(new.credential_id, self.c.credential_id)
        self.assertNotEqual(new.passport["key_fingerprint"], self.c.passport["key_fingerprint"])
        self.assertTrue(self.verify(new.token).valid)                      # new works
        self.assertTrue(self.verify(self.c.token).valid)                   # grace period
        self.assertEqual(self.svc.get_credential_status(self.c.credential_id)["status"],
                         "pending_revocation")
        self.clock.advance(61)
        r = self.svc.verify_credential(self.c.token, require_proof=False)
        self.assertEqual(r.reason, Reason.REVOKED)                         # old rejected
        self.assertEqual(self.svc.get_credential_status(self.c.credential_id)["status"], "revoked")
        self.assertTrue(self.verify(new.token).valid)

    def test_13_instances_distinct(self):
        i2 = self.svc.create_agent_instance(self.a["agent_id"])
        self.assertNotEqual(i2["instance_id"], self.i["instance_id"])
        self.assertNotEqual(i2["session_id"], self.i["session_id"])
        self.assertIn("-instance-", i2["instance_id"])
        c2 = self.svc.issue_credential(self.a["agent_id"], i2["instance_id"])
        self.assertTrue(self.verify(c2.token, expected_agent_id=self.a["agent_id"],
                                    expected_instance_id=i2["instance_id"]).valid)
        r = self.svc.verify_credential(c2.token, require_proof=False,
                                       expected_instance_id=self.i["instance_id"])
        self.assertEqual(r.reason, Reason.INSTANCE_MISMATCH)    # same agent, other instance

    def test_expected_agent_mismatch(self):
        b, _, _ = make_agent(self.svc, "other-agent")
        r = self.svc.verify_credential(self.c.token, require_proof=False,
                                       expected_agent_id=b["agent_id"])
        self.assertEqual(r.reason, Reason.AGENT_MISMATCH)

    def test_revoke_instance_and_agent(self):
        self.svc.revoke_instance(self.i["instance_id"], "agent_terminated", "admin")
        self.assertFalse(self.svc.verify_credential(self.c.token, require_proof=False).valid)
        a2, i2, c2 = make_agent(self.svc, "second")
        self.svc.revoke_agent(a2["agent_id"], RevocationReason.SECURITY_INCIDENT, "admin")
        self.assertEqual(self.svc.verify_credential(c2.token, require_proof=False).reason,
                         Reason.AGENT_NOT_ACTIVE)
        with self.assertRaises(UnauthorizedError):
            self.svc.create_agent_instance(a2["agent_id"])

    def test_credential_substitution(self):
        """Valid signature from the real issuer but registry has a different record."""
        b, ib, cb = make_agent(self.svc, "other-agent", caps=("tickets:read",))
        # attacker re-signs? impossible; but swapping tokens must not let A act as B
        r = self.svc.verify_credential(cb.token, require_proof=False,
                                       expected_agent_id=self.a["agent_id"])
        self.assertEqual(r.reason, Reason.AGENT_MISMATCH)
        # privilege confusion: registry capabilities changed after issuance -> mismatch
        from dataclasses import replace
        rec = self.svc.agents.get_agent(b["agent_id"])
        self.svc.agents.put_agent(replace(rec, capabilities=("admin:all",)))
        self.assertEqual(self.svc.verify_credential(cb.token, require_proof=False).reason,
                         Reason.REGISTRY_MISMATCH)


class Replay(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        _, _, self.c = make_agent(self.svc)

    def test_16_replay_detected(self):
        proof = self.svc.create_proof(self.c.token, "gw")
        self.assertTrue(self.svc.verify_credential(self.c.token, proof=proof, audience="gw").valid)
        r = self.svc.verify_credential(self.c.token, proof=proof, audience="gw")
        self.assertEqual(r.reason, Reason.REPLAY_DETECTED)

    def test_replay_same_request_id_new_nonce(self):
        p1 = self.svc.create_proof(self.c.token, "gw", request_id="req-123456")
        p2 = self.svc.create_proof(self.c.token, "gw", request_id="req-123456")
        self.assertTrue(self.svc.verify_credential(self.c.token, proof=p1, audience="gw").valid)
        self.assertEqual(self.svc.verify_credential(self.c.token, proof=p2, audience="gw").reason,
                         Reason.REPLAY_DETECTED)

    def test_proof_required_stale_audience_forged(self):
        self.assertEqual(self.svc.verify_credential(self.c.token).reason, Reason.PROOF_REQUIRED)
        p = self.svc.create_proof(self.c.token, "gw")
        self.clock.advance(120)
        c2 = self.svc.issue_credential(*self._ids(), ttl_seconds=300)
        self.assertEqual(self.svc.verify_credential(self.c.token, proof=p, audience="gw").reason,
                         Reason.PROOF_STALE)
        p = self.svc.create_proof(c2.token, "gw")
        self.assertEqual(self.svc.verify_credential(c2.token, proof=p, audience="other").reason,
                         Reason.AUDIENCE_MISMATCH)
        p = self.svc.create_proof(c2.token, "gw")
        p["nonce"] = p["nonce"] + "x"                      # tamper => signature fails
        self.assertEqual(self.svc.verify_credential(c2.token, proof=p, audience="gw").reason,
                         Reason.INVALID_PROOF)

    def _ids(self):
        rec = self.svc.credentials.get(self.c.credential_id)
        return rec.agent_id, rec.instance_id

    def test_stolen_token_without_key_useless(self):
        evil = AgentSideKey()
        p = evil.make_proof(self.c.credential_id, "gw", timestamp=int(self.clock.now()))
        self.assertEqual(self.svc.verify_credential(self.c.token, proof=p, audience="gw").reason,
                         Reason.INVALID_PROOF)

    def test_failed_verification_does_not_burn_nonce(self):
        p = self.svc.create_proof(self.c.token, "gw")
        self.assertEqual(self.svc.verify_credential(self.c.token, proof=p, audience="WRONG").reason,
                         Reason.AUDIENCE_MISMATCH)
        self.assertTrue(self.svc.verify_credential(self.c.token, proof=p, audience="gw").valid)


class AgentHeldKey(unittest.TestCase):
    def test_agent_held_key_flow(self):
        svc, clock = make_service()
        a = svc.register_agent("acme", "edge-agent", "edge", "o@x.com")
        i = svc.create_agent_instance(a["agent_id"])
        k = AgentSideKey()
        c = svc.issue_credential(a["agent_id"], i["instance_id"],
                                 **k.csr(a["agent_id"], i["instance_id"]))
        self.assertFalse(svc.keystore.has_key("x"))
        p = k.make_proof(c.credential_id, "gw", timestamp=int(clock.now()))
        self.assertTrue(svc.verify_credential(c.token, proof=p, audience="gw").valid)
        # CSR without possession of the key is rejected
        other = AgentSideKey()
        with self.assertRaises(ValidationError):
            svc.issue_credential(a["agent_id"], i["instance_id"], public_key=other.public_key,
                                 pop_signature=k.csr(a["agent_id"], i["instance_id"])["pop_signature"])


class Trust(unittest.TestCase):
    def test_17_unknown_issuer(self):
        svc, _ = make_service()
        _, _, c = make_agent(svc)
        other, _ = make_service()          # independent trust root
        r = other.verify_credential(c.token, require_proof=False)
        self.assertEqual(r.reason, Reason.UNKNOWN_ISSUER)

    def test_untrusted_chain(self):
        svc, _ = make_service()
        _, _, c = make_agent(svc)
        other, _ = make_service()
        # share cert but not the root => chain verification must fail
        cert = svc.trust.get_issuer_cert(json.loads(b64u_decode(c.token.split(".")[1]))["issuer_key_id"])
        other.trust.put_issuer_cert(cert)
        self.assertEqual(other.verify_credential(c.token, require_proof=False).reason,
                         Reason.UNTRUSTED_ISSUER_CHAIN)

    def test_issuer_rotation_overlap_and_retire(self):
        svc, clock = make_service()
        a, i, c_old = make_agent(svc)
        svc.rotate_issuer_key("acme", grace_seconds=100)
        c_new = svc.issue_credential(a["agent_id"], i["instance_id"])
        self.assertNotEqual(c_old.passport["issuer_key_id"], c_new.passport["issuer_key_id"])
        self.assertTrue(svc.verify_credential(c_old.token, require_proof=False).valid)
        self.assertTrue(svc.verify_credential(c_new.token, require_proof=False).valid)
        clock.advance(101)
        self.assertEqual(svc.verify_credential(c_old.token, require_proof=False).reason,
                         Reason.ISSUER_KEY_RETIRED)
        self.assertTrue(svc.verify_credential(c_new.token, require_proof=False).valid)

    def test_issuer_revocation(self):
        svc, _ = make_service()
        _, _, c = make_agent(svc)
        svc.revoke_issuer_key(c.passport["issuer_key_id"], "compromise", "sec")
        self.assertEqual(svc.verify_credential(c.token, require_proof=False).reason,
                         Reason.ISSUER_REVOKED)

    def test_agent_key_rotation(self):
        svc, clock = make_service()
        a, i, c = make_agent(svc)
        svc.rotate_agent_key(a["agent_id"], grace_seconds=50)
        self.assertTrue(svc.verify_credential(c.token, require_proof=False).valid)
        i2 = svc.create_agent_instance(a["agent_id"])          # bound to new key
        svc.issue_credential(a["agent_id"], i2["instance_id"])
        clock.advance(51)
        self.assertEqual(svc.verify_credential(c.token, require_proof=False).reason,
                         Reason.AGENT_KEY_RETIRED)
        with self.assertRaises(UnauthorizedError):
            svc.issue_credential(a["agent_id"], i["instance_id"])


class SubAgents(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()
        self.a, self.i, self.c = make_agent(self.svc)

    def spawn(self, token=None, **kw):
        token = token or self.c.token
        kw.setdefault("agent_name", "research-agent")
        kw.setdefault("agent_type", "research")
        kw.setdefault("capabilities", ["tickets:read"])
        return self.svc.spawn_sub_agent(token, self.svc.create_proof(token, SPAWN_AUDIENCE), **kw)

    def test_14_create_child(self):
        r = self.spawn()
        self.assertEqual(r.agent["parent_agent_id"], self.a["agent_id"])
        self.assertTrue(r.agent["is_sub_agent"])
        self.assertEqual(r.spawn["parent_agent_id"], self.a["agent_id"])
        v = self.svc.verify_credential(r.credential.token, require_proof=False)
        self.assertTrue(v.valid)
        self.assertTrue(v.is_sub_agent)
        self.assertEqual(v.parent_agent_id, self.a["agent_id"])
        self.assertIn(r.agent["agent_id"], self.svc.get_agent_identity(self.a["agent_id"])["children"])
        # grandchild chain: Parent -> Research -> Database
        child_caps = ["agent:spawn", "tickets:read"]
        r2 = self.spawn(agent_name="mid-agent", capabilities=child_caps)
        r3 = self.spawn(r2.credential.token, agent_name="db-agent", capabilities=["tickets:read"])
        self.assertEqual(len(r3.agent["lineage"]), 2)

    def test_15_unauthorized_child_identity(self):
        # no valid parent token
        with self.assertRaises(UnauthorizedError):
            self.svc.spawn_sub_agent("agp1.bad.token", {}, agent_name="x", agent_type="t")
        # valid token but no/replayed proof
        with self.assertRaises(UnauthorizedError):
            self.svc.spawn_sub_agent(self.c.token, None, agent_name="x", agent_type="t")
        p = self.svc.create_proof(self.c.token, SPAWN_AUDIENCE)
        self.svc.spawn_sub_agent(self.c.token, p, agent_name="x", agent_type="t",
                                 capabilities=["tickets:read"])
        with self.assertRaises(UnauthorizedError):
            self.svc.spawn_sub_agent(self.c.token, p, agent_name="y", agent_type="t")
        # proof for another audience cannot be used to spawn
        p2 = self.svc.create_proof(self.c.token, "gw")
        with self.assertRaises(UnauthorizedError):
            self.svc.spawn_sub_agent(self.c.token, p2, agent_name="z", agent_type="t")

    def test_capability_escalation_and_missing_spawn_cap(self):
        with self.assertRaises(UnauthorizedError):
            self.spawn(capabilities=["admin:all"])
        b, _, cb = make_agent(self.svc, "no-spawn", caps=("tickets:read",))
        with self.assertRaises(UnauthorizedError):
            self.spawn(cb.token)

    def test_depth_limit(self):
        svc, _ = make_service(max_sub_agent_depth=2)
        a, i, c = make_agent(svc)
        p = lambda t: svc.create_proof(t, SPAWN_AUDIENCE)
        r1 = svc.spawn_sub_agent(c.token, p(c.token), agent_name="l1", agent_type="t",
                                 capabilities=["agent:spawn"])
        with self.assertRaises(UnauthorizedError):
            svc.spawn_sub_agent(r1.credential.token, p(r1.credential.token), agent_name="l2",
                                agent_type="t", capabilities=["agent:spawn"])

    def test_parent_revocation_cascades(self):
        r = self.spawn()
        self.svc.revoke_agent(self.a["agent_id"], "compromise", "admin")
        self.assertEqual(self.svc.verify_credential(r.credential.token, require_proof=False).reason,
                         Reason.ANCESTOR_NOT_ACTIVE)

    def test_forged_lineage_claim(self):
        r = self.spawn()
        t = tamper_payload(r.credential.token, parent_agent_id="agt_other", lineage=["agt_other"])
        self.assertFalse(self.svc.verify_credential(t, require_proof=False).valid)


class Secrets(unittest.TestCase):
    def test_19_secrets_never_returned(self):
        svc, _ = make_service()
        a, i, c = make_agent(svc)
        blob = json.dumps([a, i, svc.get_agent_identity(a["agent_id"]),
                           svc.get_credential_status(c.credential_id),
                           svc.verify_credential(c.token, require_proof=False).to_dict(),
                           c.to_dict(include_token=False)])
        for bad in ("private", "secret", "seed", "master"):
            self.assertNotIn(bad, blob.lower())
        self.assertNotIn(c.token, blob)
        self.assertNotIn(c.token, repr(c))
        self.assertNotIn(c.token, str(c))
        for name in dir(svc.keystore):
            self.assertFalse(name.lower() in ("export_key", "get_private_key", "private_key"))
        self.assertNotIn("private", repr(svc.keystore).lower())

    def test_20_private_keys_never_in_logs(self):
        records = []

        class H(logging.Handler):
            def emit(self, r):
                records.append(r.getMessage())
        h = H()
        logging.getLogger("agentguard.identity.security").addHandler(h)
        logging.getLogger("agentguard.identity.security").setLevel(logging.DEBUG)
        try:
            svc = IdentityService(IdentityConfig(log_to_python_logging=True))
            svc.register_organization("acme", "Acme")
            a, i, c = make_agent(svc)
            p = svc.create_proof(c.token, "gw")
            svc.verify_credential(c.token, proof=p, audience="gw")
            svc.verify_credential(c.token, proof=p, audience="gw")
            svc.rotate_credential(c.credential_id)
            svc.revoke_credential(c.credential_id, "compromise", "admin")
        finally:
            logging.getLogger("agentguard.identity.security").removeHandler(h)
        text = "\n".join(records) + "\n".join(json.dumps(e) for e in svc.log.events)
        self.assertGreater(len(records), 5)
        self.assertNotIn(c.token, text)
        self.assertNotIn("agp1.", text)
        self.assertNotIn("BEGIN", text)
        self.assertNotIn(p["signature"], text)
        # extract every private key held in the keystore; none may appear in logs
        for blob in svc.keystore._keys.values():
            raw = svc.keystore._fernet.decrypt(blob)
            self.assertNotIn(b64u_encode(raw), text)
            self.assertNotIn(raw.hex(), text)

    def test_logger_allowlist_and_redaction(self):
        lg = SecurityLogger(use_python_logging=False)
        rec = lg.emit("x", agent_id="a", private_key="SUPERSECRET", token="agp1.zz.yy",
                      reason="agp1.zz.yy", detail="x\nforged log line")
        self.assertNotIn("private_key", rec)
        self.assertNotIn("token", rec)
        self.assertEqual(rec["reason"], "[REDACTED]")

    def test_keystore_encrypted_at_rest(self):
        svc, _ = make_service()
        a, _, _ = make_agent(svc)
        for blob in svc.keystore._keys.values():
            self.assertTrue(blob.startswith(b"gAAAA"))     # Fernet token, not raw key


if __name__ == "__main__":
    unittest.main()
