"""Step 9 cross-language conformance test (Python side).

Loads the shared fixture and asserts that the Python SDK's canonical JSON + Ed25519 implementation
reproduces the EXACT bytes and signature, and that the fixture verifies with the CORE AgentGuard
verifier. The Node test asserts the same from the JavaScript side.
"""
import json
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_identity.crypto import keys
from agent_identity.crypto.encoding import b64u_decode, b64u_encode

from agentguard_sdk.crypto_compat import canonical_json, proof_bytes, csr_bytes

_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "sdks", "conformance", "vectors.json")


class ConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_FIXTURE, encoding="utf-8") as fh:
            cls.v = json.load(fh)

    def test_canonical_proof_bytes_match_fixture(self):
        expected = b64u_decode(self.v["proof"]["canonical_bytes_b64u"])
        self.assertEqual(proof_bytes(self.v["proof"]["object"]), expected)

    def test_canonical_csr_bytes_match_fixture(self):
        expected = b64u_decode(self.v["csr"]["canonical_bytes_b64u"])
        self.assertEqual(csr_bytes(self.v["csr"]["agent_id"], self.v["csr"]["instance_id"],
                                   self.v["csr"]["public_key"]), expected)

    def test_python_reproduces_the_signature_exactly(self):
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.v["key"]["seed_hex"]))
        sig = priv.sign(keys.DOMAIN_PROOF + proof_bytes(self.v["proof"]["object"]))
        self.assertEqual(b64u_encode(sig), self.v["proof"]["signature_b64u"])

    def test_fixture_verifies_with_the_core_verifier(self):
        proof = self.v["proof"]["object"]
        self.assertTrue(keys.verify(self.v["key"]["public_key_b64u"], keys.DOMAIN_PROOF,
                                    keys.proof_bytes(proof), b64u_decode(proof["signature"])))

    def test_csr_fixture_verifies_with_the_core_verifier(self):
        csr = self.v["csr"]
        self.assertTrue(keys.verify(csr["public_key"], keys.DOMAIN_CSR,
                                    keys.csr_bytes(csr["agent_id"], csr["instance_id"],
                                                   csr["public_key"]),
                                    b64u_decode(csr["signature_b64u"])))

    def test_tampered_proof_does_not_verify(self):
        proof = dict(self.v["proof"]["object"])
        proof["audience"] = "attacker"
        self.assertFalse(keys.verify(self.v["key"]["public_key_b64u"], keys.DOMAIN_PROOF,
                                     keys.proof_bytes(proof), b64u_decode(proof["signature"])))

    def test_canonical_json_is_ascii_and_sorted(self):
        self.assertEqual(canonical_json({"b": 1, "a": "x"}), b'{"a":"x","b":1}')


if __name__ == "__main__":
    unittest.main()
