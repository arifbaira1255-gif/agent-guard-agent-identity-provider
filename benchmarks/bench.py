"""Measured (not claimed) performance.  PYTHONPATH=src python3 benchmarks/bench.py"""
import platform
import statistics
import time

from agent_identity import AgentSideKey, IdentityConfig, IdentityService
from agent_identity.core.models import RevocationReason, TargetType
from agent_identity.crypto import keys
from agent_identity.crypto.encoding import b64u_encode


def bench(name, fn, n):
    fn()
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1e6)
    samples.sort()
    print(f"{name:34s} n={n:6d}  mean={statistics.mean(samples):8.1f}us  "
          f"p50={samples[n//2]:8.1f}us  p99={samples[int(n*.99)-1]:8.1f}us  "
          f"~{1e6/statistics.mean(samples):9.0f} ops/s")


svc = IdentityService(IdentityConfig(log_to_python_logging=False, replay_cache_max_entries=5_000_000))
svc.register_organization("acme", "Acme")
a = svc.register_agent("acme", "bench-agent", "t", "o@x.com", capabilities=["x:read"])
inst = svc.create_agent_instance(a["agent_id"])
key = AgentSideKey()
cred = svc.issue_credential(a["agent_id"], inst["instance_id"], **key.csr(a["agent_id"], inst["instance_id"]))
priv = keys.generate_private_key()
pub = b64u_encode(keys.public_bytes(priv))
sig = keys.sign(priv, keys.DOMAIN_PASSPORT, b"x" * 512)
cnt = [0]

def reg():
    svc.register_agent("acme", "bench-agent", "t", "o@x.com", capabilities=["x:read"])

def issue():
    svc.issue_credential(a["agent_id"], inst["instance_id"], **key.csr(a["agent_id"], inst["instance_id"]))

def verify_no_proof():
    assert svc.verify_credential(cred.token, require_proof=False).valid

def verify_proof():
    p = key.make_proof(cred.credential_id, "gw")
    assert svc.verify_credential(cred.token, proof=p, audience="gw").valid

proofs = [key.make_proof(cred.credential_id, "gw") for _ in range(3002)]
it = iter(proofs)

def verify_only_proof():       # excludes client-side proof signing
    assert svc.verify_credential(cred.token, proof=next(it), audience="gw").valid

rev_id = svc.issue_credential(a["agent_id"], inst["instance_id"]).credential_id
svc.revoke_credential(rev_id, RevocationReason.COMPROMISE, "bench")

print(f"python {platform.python_version()} on {platform.machine()} / {platform.system()} (single thread, in-memory stores)")
bench("raw Ed25519 signature verify", lambda: keys.verify(pub, keys.DOMAIN_PASSPORT, b"x" * 512, sig), 5000)
bench("agent registration", reg, 1000)
bench("credential issuance (agent-held)", issue, 1000)
bench("verify (no proof)", verify_no_proof, 3000)
bench("verify (server-side only, w/ proof)", verify_only_proof, 3000)
bench("revocation lookup (revoked id)", lambda: svc.revocations.is_revoked(TargetType.CREDENTIAL, rev_id, time.time()), 20000)
