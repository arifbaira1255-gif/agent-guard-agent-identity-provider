"""Measured SPIFFE adapter performance (dev Workload API, real wire format + real crypto).
Run:  PYTHONPATH=src:. python3 benchmarks/bench_spiffe.py
NOTE: retrieval numbers use the in-process dev transport: they exclude real UDS/gRPC latency."""
import concurrent.futures as cf
import platform
import statistics
import time

from tests.spiffe_env import Env
from agent_identity.spiffe.x509svid import verify_x509_svid


def bench(name, fn, n):
    fn()
    s = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        s.append((time.perf_counter() - t) * 1e6)
    s.sort()
    print(f"{name:40s} n={n:6d} mean={statistics.mean(s):9.1f}us p50={s[n//2]:9.1f}us "
          f"p99={s[int(n*.99)-1]:9.1f}us ~{1e6/statistics.mean(s):8.0f} ops/s")


e = Env()
chain = e.p.client.fetch_x509_svid(e.sid_inst).chain_der()
tok = e.jwt()
now = e.clock.now()
cfg = e.cfg

print(f"python {platform.python_version()} on {platform.machine()} / {platform.system()} (dev transport)")
bench("X.509-SVID fetch (client.fetch)", lambda: e.p.client.fetch_x509_svid(e.sid_inst), 500)
bench("JWT-SVID fetch (client.fetch)", lambda: e.p.client.fetch_jwt_svid(["gateway"], e.sid_inst), 500)
bench("issue() (cached X509 source)", lambda: e.p.issue(e.a_id, e.i_id), 2000)
bench("X.509 chain validation (raw)", lambda: verify_x509_svid(chain, e.p.bundles, now, max_depth=5,
                                                              skew_seconds=30), 2000)
bench("verify_x509 (chain + registry authz)", lambda: e.p.verify_x509(chain), 2000)
bench("verify JWT-SVID (full, no replay)", lambda: e.p.verify(tok, audience="gateway"), 2000)
bench("credential refresh (bundles x509+jwt)", e.p.refresh_bundles, 500)


def rotate():
    e.clock.advance(100000)          # force expiry => source must rotate
    e.p.x509_source(e.sid_inst).current()


bench("forced X.509 rotation", rotate, 300)

e2 = Env()
chain2 = e2.p.client.fetch_x509_svid(e2.sid_inst).chain_der()
for threads in (1, 4, 16):
    n = 4000
    t = time.perf_counter()
    with cf.ThreadPoolExecutor(threads) as ex:
        ok = sum(r.valid for r in ex.map(lambda _: e2.p.verify_x509(chain2), range(n)))
    dt = time.perf_counter() - t
    assert ok == n
    print(f"concurrent verify_x509 threads={threads:2d}   n={n} total={dt:.3f}s ~{n/dt:8.0f} ops/s (GIL-bound)")
