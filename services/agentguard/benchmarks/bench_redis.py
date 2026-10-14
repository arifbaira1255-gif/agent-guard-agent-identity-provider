"""Measured Redis security-state performance (needs a real Redis):
  AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 [AGENTGUARD_TEST_REDIS_PASSWORD=...] PYTHONPATH=src:. python3 benchmarks/bench_redis.py
Latency/throughput depend on hardware, network distance and TLS; Python threads are GIL-bound. Run where you deploy."""
import concurrent.futures as cf
import platform
import statistics
import time

from agent_identity.state import BucketPolicy, KeyBuilder, build_security_state
from agent_identity.state.cache import VersionedCache
from tests.test_state_integration import HOST, new_prefix, rcfg

assert HOST, "set AGENTGUARD_TEST_REDIS_HOST"
st = build_security_state(rcfg(new_prefix(), pool_max_connections=64))
n_ = iter(range(10 ** 9))


def bench(label, fn, n):
    fn(); s = []
    for _ in range(n):
        t = time.perf_counter(); fn(); s.append((time.perf_counter() - t) * 1e3)
    s.sort()
    print(f"{label:30s} n={n:5d} mean={statistics.mean(s):7.3f}ms p50={s[n//2]:7.3f}ms p99={s[int(n*.99)-1]:7.3f}ms")


print(f"python {platform.python_version()} {platform.machine()} redis={rcfg('x').host}:{rcfg('x').port} tls={rcfg('x').tls}")
cache = VersionedCache(st.backend, st.keys, domain="idcache", ttl_seconds=30)
val = {"a": 1, "b": "x" * 200}
cache.get("agent", "hot", lambda: val, lambda v: v, lambda d: d)
pol = BucketPolicy("bench", rate_per_sec=1e6, burst=10 ** 6)
bench("replay check (new nonce)", lambda: st.replay.check_and_store(f"c:{next(n_)}", 30, 0), 1000)
bench("cache lookup (hit)", lambda: cache.get("agent", "hot", lambda: val, lambda v: v, lambda d: d), 1000)
bench("cache write (set)", lambda: st.backend.set(f"{st.keys.prefix}:bench:{next(n_)}", b"x" * 256, 30000), 1000)
bench("revocation lookup (hit)", lambda: cache.get("rev", "credential:c1", lambda: None, lambda v: v, lambda d: d), 1000)
bench("rate-limit (token bucket)", lambda: st.limiter.allow(pol, "acme", "agent", "a1"), 1000)
def lock():
    h = st.locks.acquire("acme", f"b{next(n_)}", ttl_seconds=5); h.release()
bench("lock acquire+release", lock, 500)
for th in (1, 8, 32):
    n = 4000; t = time.perf_counter()
    with cf.ThreadPoolExecutor(th) as ex:
        list(ex.map(lambda _: st.replay.check_and_store(f"cc:{next(n_)}", 30, 0), range(n)))
    dt = time.perf_counter() - t
    print(f"concurrent replay threads={th:2d} n={n} {n/dt:8.0f} ops/s  pool={st.backend.pool_stats()}")
st.close()
