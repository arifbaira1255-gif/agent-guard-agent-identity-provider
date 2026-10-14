"""Step 7 performance & capacity benchmark (real PostgreSQL + Redis).

Reports REAL measured numbers: throughput (ops/sec), latency percentiles (p50/p90/p99), and the
test conditions. It invents nothing.

Usage:
  AGENTGUARD_TEST_PG_HOST=127.0.0.1 AGENTGUARD_TEST_PG_USER=agentguard \
  AGENTGUARD_TEST_PG_PASSWORD=devpass AGENTGUARD_TEST_REDIS_HOST=127.0.0.1 \
  AGENTGUARD_TEST_REDIS_PASSWORD=devredispass \
  PYTHONPATH=src:. python3 scripts/benchmark_step7.py
"""
import os
import secrets
import statistics
import sys
import time

from cryptography.fernet import Fernet

from agent_identity import IdentityConfig, IdentityService
from agent_identity.storage.postgres import PgConfig, build_postgres_storage, migrate
from agent_identity.storage.postgres.db import Database
from agent_identity.state import RedisConfig, build_security_state

TD = "bench.agentguard.example.net"
PG_HOST = os.environ["AGENTGUARD_TEST_PG_HOST"]
PG_PORT = int(os.environ.get("AGENTGUARD_TEST_PG_PORT", "5432"))
PG_USER = os.environ["AGENTGUARD_TEST_PG_USER"]
PG_PW = os.environ["AGENTGUARD_TEST_PG_PASSWORD"]
REDIS_HOST = os.environ["AGENTGUARD_TEST_REDIS_HOST"]
REDIS_PORT = int(os.environ.get("AGENTGUARD_TEST_REDIS_PORT", "6379"))
REDIS_PW = os.environ.get("AGENTGUARD_TEST_REDIS_PASSWORD", "")


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def bench(name, fn, n):
    lat = []
    t0 = time.perf_counter()
    for _ in range(n):
        s = time.perf_counter()
        fn()
        lat.append(time.perf_counter() - s)
    wall = time.perf_counter() - t0
    return {"op": name, "n": n, "wall_s": round(wall, 3),
            "ops_per_s": round(n / wall, 1),
            "p50_ms": round(pct(lat, 0.50) * 1000, 2),
            "p90_ms": round(pct(lat, 0.90) * 1000, 2),
            "p99_ms": round(pct(lat, 0.99) * 1000, 2),
            "mean_ms": round(statistics.mean(lat) * 1000, 2)}


def main():
    import psycopg
    dbname = "ag_bench_" + secrets.token_hex(6)
    with psycopg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PW,
                         dbname="postgres", autocommit=True) as a:
        a.execute(f'CREATE DATABASE "{dbname}"')
    master = Fernet.generate_key()
    os.environ["AGENT_IDENTITY_MASTER_KEY"] = master.decode()
    cfg = PgConfig(environment="development", host=PG_HOST, port=PG_PORT, dbname=dbname,
                   user=PG_USER, password=PG_PW, sslmode="disable", pool_min_size=4,
                   pool_max_size=32).validate()
    db = Database(cfg)
    migrate.migrate(db)
    db.close()
    pg = build_postgres_storage(cfg, master)
    rcfg = RedisConfig(environment="development", host=REDIS_HOST, port=REDIS_PORT,
                       password=REDIS_PW, tls=False, key_prefix="bench" + secrets.token_hex(4),
                       retry_base_backoff_seconds=0.01).validate()
    state = build_security_state(rcfg)

    svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                          **pg.service_kwargs())
    svc.register_organization("bench", "Bench")
    # one agent/instance with an issued credential to exercise lookup + revocation checks
    a = svc.register_agent("bench", "worker", "service", "bench@example.com", "bench",
                           ["bench:run"], "production", {})
    inst = svc.create_agent_instance(a["agent_id"])
    cred = svc.issue_credential(a["agent_id"], inst["instance_id"])
    aid = a["agent_id"]

    results = []
    results.append(bench("identity_lookup_get_agent_identity", lambda: svc.get_agent_identity(aid), 2000))
    results.append(bench("identity_creation_register_agent",
                         lambda: svc.register_agent("bench", "w", "service", "b@e.com", "b",
                                                    ["bench:run"], "production", {}), 500))
    results.append(bench("credential_issuance_issue_credential",
                         lambda: svc.issue_credential(aid, inst["instance_id"]), 500))
    results.append(bench("revocation_check_verify_credential",
                         lambda: svc.verify_credential(cred.token, require_proof=False), 2000))
    # concurrent lookups across 8 threads
    import concurrent.futures as cf
    def cgo(_):
        svc.get_agent_identity(aid)
    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(cgo, range(4000)))
    wall = time.perf_counter() - t0
    results.append({"op": "concurrent_lookup_8_threads", "n": 4000, "wall_s": round(wall, 3),
                    "ops_per_s": round(4000 / wall, 1),
                    "p50_ms": None, "p90_ms": None, "p99_ms": None, "mean_ms": None})

    print("=== Step 7 benchmark (real PostgreSQL + Redis) ===")
    print(f"conditions: PG={PG_HOST}:{PG_PORT} Redis={REDIS_HOST}:{REDIS_PORT} "
          f"pool_max=32, Redis key-prefix isolated, 1 instance, single process")
    for r in results:
        lat = "" if r["p50_ms"] is None else \
            f"p50={r['p50_ms']}ms p90={r['p90_ms']}ms p99={r['p99_ms']}ms mean={r['mean_ms']}ms"
        print(f"  {r['op']:<42} n={r['n']:<6} wall={r['wall_s']}s "
              f"{r['ops_per_s']:>8} ops/s  {lat}")
    print("=== done ===")

    state.close()
    pg.close()
    with psycopg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PW,
                         dbname="postgres", autocommit=True) as a:
        a.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')


if __name__ == "__main__":
    main()
