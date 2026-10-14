"""Measured PostgreSQL persistence latency. Needs a real DB:
  AGENTGUARD_TEST_PG_HOST=... AGENTGUARD_TEST_PG_USER=... AGENTGUARD_TEST_PG_PASSWORD=... \
  PYTHONPATH=src:. python3 benchmarks/bench_pg.py
Numbers depend entirely on your hardware/network/PG settings; run on the target environment."""
import concurrent.futures as cf
import os
import platform
import secrets
import statistics
import time
from dataclasses import replace

from cryptography.fernet import Fernet

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.models import RevocationReason, RevocationRecord, TargetType
from agent_identity.storage.postgres import build_postgres_storage, migrate
from agent_identity.storage.postgres.db import Database
from tests.test_pg_integration import PW, admin, pgcfg

name = "ag_bench_" + secrets.token_hex(4)
with admin() as a:
    a.execute(f'CREATE DATABASE "{name}"')
try:
    cfg = pgcfg(name, pool_max_size=16)
    d = Database(cfg); migrate.migrate(d); d.close()
    st = build_postgres_storage(cfg, Fernet.generate_key())
    svc = IdentityService(IdentityConfig(trust_domain="bench.example.net", log_to_python_logging=False),
                          **st.service_kwargs())
    svc.register_organization("acme", "Acme")
    ag = svc.register_agent("acme", "b", "t", "o@x.com", "", ["agent:spawn"], "production", {})
    inst = svc.create_agent_instance(ag["agent_id"])
    cred = svc.issue_credential(ag["agent_id"], inst["instance_id"])
    rec = st.agents.get_agent(ag["agent_id"])
    st.revocations.add(RevocationRecord(TargetType.AGENT, "other", RevocationReason.COMPROMISE, 1.0, "t", 1.0, None))

    def bench(label, fn, n):
        fn(); s = []
        for _ in range(n):
            t = time.perf_counter(); fn(); s.append((time.perf_counter() - t) * 1e3)
        s.sort()
        print(f"{label:34s} n={n:5d} mean={statistics.mean(s):7.3f}ms p50={s[n//2]:7.3f}ms p99={s[int(n*.99)-1]:7.3f}ms")

    print(f"python {platform.python_version()} {platform.machine()}  pool_max={cfg.pool_max_size}")
    bench("identity lookup (get_agent)", lambda: st.agents.get_agent(ag["agent_id"]), 500)
    bench("revocation lookup", lambda: st.revocations.get(TargetType.AGENT, "other"), 500)
    bench("identity update (status upsert)", lambda: st.agents.put_agent(replace(rec)), 300)
    bench("identity creation (register_agent)", lambda: svc.register_agent(
        "acme", "n" + secrets.token_hex(3), "t", "o@x.com", "", ["x:read"], "production", {}), 200)
    bench("verify_credential (full path)", lambda: svc.verify_credential(cred.token, require_proof=False), 300)
    for th in (1, 8, 16):
        n = 800; t = time.perf_counter()
        with cf.ThreadPoolExecutor(th) as ex:
            ok = sum(r.valid for r in ex.map(lambda _: svc.verify_credential(cred.token, require_proof=False), range(n)))
        dt = time.perf_counter() - t
        print(f"concurrent verify threads={th:2d} n={n} ok={ok} {n/dt:8.0f} ops/s")
    # slow-query hint: look at plans for the hot paths
    for q in ("SELECT * FROM agents WHERE agent_id='x'", "SELECT * FROM revocations WHERE target_type='agent' AND target_id='x'"):
        plan = st.db.run("explain", lambda c: c.execute("EXPLAIN " + q).fetchall())
        print("EXPLAIN:", plan[0]["QUERY PLAN"])
    st.close()
finally:
    with admin() as a:
        a.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
