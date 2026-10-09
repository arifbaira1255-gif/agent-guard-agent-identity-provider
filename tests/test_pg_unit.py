"""PostgreSQL layer unit tests (no database needed): config, error mapping, retry/fail-closed,
migration files, SQL-injection safety by construction, durable-store guards."""
import ast
import contextlib
import os
import unittest
from pathlib import Path
from unittest import mock

from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.errors import ConflictError, StorageError
from agent_identity.spiffe.config import Environment
from agent_identity.storage.postgres import (PgConfig, PgConfigError, SchemaMismatchError,
                                              StorageUnavailableError, require_durable_or_raise)
from agent_identity.storage.postgres import db as pgdb
from agent_identity.storage.postgres import errors as pgerr
from agent_identity.storage.postgres import migrate
from agent_identity.storage.postgres.db import Database

PGDIR = Path(__file__).resolve().parent.parent / "src/agent_identity/storage/postgres"
SECRET = "S3cr3t-Passw0rd-XYZ"


def cfg(**kw):
    d = dict(environment="development", host="db", dbname="ag", user="app", password=SECRET,
             sslmode="disable", retry_initial_backoff_seconds=0.0)
    d.update(kw)
    return PgConfig(**d).validate()


class FakeErr(Exception):
    def __init__(self, sqlstate=None, msg="boom"):
        super().__init__(msg)
        self.sqlstate = sqlstate


class OperationalError(Exception):          # same class NAME as psycopg's => treated as connection failure
    pass


class FakeConn:
    def __init__(self, log, script=None):
        self.log, self.script = log, script or {}

    @contextlib.contextmanager
    def transaction(self):
        self.log.append("begin")
        try:
            yield
        except BaseException:
            self.log.append("rollback")
            raise
        else:
            self.log.append("commit")

    def execute(self, sql, params=None):
        for k, v in self.script.items():
            if k in sql:
                return v
        return FakeCursor(None)


class FakeCursor:
    def __init__(self, row, rows=None):
        self.row, self.rows = row, rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakePool:
    def __init__(self, script=None):
        self.log, self.script, self.closed = [], script, False

    @contextlib.contextmanager
    def connection(self):
        yield FakeConn(self.log, self.script)

    def close(self):
        self.closed = True


class Config(unittest.TestCase):
    def test_production_requires_verified_tls_and_root_cert(self):
        for kw in (dict(sslmode="require", sslrootcert="/ca.pem"), dict(sslmode="disable"),
                   dict(sslmode="verify-full", sslrootcert="")):
            with self.assertRaises(PgConfigError):
                cfg(environment="production", **kw)
        self.assertEqual(cfg(environment="production", sslmode="verify-full",
                             sslrootcert="/ca.pem").environment, Environment.PRODUCTION)

    def test_production_forbids_auto_migrate(self):
        with self.assertRaises(PgConfigError):
            cfg(environment="production", sslmode="verify-full", sslrootcert="/ca.pem", auto_migrate=True)

    def test_process_env_can_only_tighten(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(PgConfigError):
                cfg()                      # development config under a production process

    def test_bounds_and_required(self):
        for kw in (dict(host=""), dict(pool_min_size=5, pool_max_size=2), dict(port=0),
                   dict(statement_timeout_ms=0), dict(sslmode="bogus"), dict(retry_max_attempts=0)):
            with self.assertRaises(PgConfigError):
                cfg(**kw)

    def test_password_never_in_repr_or_safe_dict(self):
        c = cfg()
        self.assertNotIn(SECRET, repr(c))
        self.assertNotIn(SECRET, str(c.safe_dict()))
        self.assertIn(SECRET, str(c.connect_kwargs()))      # passed to the driver only, as a kwarg

    def test_password_file_and_from_env(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(SECRET + "\n")
        try:
            c = cfg(password="", password_file=f.name)
            self.assertEqual(c.resolve_password(), SECRET)
            self.assertNotIn(f.name, str(c.safe_dict()))
        finally:
            os.unlink(f.name)
        env = {"AGENTGUARD_ENV": "development", "AGENTGUARD_PG_HOST": "h", "AGENTGUARD_PG_DB": "d",
               "AGENTGUARD_PG_USER": "u", "AGENTGUARD_PG_SSLMODE": "disable"}
        self.assertEqual(PgConfig.from_env(env).host, "h")
        with self.assertRaises(PgConfigError):
            PgConfig.from_env({**env, "AGENTGUARD_PG_PORT": "abc"})


class ErrorMapping(unittest.TestCase):
    def test_mapping_and_no_driver_text(self):
        m = pgerr.map_error(FakeErr("23505", f"duplicate key ... password={SECRET}"))
        self.assertIsInstance(m, ConflictError)
        self.assertNotIn(SECRET, str(m))
        for st in ("40001", "40P01", "57014", "08006", "53300"):
            self.assertIsInstance(pgerr.map_error(FakeErr(st)), StorageUnavailableError)
        self.assertIsInstance(pgerr.map_error(OperationalError("conn")), StorageUnavailableError)
        other = pgerr.map_error(FakeErr("42P01", f"relation x {SECRET}"))
        self.assertEqual(type(other), StorageError)
        self.assertNotIn(SECRET, str(other))
        self.assertIsInstance(pgerr.map_error(FakeErr("23514")), ConflictError)     # trigger violations


class DbBehaviour(unittest.TestCase):
    def mk(self, pool=None, **kw):
        return Database(cfg(**kw), pool=pool or FakePool(), sleep=lambda s: None)

    def test_commit_and_metrics(self):
        db = self.mk()
        self.assertEqual(db.run("x", lambda c: 7), 7)
        self.assertEqual(db._pool.log, ["begin", "commit"])
        self.assertEqual(db.metrics.get(pgdb.OPS, "x"), 1)

    def test_rollback_on_error_and_conflict_not_retried(self):
        db = self.mk()
        n = []

        def fn(c):
            n.append(1)
            raise FakeErr("23505")
        with self.assertRaises(ConflictError):
            db.run("x", fn)
        self.assertEqual(len(n), 1)
        self.assertEqual(db._pool.log, ["begin", "rollback"])

    def test_transient_retried_then_succeeds(self):
        db = self.mk()
        calls = []

        def fn(c):
            calls.append(1)
            if len(calls) < 3:
                raise FakeErr("40001")
            return "ok"
        self.assertEqual(db.run("x", fn), "ok")
        self.assertEqual(db.metrics.get(pgdb.RETRIES, "x"), 2)

    def test_transient_exhausted_fails_closed_with_safe_message(self):
        db = self.mk()

        def fn(c):
            raise OperationalError(f"could not connect password={SECRET}")
        with self.assertRaises(StorageUnavailableError) as cm:
            db.run("x", fn)
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertEqual(db.metrics.get(pgdb.RETRIES, "x"), 2)

    def test_logs_do_not_leak_driver_text(self):
        db = self.mk()
        with self.assertLogs("agentguard.postgres", level="WARNING") as lg:
            with self.assertRaises(StorageError):
                db.run("x", lambda c: (_ for _ in ()).throw(FakeErr("42P01", f"leak {SECRET}")))
        self.assertNotIn(SECRET, "\n".join(lg.output))

    def test_closed_db_denies(self):
        db = self.mk()
        db.close()
        db.close()                                           # idempotent
        self.assertTrue(db._pool.closed)
        with self.assertRaises(StorageUnavailableError):
            db.run("x", lambda c: 1)
        self.assertFalse(db.liveness())

    def test_readiness_requires_matching_schema(self):
        ok = FakePool({"to_regclass": FakeCursor({"t": "schema_migrations"})})
        db = self.mk(ok)
        self.assertTrue(db.health())
        # schema table missing => not ready
        missing = Database(cfg(), pool=FakePool({"to_regclass": FakeCursor({"t": None})}),
                           sleep=lambda s: None)
        r = missing.readiness()
        self.assertTrue(r["db"] and not r["schema"] and not r["ready"])
        with self.assertRaises(SchemaMismatchError):
            migrate.verify_schema(missing)
        # DB newer than code => not ready
        mig = migrate.load_migrations()[0]
        ahead = Database(cfg(), pool=FakePool({
            "to_regclass": FakeCursor({"t": "x"}),
            "FROM schema_migrations": FakeCursor(None, [
                {"version": 1, "name": mig.name, "checksum": mig.checksum},
                {"version": 2, "name": "future", "checksum": "00"}])}), sleep=lambda s: None)
        with self.assertRaises(SchemaMismatchError):
            migrate.verify_schema(ahead)
        # tampered checksum => not ready
        bad = Database(cfg(), pool=FakePool({
            "to_regclass": FakeCursor({"t": "x"}),
            "FROM schema_migrations": FakeCursor(None, [{"version": 1, "name": mig.name, "checksum": "bad"}])}),
            sleep=lambda s: None)
        with self.assertRaises(SchemaMismatchError):
            migrate.verify_schema(bad)
        good = Database(cfg(), pool=FakePool({
            "to_regclass": FakeCursor({"t": "x"}),
            "FROM schema_migrations": FakeCursor(None, [{"version": 1, "name": mig.name,
                                                         "checksum": mig.checksum}])}), sleep=lambda s: None)
        self.assertEqual(migrate.verify_schema(good), 1)
        self.assertTrue(good.readiness()["ready"])


class MigrationFiles(unittest.TestCase):
    def test_contiguous_checksummed_deterministic(self):
        a, b = migrate.load_migrations(), migrate.load_migrations()
        self.assertEqual([m.checksum for m in a], [m.checksum for m in b])
        self.assertEqual([m.version for m in a], list(range(1, len(a) + 1)))
        self.assertEqual(migrate.expected_version(), len(a))

    def test_bad_names_and_gaps_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "0002_x.sql").write_text("select 1")
            with self.assertRaises(StorageError):
                migrate.load_migrations(Path(d))
            Path(d, "bad.sql").write_text("select 1")
            with self.assertRaises(StorageError):
                migrate.load_migrations(Path(d))

    def test_schema_has_no_plaintext_private_key_columns(self):
        sql = migrate.load_migrations()[0].sql.lower()
        self.assertIn("encrypted_private", sql)
        for bad in ("private_key", "secret", "password"):
            self.assertNotIn(bad, sql)


class SqlSafety(unittest.TestCase):
    """Injection safety by construction: every execute() gets a CONSTANT string + bound params."""

    def _scan(self, path):
        tree = ast.parse(path.read_text())
        found = 0
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "execute":
                found += 1
                a = n.args[0]
                if path.name == "migrate.py" and (isinstance(a, ast.Attribute) and a.attr == "sql"
                                                  or isinstance(a, ast.Name) and a.id == "_CREATE"):
                    continue          # migration scripts come from checksummed files, never from input
                self.assertIsInstance(a, ast.Constant, f"{path.name}:{n.lineno} SQL must be a constant string")
                self.assertIsInstance(a.value, str)
        return found

    def test_all_sql_is_constant(self):
        total = sum(self._scan(PGDIR / f) for f in ("repos.py", "migrate.py", "db.py"))
        self.assertGreater(total, 30)

    def test_no_string_formatting_near_sql(self):
        src = (PGDIR / "repos.py").read_text()
        for bad in ("f\"SELECT", "f\"INSERT", "f\"UPDATE", ".format(", "% (", "%s\" %", "' + "):
            self.assertNotIn(bad, src)


class DurableGuards(unittest.TestCase):
    def test_memory_stores_rejected_in_production_and_staging(self):
        for env in ("production", "staging"):
            with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": env}):
                with self.assertRaises(StorageError):
                    IdentityService(IdentityConfig(trust_domain="x.example.net", log_to_python_logging=False))

    def test_memory_allowed_in_development(self):
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "development"}):
            IdentityService(IdentityConfig(trust_domain="x.example.net", log_to_python_logging=False))
        require_durable_or_raise()

    def test_memory_bindings_rejected_in_production(self):
        from agent_identity.spiffe.bindings import MemoryBindingRegistry
        with mock.patch.dict(os.environ, {"AGENTGUARD_ENV": "production"}):
            with self.assertRaises(StorageError):
                require_durable_or_raise(bindings=MemoryBindingRegistry())


class FailClosedVerification(unittest.TestCase):
    def test_storage_outage_denies_credential_verification(self):
        from tests.helpers import make_agent, make_service
        svc, _ = make_service()
        a, i, c = make_agent(svc)
        self.assertTrue(svc.verify_credential(c.token, require_proof=False).valid)

        def down(*args, **kw):
            raise StorageUnavailableError("database temporarily unavailable")
        for attr in ("get_agent", "get_instance", "get_org"):
            setattr(svc.agents, attr, down)
        r = svc.verify_credential(c.token, require_proof=False)
        self.assertFalse(r.valid)                       # never "valid" when state cannot be read

    def test_revocation_store_outage_denies(self):
        from tests.helpers import make_agent, make_service
        svc, _ = make_service()
        a, i, c = make_agent(svc)

        def down(*args, **kw):
            raise StorageUnavailableError("database temporarily unavailable")
        svc.revocations.get = down
        self.assertFalse(svc.verify_credential(c.token, require_proof=False).valid)


if __name__ == "__main__":
    unittest.main()
