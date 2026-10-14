"""Connection pool + transactions + bounded retry + health. Fail closed: no fallback store, ever."""
import contextlib
import logging
import random
import threading
import time
from typing import Callable, Optional

from ...spiffe import metrics as _M
from .config import PgConfig
from .errors import (SchemaMismatchError, StorageUnavailableError, is_transient, map_error, sqlstate_of)

log = logging.getLogger("agentguard.postgres")

OPS = "agentguard_pg_operations_total"
OP_FAIL = "agentguard_pg_operation_failures_total"
LATENCY = "agentguard_pg_query_latency_seconds"
RETRIES = "agentguard_pg_retries_total"
CONN_FAIL = "agentguard_pg_connection_failures_total"
TX_FAIL = "agentguard_pg_transaction_failures_total"
POOL_SIZE = "agentguard_pg_pool_size"


class Database:
    """`run(op, fn)` executes fn(conn) in ONE transaction (commit on success, rollback on error).
    All repository writes are idempotent upserts, so transient failures are retried safely."""

    def __init__(self, config: PgConfig, *, pool=None, metrics: Optional[_M.Metrics] = None,
                 sleep=time.sleep):
        self.cfg = config.validate()
        self.metrics = metrics or _M.Metrics()
        self._sleep = sleep
        self._closed = False
        self._lock = threading.Lock()
        self._pool = pool if pool is not None else self._open_pool()
        # Step 8: per-thread tenant context. When set, every operation on this thread runs with the
        # transaction-local GUC `app.current_org`, which the Row-Level Security policies enforce
        # (defence in depth next to the application-level tenant checks).
        self._tenant_ctx = threading.local()

    # ------------------------------------------------------------- Step 8 tenant context
    def current_tenant(self) -> Optional[str]:
        return getattr(self._tenant_ctx, "org", None)

    @contextlib.contextmanager
    def tenant_scope(self, org_id: Optional[str], *, user_id: Optional[str] = None,
                     platform_admin: bool = False):
        """Bind subsequent operations performed on THIS thread to a tenant and/or user.

        ``user_id`` enables the "my own rows" RLS allowance (login-time tenant resolution, listing
        and revoking one's own sessions). ``platform_admin=True`` is a deliberate, auditable
        escalation used only for legitimate cross-tenant platform operations; it is set by the
        platform-admin code path, never derived from tenant input. The GUCs are applied inside each
        operation's own transaction (see ``run``), so they can never bleed across pooled connections
        or between requests.
        """
        previous = (getattr(self._tenant_ctx, "org", None), getattr(self._tenant_ctx, "user", None),
                    getattr(self._tenant_ctx, "platform", False))
        self._tenant_ctx.org = org_id
        self._tenant_ctx.user = user_id
        self._tenant_ctx.platform = bool(platform_admin)
        try:
            yield
        finally:
            (self._tenant_ctx.org, self._tenant_ctx.user,
             self._tenant_ctx.platform) = previous

    def _bind_tenant(self, conn) -> None:                      # called inside the tx, before fn()
        org = getattr(self._tenant_ctx, "org", None)
        user = getattr(self._tenant_ctx, "user", None)
        platform = getattr(self._tenant_ctx, "platform", False)
        if org is not None:
            conn.execute("SELECT set_config('app.current_org', %s, true)", (org,))
        if user is not None:
            conn.execute("SELECT set_config('app.current_user', %s, true)", (user,))
        if platform:
            conn.execute("SELECT set_config('app.platform_admin', 'on', true)")

    def _open_pool(self):
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError:
            raise StorageUnavailableError("psycopg/psycopg_pool not installed "
                                          "(pip install 'agentguard-agent-identity[postgres]')")
        c = self.cfg
        pool = ConnectionPool(conninfo="", kwargs={**c.connect_kwargs(), "row_factory": dict_row},
                              min_size=c.pool_min_size, max_size=c.pool_max_size,
                              timeout=c.pool_acquire_timeout_seconds, open=False,
                              check=ConnectionPool.check_connection, name="agentguard")
        try:
            pool.open(wait=True, timeout=c.pool_acquire_timeout_seconds + c.connect_timeout_seconds)
        except Exception as e:
            self.metrics.inc(CONN_FAIL)
            log.error("postgres pool failed to open (sqlstate=%s, type=%s)", sqlstate_of(e), type(e).__name__)
            raise StorageUnavailableError("database temporarily unavailable")
        return pool

    def run(self, op: str, fn: Callable, *, retry: bool = True):
        if self._closed:
            raise StorageUnavailableError("database is shut down")
        attempts = self.cfg.retry_max_attempts if retry else 1
        delay = self.cfg.retry_initial_backoff_seconds
        last = None
        for i in range(attempts):
            t0 = time.perf_counter()
            try:
                with self._pool.connection() as conn:
                    with conn.transaction():
                        self._bind_tenant(conn)
                        out = fn(conn)
                self.metrics.inc(OPS, op)
                self.metrics.observe(LATENCY, time.perf_counter() - t0)
                return out
            except Exception as e:
                mapped = map_error(e)
                transient = is_transient(e)
                self.metrics.inc(OP_FAIL, type(mapped).__name__)
                if sqlstate_of(e) in ("40001", "40P01"):
                    self.metrics.inc(TX_FAIL, sqlstate_of(e))
                if transient and not sqlstate_of(e):
                    self.metrics.inc(CONN_FAIL)
                log.warning("db op=%s failed sqlstate=%s type=%s attempt=%d", op, sqlstate_of(e),
                            type(e).__name__, i + 1)               # never the driver message
                last = mapped
                if transient and retry and i + 1 < attempts:
                    self.metrics.inc(RETRIES, op)
                    self._sleep(min(delay, self.cfg.retry_max_backoff_seconds) * (0.5 + random.random() / 2))
                    delay *= 2
                    continue
                raise mapped from None
        raise last  # pragma: no cover

    # ------------------------------------------------------------ health
    def liveness(self) -> bool:
        return not self._closed

    def health(self) -> bool:
        try:
            self.run("health", lambda c: c.execute("SELECT 1").fetchone(), retry=False)
            return True
        except Exception:
            return False

    def readiness(self, expected_version: Optional[int] = None) -> dict:
        """Ready only if the DB answers AND the schema matches this code (fail closed otherwise)."""
        from . import migrate
        out = {"live": self.liveness(), "db": False, "schema": False}
        try:
            out["db"] = self.health()
            if out["db"]:
                migrate.verify_schema(self, expected_version)
                out["schema"] = True
        except (SchemaMismatchError, StorageUnavailableError):
            pass
        out["ready"] = out["live"] and out["db"] and out["schema"]
        return out

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._pool.close()
        except Exception:
            pass
