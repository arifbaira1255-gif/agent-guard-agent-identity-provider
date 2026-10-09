"""Versioned, checksummed, forward-only migrations. Safe for CI/CD: serialized by an advisory lock,
each migration runs in one transaction, applied checksums are re-verified on every run."""
import hashlib
import re
from pathlib import Path
from typing import List, NamedTuple, Optional

from .errors import MigrationError, SchemaMismatchError, StorageError

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
_LOCK_KEY = 7_424_001           # arbitrary constant: pg_advisory_xact_lock(key)


class Migration(NamedTuple):
    version: int
    name: str
    sql: str
    checksum: str


def load_migrations(directory: Path = MIGRATIONS_DIR) -> List[Migration]:
    out, seen = [], set()
    for p in sorted(directory.glob("*.sql")):
        m = _NAME.match(p.name)
        if not m:
            raise MigrationError(f"bad migration file name: {p.name}")
        v = int(m.group(1))
        if v in seen:
            raise MigrationError(f"duplicate migration version {v}")
        seen.add(v)
        sql = p.read_text(encoding="utf-8")
        out.append(Migration(v, m.group(2), sql, hashlib.sha256(sql.encode()).hexdigest()))
    if [m.version for m in out] != list(range(1, len(out) + 1)):
        raise MigrationError("migration versions must be contiguous from 1")
    return out


def expected_version() -> int:
    return load_migrations()[-1].version


_CREATE = """CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"""


def _applied(conn) -> dict:
    return {r["version"]: r for r in conn.execute(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version").fetchall()}


def migrate(db, directory: Path = MIGRATIONS_DIR) -> List[int]:
    """Apply pending migrations. Returns versions applied. Raises MigrationError on drift/failure."""
    migs = load_migrations(directory)
    applied_now: List[int] = []

    def go(conn):
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
        conn.execute(_CREATE)
        done = _applied(conn)
        known = {m.version: m for m in migs}
        for v, row in done.items():
            if v not in known:
                raise MigrationError(f"database has migration {v} unknown to this code (newer/incompatible)")
            if row["checksum"] != known[v].checksum:
                raise MigrationError(f"migration {v} checksum drift (file modified after being applied)")
        for m in migs:
            if m.version in done:
                continue
            conn.execute(m.sql)                                   # no params: multi-statement script
            conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                         (m.version, m.name, m.checksum))
            applied_now.append(m.version)
    try:
        db.run("migrate", go, retry=False)          # whole run atomic: all pending or none
    except MigrationError:
        raise
    except StorageError as e:
        raise MigrationError(f"migration failed: {type(e).__name__}") from None
    return applied_now


def current_version(db) -> Optional[int]:
    def q(conn):
        t = conn.execute("SELECT to_regclass('schema_migrations') AS t").fetchone()["t"]
        if t is None:
            return None
        r = conn.execute("SELECT max(version) AS v FROM schema_migrations").fetchone()
        return r["v"]
    return db.run("schema_version", q, retry=False)


def verify_schema(db, expected: Optional[int] = None) -> int:
    """Refuse to operate on a missing/behind/ahead/tampered schema."""
    migs = load_migrations()
    exp = expected if expected is not None else migs[-1].version

    def q(conn):
        if conn.execute("SELECT to_regclass('schema_migrations') AS t").fetchone()["t"] is None:
            raise SchemaMismatchError("schema not initialised (run migrations)")
        return _applied(conn)
    done = db.run("schema_verify", q, retry=False)
    if max(done, default=0) != exp:
        raise SchemaMismatchError("schema version does not match this build")
    by_v = {m.version: m for m in migs}
    for v, row in done.items():
        if v not in by_v or row["checksum"] != by_v[v].checksum:
            raise SchemaMismatchError("schema migration history does not match this build")
    return exp
