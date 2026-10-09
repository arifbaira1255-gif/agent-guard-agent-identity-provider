"""PostgreSQL configuration: secrets by reference (env / file), TLS enforced outside development."""
import os
from dataclasses import dataclass, field
from typing import Optional

from ...spiffe.config import ENV_VAR, Environment
from .errors import PgConfigError

_SSL_STRICT = ("verify-full", "verify-ca")
_SSL_ALL = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")


@dataclass
class PgConfig:
    environment: Environment = Environment.PRODUCTION          # strictest by default
    host: str = ""
    port: int = 5432
    dbname: str = ""
    user: str = ""
    password: str = field(default="", repr=False)
    password_file: str = ""                                    # e.g. a mounted Kubernetes secret
    sslmode: str = "verify-full"
    sslrootcert: str = ""
    sslcert: str = ""                                          # optional client cert (mTLS to PG)
    sslkey: str = ""
    pool_min_size: int = 2
    pool_max_size: int = 10
    pool_acquire_timeout_seconds: float = 5.0
    connect_timeout_seconds: int = 5
    statement_timeout_ms: int = 5000
    lock_timeout_ms: int = 2000
    idle_in_transaction_timeout_ms: int = 10000
    retry_max_attempts: int = 3
    retry_initial_backoff_seconds: float = 0.05
    retry_max_backoff_seconds: float = 1.0
    auto_migrate: bool = False                                 # production: run `migrate` as a separate step
    application_name: str = "agentguard-identity"

    def validate(self) -> "PgConfig":
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
        for n in ("host", "dbname", "user"):
            if not getattr(self, n):
                raise PgConfigError(f"{n} is required")
        if not (0 < self.port < 65536):
            raise PgConfigError("invalid port")
        if self.sslmode not in _SSL_ALL:
            raise PgConfigError("invalid sslmode")
        if not (1 <= self.pool_min_size <= self.pool_max_size <= 500):
            raise PgConfigError("require 1 <= pool_min_size <= pool_max_size <= 500")
        if min(self.pool_acquire_timeout_seconds, self.connect_timeout_seconds,
               self.statement_timeout_ms, self.lock_timeout_ms, self.idle_in_transaction_timeout_ms) <= 0:
            raise PgConfigError("timeouts must be > 0")
        if self.retry_max_attempts < 1 or self.retry_initial_backoff_seconds < 0:
            raise PgConfigError("invalid retry policy")
        proc = os.environ.get(ENV_VAR, "").strip().lower()
        if proc:
            try:
                penv = Environment(proc)
            except ValueError:
                raise PgConfigError(f"{ENV_VAR} must be development|staging|production")
            order = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
            if order.index(self.environment) < order.index(penv):
                raise PgConfigError(f"config environment is weaker than {ENV_VAR}={proc}")
        if self.environment != Environment.DEVELOPMENT:
            if self.sslmode not in _SSL_STRICT:
                raise PgConfigError("TLS with certificate verification (verify-full/verify-ca) is required "
                                    "outside development")
            if not self.sslrootcert:
                raise PgConfigError("sslrootcert is required outside development")
            if self.sslmode == "verify-ca" and self.environment == Environment.PRODUCTION:
                pass  # allowed, verify-full preferred (hostname check)
            if self.auto_migrate and self.environment == Environment.PRODUCTION:
                raise PgConfigError("auto_migrate is not allowed in production (run migrations as a deploy step)")
        return self

    def resolve_password(self) -> str:
        if self.password_file:
            with open(self.password_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        return self.password

    def connect_kwargs(self) -> dict:
        """Passed as kwargs (never as a DSN string), so the password cannot end up in a logged string."""
        kw = {"host": self.host, "port": self.port, "dbname": self.dbname, "user": self.user,
              "sslmode": self.sslmode, "connect_timeout": self.connect_timeout_seconds,
              "application_name": self.application_name,
              "options": (f"-c statement_timeout={int(self.statement_timeout_ms)} "
                          f"-c lock_timeout={int(self.lock_timeout_ms)} "
                          f"-c idle_in_transaction_session_timeout={int(self.idle_in_transaction_timeout_ms)}")}
        pw = self.resolve_password()
        if pw:
            kw["password"] = pw
        for k in ("sslrootcert", "sslcert", "sslkey"):
            if getattr(self, k):
                kw[k] = getattr(self, k)
        return kw

    def safe_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("password",)}
        d["environment"] = self.environment.value
        d["password_file"] = "<set>" if self.password_file else ""
        return d

    @classmethod
    def from_env(cls, env=None) -> "PgConfig":
        e = os.environ if env is None else env
        def g(k, d=""):
            return e.get("AGENTGUARD_PG_" + k, d)
        def gi(k, d):
            try:
                return int(g(k, str(d)))
            except ValueError:
                raise PgConfigError(f"AGENTGUARD_PG_{k} must be an integer")
        return cls(environment=(e.get(ENV_VAR) or "production").lower(), host=g("HOST"), port=gi("PORT", 5432),
                   dbname=g("DB"), user=g("USER"), password=g("PASSWORD"), password_file=g("PASSWORD_FILE"),
                   sslmode=g("SSLMODE", "verify-full"), sslrootcert=g("SSLROOTCERT"), sslcert=g("SSLCERT"),
                   sslkey=g("SSLKEY"), pool_min_size=gi("POOL_MIN", 2), pool_max_size=gi("POOL_MAX", 10),
                   statement_timeout_ms=gi("STATEMENT_TIMEOUT_MS", 5000),
                   connect_timeout_seconds=gi("CONNECT_TIMEOUT_S", 5),
                   auto_migrate=g("AUTO_MIGRATE", "0") == "1").validate()
