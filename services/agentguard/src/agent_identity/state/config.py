"""Redis configuration: environment-driven, secrets by reference, TLS + auth enforced outside development."""
import os
from dataclasses import dataclass, field
from typing import Tuple
from urllib.parse import urlsplit

from ..spiffe.config import ENV_VAR, Environment
from .errors import StateConfigError

_ORDER = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]


@dataclass
class RedisConfig:
    environment: Environment = Environment.PRODUCTION
    mode: str = "standalone"                       # standalone | sentinel | cluster
    host: str = ""
    port: int = 6379
    db: int = 0
    username: str = ""
    password: str = field(default="", repr=False)
    password_file: str = ""
    tls: bool = True
    tls_ca_cert: str = ""
    tls_client_cert: str = ""
    tls_client_key: str = ""
    tls_check_hostname: bool = True
    sentinel_hosts: Tuple[Tuple[str, int], ...] = ()
    sentinel_master: str = ""
    connect_timeout_seconds: float = 2.0
    command_timeout_seconds: float = 0.5
    pool_max_connections: int = 50
    pool_wait_seconds: float = 2.0
    retry_attempts: int = 3
    retry_base_backoff_seconds: float = 0.02
    retry_max_backoff_seconds: float = 0.5
    health_check_interval_seconds: int = 15
    key_prefix: str = "agentguard"
    # TTL policy (seconds). Every security-state record has an explicit, bounded TTL.
    replay_max_ttl_seconds: int = 86400
    cache_ttl_agent_seconds: int = 30
    cache_ttl_revocation_seconds: int = 10
    temp_state_max_ttl_seconds: int = 86400
    lock_default_ttl_seconds: int = 30

    def validate(self) -> "RedisConfig":
        if isinstance(self.environment, str):
            self.environment = Environment(self.environment)
        if self.mode not in ("standalone", "sentinel", "cluster"):
            raise StateConfigError("mode must be standalone|sentinel|cluster")
        if self.mode == "sentinel":
            if not self.sentinel_hosts or not self.sentinel_master:
                raise StateConfigError("sentinel mode needs sentinel_hosts and sentinel_master")
        elif not self.host:
            raise StateConfigError("host is required")
        if not (0 < self.port < 65536) or not (0 <= self.db < 1024):
            raise StateConfigError("invalid port/db")
        if min(self.connect_timeout_seconds, self.command_timeout_seconds, self.pool_wait_seconds) <= 0:
            raise StateConfigError("timeouts must be > 0")
        if not (1 <= self.pool_max_connections <= 10_000) or self.retry_attempts < 1:
            raise StateConfigError("invalid pool/retry settings")
        for n in ("replay_max_ttl_seconds", "cache_ttl_agent_seconds", "cache_ttl_revocation_seconds",
                  "temp_state_max_ttl_seconds", "lock_default_ttl_seconds"):
            v = getattr(self, n)
            if not (1 <= v <= 7 * 86400):
                raise StateConfigError(f"{n} must be within 1s..7d")
        proc = os.environ.get(ENV_VAR, "").strip().lower()
        if proc:
            try:
                penv = Environment(proc)
            except ValueError:
                raise StateConfigError(f"{ENV_VAR} must be development|staging|production")
            if _ORDER.index(self.environment) < _ORDER.index(penv):
                raise StateConfigError(f"config environment is weaker than {ENV_VAR}={proc}")
        if self.environment != Environment.DEVELOPMENT:
            if not self.tls or not self.tls_check_hostname:
                raise StateConfigError("TLS with hostname verification is required outside development")
            if not (self.password or self.password_file):
                raise StateConfigError("Redis authentication (password) is required outside development")
            if self.tls_client_cert and not self.tls_client_key:
                raise StateConfigError("tls_client_key required with tls_client_cert")
        return self

    def resolve_password(self) -> str:
        if self.password_file:
            with open(self.password_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        return self.password

    def safe_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "password"}
        d["environment"] = self.environment.value
        d["password_file"] = "<set>" if self.password_file else ""
        return d

    @classmethod
    def from_env(cls, env=None) -> "RedisConfig":
        e = os.environ if env is None else env
        g = lambda k, d="": e.get("AGENTGUARD_REDIS_" + k, d)

        def num(k, d, t=int):
            try:
                return t(g(k, str(d)))
            except ValueError:
                raise StateConfigError(f"AGENTGUARD_REDIS_{k} must be a number")
        host, port, db, tls = g("HOST"), num("PORT", 6379), num("DB", 0), g("TLS", "1") == "1"
        url = g("URL")
        if url:                                    # convenience, but NEVER with embedded credentials
            u = urlsplit(url)
            if u.username or u.password:
                raise StateConfigError("credentials in AGENTGUARD_REDIS_URL are not allowed; "
                                       "use AGENTGUARD_REDIS_USERNAME / _PASSWORD / _PASSWORD_FILE")
            if u.scheme not in ("redis", "rediss"):
                raise StateConfigError("URL scheme must be redis:// or rediss://")
            host, port = u.hostname or host, u.port or port
            tls = u.scheme == "rediss"
            if u.path.strip("/").isdigit():
                db = int(u.path.strip("/"))
        sent = tuple((h.rsplit(":", 1)[0], int(h.rsplit(":", 1)[1])) for h in g("SENTINELS").split(",") if h)
        return cls(environment=(e.get(ENV_VAR) or "production").lower(), mode=g("MODE", "standalone"), host=host,
                   port=port, db=db, username=g("USERNAME"), password=g("PASSWORD"),
                   password_file=g("PASSWORD_FILE"), tls=tls, tls_ca_cert=g("TLS_CA_CERT"),
                   tls_client_cert=g("TLS_CLIENT_CERT"), tls_client_key=g("TLS_CLIENT_KEY"),
                   tls_check_hostname=g("TLS_CHECK_HOSTNAME", "1") == "1", sentinel_hosts=sent,
                   sentinel_master=g("SENTINEL_MASTER"), pool_max_connections=num("POOL_MAX", 50),
                   command_timeout_seconds=num("COMMAND_TIMEOUT_S", 0.5, float),
                   connect_timeout_seconds=num("CONNECT_TIMEOUT_S", 2.0, float),
                   key_prefix=g("KEY_PREFIX", "agentguard")).validate()
