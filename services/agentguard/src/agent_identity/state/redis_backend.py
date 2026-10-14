"""Production Redis backend (redis-py >= 5). Atomic operations are Lua scripts / single atomic commands.
Errors are mapped to StateUnavailableError WITHOUT driver text. Retries only connection/timeout errors."""
import logging
import random
import time
from typing import Optional, Tuple

from ..spiffe import metrics as _M
from .backend import StateBackend, _ttl, _val
from .config import RedisConfig
from .errors import StateConfigError, StateCorruptError, StateUnavailableError

log = logging.getLogger("agentguard.redis")

CMDS = "agentguard_redis_commands_total"
ERRORS = "agentguard_redis_errors_total"
LATENCY = "agentguard_redis_command_latency_seconds"
RETRIES = "agentguard_redis_retries_total"
RECONNECTS = "agentguard_redis_reconnects_total"

_CAD = "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end"
_CAE = ("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) "
        "else return 0 end")
_CAS = ("if redis.call('GET',KEYS[1])==ARGV[1] then redis.call('SET',KEYS[1],ARGV[2],'KEEPTTL') "
        "return 1 else return 0 end")
_BUCKET = """
local t=redis.call('TIME'); local now=t[1]*1000+math.floor(t[2]/1000)
local rate=tonumber(ARGV[1]); local burst=tonumber(ARGV[2]); local cost=tonumber(ARGV[3])
local b=redis.call('HMGET',KEYS[1],'tokens','ts')
local tokens=tonumber(b[1]); local ts=tonumber(b[2])
if tokens==nil or ts==nil then tokens=burst; ts=now end
tokens=math.min(burst, tokens+math.max(0,now-ts)*rate/1000)
local allowed=0; local retry=0
if tokens>=cost then tokens=tokens-cost; allowed=1 else retry=math.ceil((cost-tokens)*1000/rate) end
redis.call('HSET',KEYS[1],'tokens',tostring(tokens),'ts',now)
redis.call('PEXPIRE',KEYS[1],math.ceil(burst/rate*1000)+1000)
return {allowed, math.floor(tokens), retry}
"""
_REPLAY = """
if redis.call('EXISTS',KEYS[2])==0 then
  redis.call('SET',KEYS[2],'1','PX',ARGV[2])
  redis.call('SET',KEYS[3],'1','PX',ARGV[1])
end
if redis.call('EXISTS',KEYS[3])==1 then return 2 end
if redis.call('SET',KEYS[1],'1','NX','PX',ARGV[1]) then return 1 else return 0 end
"""
_WINDOW = """
local c=redis.call('INCR',KEYS[1])
if c==1 or redis.call('PTTL',KEYS[1])<0 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end
return c
"""


class RedisBackend(StateBackend):
    def __init__(self, config: RedisConfig, *, client=None, metrics: Optional[_M.Metrics] = None,
                 sleep=time.sleep):
        self.cfg = config.validate()
        self.metrics = metrics or _M.Metrics()
        self._sleep = sleep
        self._closed = False
        self._r = client if client is not None else self._connect()
        self._scripts = {}
        for name, lua in (("cad", _CAD), ("cae", _CAE), ("cas", _CAS), ("bucket", _BUCKET), ("window", _WINDOW), ("replay", _REPLAY)):
            self._scripts[name] = self._r.register_script(lua)

    # ------------------------------------------------------------ connection
    def _connect(self):
        try:
            import redis
        except ImportError:
            raise StateUnavailableError("redis-py not installed (pip install 'agentguard-agent-identity[redis]')")
        c = self.cfg
        common = dict(username=c.username or None, password=c.resolve_password() or None,
                      socket_timeout=c.command_timeout_seconds,
                      socket_connect_timeout=c.connect_timeout_seconds,
                      health_check_interval=c.health_check_interval_seconds, decode_responses=False)
        # TLS: redis-py >= 6 removed the `ssl=True` kwarg; TLS is selected by using SSLConnection
        # as the connection class. Passing `ssl=True` raises TypeError on modern redis-py, which
        # would make every Redis operation fail closed -- so we select the class explicitly.
        connection_class = None
        if c.tls:
            connection_class = redis.SSLConnection
            common.update(ssl_cert_reqs="required", ssl_check_hostname=c.tls_check_hostname,
                          ssl_ca_certs=c.tls_ca_cert or None, ssl_certfile=c.tls_client_cert or None,
                          ssl_keyfile=c.tls_client_key or None)
        try:
            if c.mode == "cluster":
                from redis.cluster import RedisCluster
                return RedisCluster(host=c.host, port=c.port, max_connections=c.pool_max_connections, **common)
            if c.mode == "sentinel":
                from redis.sentinel import Sentinel
                s = Sentinel(list(c.sentinel_hosts), sentinel_kwargs=dict(common), db=c.db,
                             max_connections=c.pool_max_connections, **common)
                return s.master_for(c.sentinel_master)
            pool_kwargs = dict(host=c.host, port=c.port, db=c.db,
                               max_connections=c.pool_max_connections,
                               timeout=c.pool_wait_seconds, **common)
            if connection_class is not None:
                pool_kwargs["connection_class"] = connection_class
            pool = redis.BlockingConnectionPool(**pool_kwargs)
            return redis.Redis(connection_pool=pool)
        except Exception as e:
            log.error("redis client init failed (type=%s)", type(e).__name__)
            raise StateUnavailableError("state store unavailable")

    # ------------------------------------------------------------ call wrapper
    def _call(self, op: str, fn):
        if self._closed:
            raise StateUnavailableError("state store is shut down")
        delay = self.cfg.retry_base_backoff_seconds
        for attempt in range(self.cfg.retry_attempts):
            t0 = time.perf_counter()
            try:
                out = fn()
                self.metrics.inc(CMDS, op)
                self.metrics.observe(LATENCY, time.perf_counter() - t0)
                return out
            except Exception as e:
                kind = self._kind(e)
                self.metrics.inc(ERRORS, kind)
                log.warning("redis op=%s failed kind=%s type=%s attempt=%d", op, kind, type(e).__name__, attempt + 1)
                if kind in ("connection", "timeout") and attempt + 1 < self.cfg.retry_attempts:
                    self.metrics.inc(RETRIES, op)
                    if kind == "connection":
                        self.metrics.inc(RECONNECTS)
                    self._sleep(min(delay, self.cfg.retry_max_backoff_seconds) * (0.5 + random.random() / 2))
                    delay *= 2
                    continue
                if kind == "response":
                    raise StateCorruptError("state store rejected the command") from None
                raise StateUnavailableError("state store unavailable") from None

    @staticmethod
    def _kind(e) -> str:
        names = {c.__name__ for c in type(e).__mro__}
        if names & {"AuthenticationError", "AuthenticationWrongNumberOfArgsError"}:
            return "auth"
        if names & {"TimeoutError"}:
            return "timeout"
        if names & {"ConnectionError", "BusyLoadingError", "ClusterDownError", "MasterNotFoundError"}:
            return "connection"
        if names & {"ReadOnlyError"}:
            return "readonly"             # talking to a replica after failover: do not trust, do not retry blindly
        if names & {"ResponseError"}:
            return "response"
        return "other"

    # ------------------------------------------------------------ operations
    def set_if_absent(self, key, value, ttl_ms):
        t, v = _ttl(ttl_ms), _val(value)
        return bool(self._call("set_nx", lambda: self._r.set(key, v, nx=True, px=t)))

    def set(self, key, value, ttl_ms):
        t, v = _ttl(ttl_ms), _val(value)
        self._call("set", lambda: self._r.set(key, v, px=t))

    def get(self, key):
        return self._call("get", lambda: self._r.get(key))

    def delete(self, key):
        return bool(self._call("del", lambda: self._r.delete(key)))

    def compare_and_delete(self, key, expected):
        v = _val(expected)
        return bool(self._call("cad", lambda: self._scripts["cad"](keys=[key], args=[v])))

    def compare_and_extend(self, key, expected, ttl_ms):
        t, v = _ttl(ttl_ms), _val(expected)
        return bool(self._call("cae", lambda: self._scripts["cae"](keys=[key], args=[v, t])))

    def compare_and_set(self, key, expected, new):
        e, n = _val(expected), _val(new)
        return bool(self._call("cas", lambda: self._scripts["cas"](keys=[key], args=[e, n])))

    def token_bucket(self, key, rate_per_sec, burst, cost=1):
        if rate_per_sec <= 0 or burst < 1 or cost < 1:
            raise StateConfigError("invalid token bucket parameters")
        r = self._call("bucket", lambda: self._scripts["bucket"](keys=[key], args=[rate_per_sec, burst, cost]))
        try:
            return bool(int(r[0])), int(r[1]), int(r[2])
        except Exception:
            raise StateCorruptError("unexpected rate-limit script result") from None

    def window_incr(self, key, window_ms):
        w = _ttl(window_ms)
        return int(self._call("window", lambda: self._scripts["window"](keys=[key], args=[w])))

    def replay_check(self, key, marker_key, quarantine_key, ttl_ms, marker_ttl_ms):
        t, mt = _ttl(ttl_ms), _ttl(marker_ttl_ms)
        r = self._call("replay", lambda: self._scripts["replay"](keys=[key, marker_key, quarantine_key],
                                                                 args=[t, mt]))
        if int(r) not in (0, 1, 2):
            raise StateCorruptError("unexpected replay script result")
        return int(r)

    def ping(self):
        try:
            return bool(self._call("ping", lambda: self._r.ping()))
        except StateUnavailableError:
            return False

    def pool_stats(self) -> dict:
        """Best-effort connection utilisation (reads redis-py pool internals if present)."""
        pool = getattr(self._r, "connection_pool", None)
        if pool is None:
            return {}
        return {"max": getattr(pool, "max_connections", None),
                "created": getattr(pool, "_created_connections", None),
                "in_use": len(getattr(pool, "_in_use_connections", ()) or ())}

    def close(self):
        self._closed = True
        try:
            self._r.close()
        except Exception:
            pass
