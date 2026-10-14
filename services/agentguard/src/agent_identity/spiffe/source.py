"""Auto-rotating SVID sources. Rotation happens BEFORE expiry; while a refresh is failing the
still-valid SVID keeps being served (no needless outage); once expired, current() raises (DENY)."""
import threading
from typing import Dict, Optional, Tuple

from . import metrics as M
from .errors import R, SvidError
from .jwtsvid import JwtSvid
from .x509svid import X509Svid


def needs_rotation(not_before: float, not_after: float, now: float, cfg) -> bool:
    remaining = not_after - now
    return remaining <= max(cfg.rotation_min_remaining_seconds,
                            cfg.rotation_threshold_fraction * (not_after - not_before))


class X509Source:
    def __init__(self, client, spiffe_id: Optional[str], config, clock, metrics: M.Metrics, logger=None):
        self._c, self._id, self._cfg, self._clock, self._m, self._log = \
            client, spiffe_id, config, clock, metrics, logger
        self._svid: Optional[X509Svid] = None
        self._lock = threading.Lock()          # guards state
        self._refresh_lock = threading.Lock()  # single-flight refresh
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def refresh(self, *, only_if_needed: bool = False) -> X509Svid:
        with self._refresh_lock:
            if only_if_needed:      # single-flight: a concurrent caller may already have rotated
                with self._lock:
                    cur = self._svid
                if cur is not None and not needs_rotation(cur.not_before, cur.not_after,
                                                          self._clock.now(), self._cfg):
                    return cur
            new = self._c.fetch_x509_svid(self._id)
            with self._lock:
                old = self._svid
                if old is None or old.leaf.serial_number != new.leaf.serial_number:
                    self._svid = new
                    if old is not None:
                        self._m.inc(M.ROTATIONS, "x509")
                        if self._log:
                            self._log.emit("svid.rotate", result="ok")
            return new

    def current(self) -> X509Svid:
        now = self._clock.now()
        with self._lock:
            svid = self._svid
        if svid is None:
            return self.refresh()
        if needs_rotation(svid.not_before, svid.not_after, now, self._cfg):
            try:
                svid = self.refresh(only_if_needed=True)
            except Exception:
                self._m.inc(M.REFRESH_FAIL, "x509")
                if self._clock.now() >= svid.not_after:
                    self._m.inc(M.EXPIRED, "x509")
                    raise SvidError("SVID expired and refresh failed", R.EXPIRED)
        if self._clock.now() >= svid.not_after:
            self._m.inc(M.EXPIRED, "x509")
            raise SvidError("SVID expired", R.EXPIRED)
        return svid

    def start(self):
        def loop():
            while not self._stop.wait(self._cfg.refresh_interval_seconds):
                try:
                    self.current()
                except Exception:
                    pass
        self._thread = threading.Thread(target=loop, name="x509-source", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()


class JwtSource:
    def __init__(self, client, config, clock, metrics: M.Metrics):
        self._c, self._cfg, self._clock, self._m = client, config, clock, metrics
        self._cache: Dict[Tuple[str, str], Tuple[JwtSvid, float]] = {}
        self._lock = threading.Lock()

    def get(self, audience: str, spiffe_id: str) -> JwtSvid:
        key, now = (audience, spiffe_id), self._clock.now()
        with self._lock:
            hit = self._cache.get(key)
        if hit and not needs_rotation(hit[1], hit[0].expiry, now, self._cfg):
            return hit[0]
        tok = self._c.fetch_jwt_svid([audience], spiffe_id)
        with self._lock:
            if hit:
                self._m.inc(M.ROTATIONS, "jwt")
            self._cache[key] = (tok, now)
        return tok
