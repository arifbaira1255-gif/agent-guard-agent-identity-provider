"""Idempotency for identity registration and credential issuance (Step 7).

Guarantees
----------
* **Explicit scope.** A key is scoped by ``(scope, operation, idem_key)`` where ``scope`` is the
  tenant (organization id) or ``_system`` for control-plane operations. The same key under a
  different tenant is a different record — a tenant can never collide with, or read, another
  tenant's idempotency state.
* **Atomic reservation.** The first caller INSERTs the record (``in_progress``); every concurrent
  caller sees it and does NOT re-execute the security-critical transition. Exactly one instance
  performs the work.
* **Bounded retention.** Every record carries ``expires_at``; a coordination job purges expired
  rows. Nothing lives forever.
* **Safe duplicate handling + conflict detection.** A replay is only served when the request
  digest AND the actor match the original. A different body or a different principal for the same
  key is a hard ``ConflictError`` — never a silent success.
* **No credential leakage.** The stored response is Fernet-encrypted at rest and is only returned
  to the SAME actor that created it. An unauthorized caller presenting a matching key gets a
  conflict, never the credential.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ..core.errors import ConflictError, StorageError

SYSTEM_SCOPE = "_system"
NEW = "new"
REPLAY = "replay"
IN_PROGRESS = "in_progress"
CONFLICT = "conflict"


def request_digest(body: dict) -> str:
    """Stable digest of a request body (sorted keys, no whitespace)."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


@dataclass(frozen=True)
class Reservation:
    outcome: str                       # new | replay | in_progress | conflict
    result_ref: Optional[str] = None
    response: Optional[bytes] = None   # decrypted stored response (replay only)


class IdempotencyStore(ABC):
    @abstractmethod
    def reserve(self, scope: str, operation: str, idem_key: str, *, digest: str, actor: str,
                owner_instance: str, ttl_seconds: float, now: float) -> Reservation: ...

    @abstractmethod
    def complete(self, scope: str, operation: str, idem_key: str, *, result_ref: str,
                 response: bytes, now: float) -> None: ...

    @abstractmethod
    def fail(self, scope: str, operation: str, idem_key: str, *, now: float) -> None: ...

    @abstractmethod
    def takeover_stale(self, scope: str, operation: str, idem_key: str, *, digest: str, actor: str,
                       owner_instance: str, stale_before: float, now: float) -> bool:
        """Atomically take over an ``in_progress`` reservation whose owner died (its ``updated_at``
        is older than ``stale_before``). Returns True only for the single winner. Never touches a
        ``completed`` record."""

    @abstractmethod
    def purge_expired(self, now: float) -> int: ...


def _validate(scope: str, operation: str, idem_key: str) -> None:
    for name, v, n in (("scope", scope, 128), ("operation", operation, 64), ("idem_key", idem_key, 256)):
        if not isinstance(v, str) or not v or len(v) > n:
            raise StorageError(f"invalid idempotency {name}")


class _Cipher:
    """Fernet encryption of stored responses. The master key never touches the store."""

    def __init__(self, master_keys):
        if isinstance(master_keys, (bytes, str)):
            master_keys = [master_keys]
        if not master_keys:
            raise StorageError("an idempotency master key is required")
        try:
            self._f = MultiFernet([Fernet(k) for k in master_keys])
        except Exception:
            raise StorageError("invalid idempotency master key") from None

    def enc(self, data: bytes) -> bytes:
        return self._f.encrypt(data)

    def dec(self, blob: bytes) -> bytes:
        try:
            return self._f.decrypt(blob)
        except InvalidToken:
            raise StorageError("stored idempotency response cannot be decrypted") from None


class MemoryIdempotencyStore(IdempotencyStore):
    """Thread-safe in-process implementation (tests / single-process development)."""

    def __init__(self, master_keys):
        self._c = _Cipher(master_keys)
        self._l = threading.Lock()
        self._d = {}

    def _live(self, k, now):
        e = self._d.get(k)
        if e is None:
            return None
        if e["expires_at"] <= now:
            del self._d[k]
            return None
        return e

    def reserve(self, scope, operation, idem_key, *, digest, actor, owner_instance, ttl_seconds, now):
        _validate(scope, operation, idem_key)
        if ttl_seconds <= 0:
            raise StorageError("idempotency ttl must be positive")
        k = (scope, operation, idem_key)
        with self._l:
            e = self._live(k, now)
            if e is None:
                self._d[k] = {"digest": digest, "actor": actor, "status": "in_progress",
                              "result_ref": None, "response": None, "owner": owner_instance,
                              "updated_at": now, "expires_at": now + ttl_seconds}
                return Reservation(NEW)
            if e["digest"] != digest or e["actor"] != actor:
                return Reservation(CONFLICT)
            if e["status"] == "completed":
                return Reservation(REPLAY, e["result_ref"], self._c.dec(e["response"]))
            return Reservation(IN_PROGRESS)

    def complete(self, scope, operation, idem_key, *, result_ref, response, now):
        k = (scope, operation, idem_key)
        with self._l:
            e = self._live(k, now)
            if e is None:
                raise StorageError("idempotency record vanished before completion")
            e["status"] = "completed"
            e["result_ref"] = result_ref
            e["response"] = self._c.enc(response)

    def fail(self, scope, operation, idem_key, *, now):
        k = (scope, operation, idem_key)
        with self._l:
            e = self._live(k, now)
            if e is not None and e["status"] == "in_progress":
                del self._d[k]          # a failed attempt frees the key for a safe retry

    def takeover_stale(self, scope, operation, idem_key, *, digest, actor, owner_instance,
                       stale_before, now):
        k = (scope, operation, idem_key)
        with self._l:
            e = self._live(k, now)
            if e is None or e["status"] != "in_progress":
                return False
            if e["digest"] != digest or e["actor"] != actor:
                return False
            if e["updated_at"] > stale_before:
                return False
            e["owner"] = owner_instance
            e["updated_at"] = now
            return True

    def purge_expired(self, now):
        with self._l:
            dead = [k for k, e in self._d.items() if e["expires_at"] <= now]
            for k in dead:
                del self._d[k]
            return len(dead)


class PgIdempotencyStore(IdempotencyStore):
    """PostgreSQL-backed store: the reservation is a single atomic INSERT ... ON CONFLICT."""

    def __init__(self, db, master_keys):
        self.db = db
        self._c = _Cipher(master_keys)

    def reserve(self, scope, operation, idem_key, *, digest, actor, owner_instance, ttl_seconds, now):
        _validate(scope, operation, idem_key)
        if ttl_seconds <= 0:
            raise StorageError("idempotency ttl must be positive")

        def go(c):
            cur = c.execute(
                "INSERT INTO idempotency_records (scope, operation, idem_key, request_digest, actor,"
                " status, owner_instance, created_at, updated_at, expires_at)"
                " VALUES (%s,%s,%s,%s,%s,'in_progress',%s,%s,%s,%s)"
                " ON CONFLICT (scope, operation, idem_key) DO NOTHING",
                (scope, operation, idem_key, digest, actor, owner_instance, now, now, now + ttl_seconds))
            if cur.rowcount == 1:
                return None
            return c.execute(
                "SELECT request_digest, actor, status, result_ref, response_enc FROM idempotency_records"
                " WHERE scope=%s AND operation=%s AND idem_key=%s",
                (scope, operation, idem_key)).fetchone()
        row = self.db.run("idem_reserve", go)
        if row is None:
            return Reservation(NEW)
        if row["request_digest"] != digest or row["actor"] != actor:
            return Reservation(CONFLICT)
        if row["status"] == "completed":
            return Reservation(REPLAY, row["result_ref"], self._c.dec(bytes(row["response_enc"])))
        return Reservation(IN_PROGRESS)

    def complete(self, scope, operation, idem_key, *, result_ref, response, now):
        blob = self._c.enc(response)

        def go(c):
            cur = c.execute(
                "UPDATE idempotency_records SET status='completed', result_ref=%s, response_enc=%s,"
                " updated_at=%s WHERE scope=%s AND operation=%s AND idem_key=%s AND status='in_progress'",
                (result_ref, blob, now, scope, operation, idem_key))
            if cur.rowcount != 1:
                raise StorageError("idempotency record is not in_progress (concurrent completion?)")
        self.db.run("idem_complete", go)

    def fail(self, scope, operation, idem_key, *, now):
        self.db.run("idem_fail", lambda c: c.execute(
            "DELETE FROM idempotency_records WHERE scope=%s AND operation=%s AND idem_key=%s"
            " AND status='in_progress'", (scope, operation, idem_key)))

    def takeover_stale(self, scope, operation, idem_key, *, digest, actor, owner_instance,
                       stale_before, now):
        def go(c):
            cur = c.execute(
                "UPDATE idempotency_records SET owner_instance=%s, updated_at=%s"
                " WHERE scope=%s AND operation=%s AND idem_key=%s AND status='in_progress'"
                " AND request_digest=%s AND actor=%s AND updated_at <= %s",
                (owner_instance, now, scope, operation, idem_key, digest, actor, stale_before))
            return cur.rowcount == 1
        return bool(self.db.run("idem_takeover", go))

    def purge_expired(self, now):
        return self.db.run("idem_purge", lambda c: c.execute(
            "DELETE FROM idempotency_records WHERE expires_at <= %s", (now,)).rowcount)
