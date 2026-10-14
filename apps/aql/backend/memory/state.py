"""Conversation / run state management backed by Supabase.

Falls back to an in-memory dict when Supabase is not configured.

Extended for the long-term memory manager: the ``memory_audit`` table holds
one row per session/run for auditing \u2014 prompt, response, model, token counts,
cost, latency and timestamp.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from core.config import get_settings

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class StateManager:
    """Persists agent runs, conversation state and audit logs."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._local: dict[str, dict[str, Any]] = {}
        self._run_meta: dict[str, str] = {}
        self._audit: list[dict[str, Any]] = []
        self._approvals: dict[str, dict[str, Any]] = {}
        # API-key records, keyed by SHA-256 hash (in-memory fallback store).
        self._api_keys: dict[str, dict[str, Any]] = {}
        # Billing: one subscription + one usage row per user, plus manual
        # payment verifications (Payoneer / bank transfer).
        self._subscriptions: dict[str, dict[str, Any]] = {}
        self._usage: dict[str, dict[str, Any]] = {}
        self._payments: dict[str, dict[str, Any]] = {}
        self._client = None
        if self.settings.supabase_url and self.settings.supabase_service_role_key:
            self._client = self._connect_supabase()

    def _connect_supabase(self):  # pragma: no cover — needs real creds
        try:
            from supabase import create_client

            return create_client(
                self.settings.supabase_url,
                self.settings.supabase_service_role_key,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Supabase unavailable (%s) — using in-memory state", exc)
            return None

    @property
    def is_local(self) -> bool:
        """True when state/audit rows live in memory only."""
        return self._client is None

    # ── run state ──────────────────────────────────────────────────────────
    def save_run(self, run_id: str, payload: dict[str, Any]) -> None:
        created_at = _utcnow_iso()
        self._run_meta[run_id] = created_at
        # Stamp the run itself so the observability layer can bucket reliably.
        payload.setdefault("created_at", created_at)
        if self._client is not None:  # pragma: no cover
            self._client.table("agent_runs").upsert(
                {"run_id": run_id, "payload": payload, "created_at": created_at}
            ).execute()
        else:
            self._local[run_id] = payload

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        if self._client is not None:  # pragma: no cover
            res = (
                self._client.table("agent_runs")
                .select("payload")
                .eq("run_id", run_id)
                .execute()
            )
            rows = res.data or []
            return rows[0]["payload"] if rows else None
        return self._local.get(run_id)

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        if self._client is not None:  # pragma: no cover
            res = (
                self._client.table("agent_runs")
                .select("payload")
                .limit(limit)
                .execute()
            )
            return [r["payload"] for r in (res.data or [])]
        return list(self._local.values())[:limit]

    def list_runs_detailed(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return runs as ``{run_id, created_at, payload}`` for observability.

        The observability layer needs the run id and a timestamp alongside the
        payload; this keeps that join in one place instead of leaking the
        storage shape into ``core/observability.py``.
        """
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table("agent_runs")
                    .select("run_id,payload,created_at")
                    .order("created_at", desc=True)
                    .limit(limit)
                    .execute()
                )
                return list(res.data or [])
            except Exception as exc:  # noqa: BLE001 — fall back to local view
                logger.warning("Supabase run list failed (%s)", exc)
        rows = []
        for run_id, payload in self._local.items():
            rows.append(
                {
                    "run_id": run_id,
                    "created_at": self._run_meta.get(run_id)
                    or payload.get("created_at", ""),
                    "payload": payload,
                }
            )
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    # ── audit log ────────────────────────────────────────────────────────────
    def log_audit(self, record: dict[str, Any]) -> dict[str, Any]:
        """Insert one audit row; keep it locally if Supabase is unavailable."""
        row = dict(record)
        row.setdefault("log_id", str(uuid.uuid4()))
        row.setdefault("created_at", _utcnow_iso())
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.memory_audit_table).insert(
                    row
                ).execute()
                return row
            except Exception as exc:  # noqa: BLE001 — keep auditing regardless
                logger.warning(
                    "Supabase audit insert failed (%s) — keeping it locally", exc
                )
        self._audit.append(row)
        return row

    # ── pending approvals (guardrails) ───────────────────────────────────────
    def save_approval(self, approval_id: str, payload: dict[str, Any]) -> None:
        """Persist one paused-run approval record."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.guardrails_approval_table).upsert(
                    {"approval_id": approval_id, "payload": payload}
                ).execute()
                return
            except Exception as exc:  # noqa: BLE001 — keep it locally regardless
                logger.warning(
                    "Supabase approval upsert failed (%s) — keeping it locally", exc
                )
        self._approvals[approval_id] = payload

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        """Fetch one approval record by id."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.guardrails_approval_table)
                    .select("payload")
                    .eq("approval_id", approval_id)
                    .execute()
                )
                rows = res.data or []
                if rows:
                    return rows[0]["payload"]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase approval read failed (%s)", exc)
        return self._approvals.get(approval_id)

    def update_approval(self, approval_id: str, patch: dict[str, Any]) -> None:
        """Merge ``patch`` into an existing approval record."""
        current = self.get_approval(approval_id) or {"approval_id": approval_id}
        current.update(patch)
        self.save_approval(approval_id, current)

    def list_approvals(
        self, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Return approval records, newest first, optionally filtered."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                query = self._client.table(
                    self.settings.guardrails_approval_table
                ).select("payload")
                res = query.limit(limit).execute()
                rows = [r["payload"] for r in (res.data or [])]
                if status:
                    rows = [r for r in rows if r.get("status") == status]
                return rows
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase approval list failed (%s)", exc)
        rows = list(self._approvals.values())
        if status:
            rows = [r for r in rows if r.get("status") == status]
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    # ── API keys (REST auth) ─────────────────────────────────────────────────
    # Only the SHA-256 *hash* of a key is ever stored — the raw key is shown to
    # the caller once at creation time and never persisted. These helpers keep
    # the storage shape out of ``core/auth.py``, mirroring the approval helpers.
    def save_api_key(self, key_hash: str, payload: dict[str, Any]) -> None:
        """Upsert one API-key record, keyed by its hash."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.api_keys_table).upsert(
                    {"key_hash": key_hash, "payload": payload}
                ).execute()
                return
            except Exception as exc:  # noqa: BLE001 — keep it locally regardless
                logger.warning(
                    "Supabase api-key upsert failed (%s) — keeping it locally", exc
                )
        self._api_keys[key_hash] = payload

    def get_api_key(self, key_hash: str) -> dict[str, Any] | None:
        """Fetch one API-key record by its hash."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.api_keys_table)
                    .select("payload")
                    .eq("key_hash", key_hash)
                    .execute()
                )
                rows = res.data or []
                if rows:
                    return rows[0]["payload"]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase api-key read failed (%s)", exc)
        return self._api_keys.get(key_hash)

    def list_api_keys(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return API-key records, newest first."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.api_keys_table)
                    .select("payload")
                    .limit(limit)
                    .execute()
                )
                rows = [r["payload"] for r in (res.data or [])]
                rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
                return rows[:limit]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase api-key list failed (%s)", exc)
        rows = list(self._api_keys.values())
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    def update_api_key(self, key_hash: str, patch: dict[str, Any]) -> None:
        """Merge ``patch`` into an existing API-key record."""
        current = self.get_api_key(key_hash) or {"key_hash": key_hash}
        current.update(patch)
        self.save_api_key(key_hash, current)

    # ── billing: subscriptions ───────────────────────────────────────────────
    # Billing state lives in its own tables (`subscriptions`, `usage`,
    # `payment_verifications`) so a schema change to one never disturbs the others.
    # Every helper mirrors the approval/api-key pattern: try Supabase, fall
    # back to memory, and never raise into the caller.
    def save_subscription(self, user_id: str, payload: dict[str, Any]) -> None:
        """Upsert one user's subscription record."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.subscriptions_table).upsert(
                    {"user_id": user_id, "payload": payload}
                ).execute()
                return
            except Exception as exc:  # noqa: BLE001 — keep it locally regardless
                logger.warning(
                    "Supabase subscription upsert failed (%s) — keeping it locally",
                    exc,
                )
        self._subscriptions[user_id] = payload

    def get_subscription(self, user_id: str) -> dict[str, Any] | None:
        """Fetch one user's subscription record."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.subscriptions_table)
                    .select("payload")
                    .eq("user_id", user_id)
                    .execute()
                )
                rows = res.data or []
                if rows:
                    return rows[0]["payload"]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase subscription read failed (%s)", exc)
        return self._subscriptions.get(user_id)

    def list_subscriptions(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return subscription records, newest first."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.subscriptions_table)
                    .select("payload")
                    .limit(limit)
                    .execute()
                )
                rows = [r["payload"] for r in (res.data or [])]
                rows.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
                return rows[:limit]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase subscription list failed (%s)", exc)
        rows = list(self._subscriptions.values())
        rows.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
        return rows[:limit]

    # ── billing: usage ───────────────────────────────────────────────────────
    def save_usage(self, user_id: str, payload: dict[str, Any]) -> None:
        """Upsert one user's monthly usage record."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.usage_table).upsert(
                    {"user_id": user_id, "payload": payload}
                ).execute()
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Supabase usage upsert failed (%s) — keeping it locally", exc
                )
        self._usage[user_id] = payload

    def get_usage(self, user_id: str) -> dict[str, Any] | None:
        """Fetch one user's usage record."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.usage_table)
                    .select("payload")
                    .eq("user_id", user_id)
                    .execute()
                )
                rows = res.data or []
                if rows:
                    return rows[0]["payload"]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase usage read failed (%s)", exc)
        return self._usage.get(user_id)

    # ── billing: manual payment verifications ────────────────────────────────
    def save_payment_verification(self, payment_id: str, row: dict[str, Any]) -> None:
        """Upsert one ``payment_verifications`` row (real columns, no jsonb)."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                self._client.table(self.settings.payment_verifications_table).upsert(
                    row
                ).execute()
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase payment upsert failed (%s)", exc)
                raise
        self._payments[payment_id] = row

    def get_payment_verification(self, payment_id: str) -> dict[str, Any] | None:
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                res = (
                    self._client.table(self.settings.payment_verifications_table)
                    .select("*")
                    .eq("id", payment_id)
                    .execute()
                )
                rows = res.data or []
                return rows[0] if rows else None
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase payment read failed (%s)", exc)
                raise
        return self._payments.get(payment_id)

    def list_payment_verifications(
        self,
        *,
        status: str | None = None,
        user_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                q = self._client.table(
                    self.settings.payment_verifications_table
                ).select("*")
                if status:
                    q = q.eq("status", status)
                if user_id:
                    q = q.eq("user_id", user_id)
                res = q.order("created_at", desc=True).limit(limit).execute()
                return list(res.data or [])
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase payment list failed (%s)", exc)
                raise
        rows = [
            r for r in self._payments.values()
            if (not status or r.get("status") == status)
            and (not user_id or r.get("user_id") == user_id)
        ]
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    def upload_payment_screenshot(
        self, path: str, data: bytes, content_type: str
    ) -> bool:
        """Store a screenshot in the private Storage bucket. False in local mode."""
        if self._client is None:
            return False
        try:  # pragma: no cover — needs real creds
            self._client.storage.from_(self.settings.payment_screenshot_bucket).upload(
                path, data, {"content-type": content_type, "upsert": "true"}
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Screenshot upload failed (%s)", exc)
            raise

    def payment_screenshot_url(self, path: str, expires_in: int = 3600) -> str:
        """A short-lived signed URL for an admin to view a screenshot."""
        if self._client is None or not path:
            return ""
        try:  # pragma: no cover — needs real creds
            res = self._client.storage.from_(
                self.settings.payment_screenshot_bucket
            ).create_signed_url(path, expires_in)
            return str(res.get("signedURL") or res.get("signedUrl") or "")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Signed URL failed (%s)", exc)
            return ""

    # ── audit log ────────────────────────────────────────────────────────────
    def list_audit(
        self,
        user_id: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return audit rows, newest first, optionally filtered."""
        if self._client is not None:  # pragma: no cover — needs real creds
            try:
                query = self._client.table(self.settings.memory_audit_table).select(
                    "*"
                )
                if user_id:
                    query = query.eq("user_id", user_id)
                if session_id:
                    query = query.eq("session_id", session_id)
                res = query.order("created_at", desc=True).limit(limit).execute()
                return res.data or []
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supabase audit read failed (%s)", exc)
        rows = [
            r
            for r in self._audit
            if (user_id is None or r.get("user_id") == user_id)
            and (session_id is None or r.get("session_id") == session_id)
        ]
        return list(reversed(rows))[:limit]
