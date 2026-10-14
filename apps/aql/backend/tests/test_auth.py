"""Tests for the production REST API and API-key authentication.

Covers the full auth surface:

* key hashing / minting (raw key returned once, only the hash stored)
* valid key accepted, missing / invalid / revoked key rejected with 401
* per-key rate limiting → 429 with ``Retry-After`` and ``X-RateLimit-*``
* ``POST /v1/agent/run`` (sync + async) and ``GET /v1/agent/status/{task_id}``
* the high-risk pause path returning ``pending_approval`` + an approval id
* graceful degradation with no keys / no Supabase (in-memory store)
* the ``AUTH_ENABLED=false`` local-dev escape hatch

The suite runs with auth disabled by default (see ``conftest.py``); every test
here builds its own app with ``create_app(auth_enabled=True)`` so the
authenticated surface is exercised explicitly.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.auth import (
    APIKeyStore,
    InvalidAPIKeyError,
    MissingAPIKeyError,
    RateLimiter,
    RevokedAPIKeyError,
    extract_api_key,
    generate_api_key,
    get_api_key_store,
    hash_api_key,
    reset_auth_state,
)
from main import create_app


@pytest.fixture(autouse=True)
def _isolate_auth_state():
    """Give every test a fresh key store and rate limiter.

    The store and limiter are process-wide singletons, so without this a key
    minted in one test would leak into the next.
    """
    reset_auth_state()
    yield
    reset_auth_state()


@pytest.fixture
def client() -> TestClient:
    """A client for an app with authentication ENABLED."""
    return TestClient(create_app(auth_enabled=True))


@pytest.fixture
def open_client() -> TestClient:
    """A client for an app with authentication DISABLED (local dev)."""
    return TestClient(create_app(auth_enabled=False))


@pytest.fixture
def api_key() -> str:
    """Mint a key and return its raw value."""
    raw, _ = get_api_key_store().create("test-key")
    return raw


def auth_header(raw_key: str) -> dict[str, str]:
    """The conventional ``Authorization: Bearer`` header."""
    return {"Authorization": f"Bearer {raw_key}"}


# ══════════════════════════════════════════════════════════════════════════════
# Hashing & key generation
# ══════════════════════════════════════════════════════════════════════════════
def test_hash_is_deterministic_and_not_the_raw_key():
    raw = "aql1_supersecret"
    digest = hash_api_key(raw)
    assert digest == hash_api_key(raw)          # deterministic
    assert digest != raw                        # never the plaintext
    assert len(digest) == 64                    # SHA-256 hex digest
    assert digest == hash_api_key("aql1_supersecret")


def test_generated_keys_are_unique_and_prefixed():
    a, b = generate_api_key(), generate_api_key()
    assert a != b
    assert a.startswith("aql1_")
    assert len(a) > 30                          # high entropy


def test_create_returns_raw_key_once_and_stores_only_the_hash():
    store = get_api_key_store()
    raw, record = store.create("ci-key", owner_id="team-a")

    assert raw.startswith("aql1_")
    assert record.key_hash == hash_api_key(raw)
    assert record.key_hash != raw

    # The persisted record must never contain the raw key.
    stored = store._state.get_api_key(record.key_hash)
    assert stored is not None
    assert "api_key" not in stored
    assert raw not in str(stored)
    assert stored["key_hash"] == hash_api_key(raw)


def test_list_never_exposes_the_raw_key(api_key):
    keys = get_api_key_store().list()
    assert len(keys) == 1
    serialised = str([k.to_dict() for k in keys])
    assert api_key not in serialised
    # The hash is not part of the public serialisation either.
    assert "key_hash" not in keys[0].to_dict()


# ══════════════════════════════════════════════════════════════════════════════
# Key extraction
# ══════════════════════════════════════════════════════════════════════════════
def test_extract_api_key_supports_both_headers():
    from starlette.requests import Request

    def make(headers: dict[str, str]) -> Request:
        raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
        return Request({"type": "http", "headers": raw, "method": "GET", "path": "/"})

    assert extract_api_key(make({"Authorization": "Bearer abc"})) == "abc"
    assert extract_api_key(make({"X-API-Key": "xyz"})) == "xyz"
    # X-API-Key wins when both are present.
    assert (
        extract_api_key(make({"Authorization": "Bearer abc", "X-API-Key": "xyz"}))
        == "xyz"
    )
    assert extract_api_key(make({})) is None
    assert extract_api_key(make({"Authorization": "Basic abc"})) is None


# ══════════════════════════════════════════════════════════════════════════════
# Store-level verification
# ══════════════════════════════════════════════════════════════════════════════
def test_store_verify_accepts_a_valid_key():
    store = get_api_key_store()
    raw, record = store.create("valid")
    assert store.verify(raw).key_id == record.key_id


def test_store_verify_rejects_missing_key():
    with pytest.raises(MissingAPIKeyError):
        get_api_key_store().verify(None)
    with pytest.raises(MissingAPIKeyError):
        get_api_key_store().verify("")


def test_store_verify_rejects_unknown_key():
    with pytest.raises(InvalidAPIKeyError):
        get_api_key_store().verify("aql1_not-a-real-key")


def test_store_verify_rejects_revoked_key():
    store = get_api_key_store()
    raw, record = store.create("to-revoke")
    store.revoke(record.key_id)
    with pytest.raises(RevokedAPIKeyError):
        store.verify(raw)


def test_revoke_unknown_key_id_raises():
    with pytest.raises(InvalidAPIKeyError):
        get_api_key_store().revoke("no-such-id")


def test_store_falls_back_to_memory_without_supabase():
    """No Supabase configured → the store still works, in memory."""
    store = APIKeyStore()
    assert store.is_local is True
    raw, record = store.create("offline")
    assert store.verify(raw).key_id == record.key_id
    assert store.get(record.key_id) is not None


# ══════════════════════════════════════════════════════════════════════════════
# Middleware: 401 paths
# ══════════════════════════════════════════════════════════════════════════════
def test_public_routes_need_no_key(client):
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/").status_code == 200


def test_missing_key_returns_401(client):
    r = client.get("/tools")
    assert r.status_code == 401
    body = r.json()
    assert body["error"] == "unauthorized"
    assert body["code"] == "missing_api_key"
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_key_returns_401(client):
    r = client.get("/tools", headers=auth_header("aql1_bogus"))
    assert r.status_code == 401
    assert r.json()["code"] == "invalid_api_key"


def test_revoked_key_returns_401(client, api_key):
    """A revoked key must stop working immediately — including on the very
    request that revokes it (the usage-tracking write must not resurrect it)."""
    key_id = get_api_key_store().list()[0].key_id

    assert client.get("/tools", headers=auth_header(api_key)).status_code == 200
    assert client.delete(f"/v1/keys/{key_id}", headers=auth_header(api_key)).status_code == 200

    r = client.get("/tools", headers=auth_header(api_key))
    assert r.status_code == 401
    assert r.json()["code"] == "revoked_api_key"


def test_valid_key_is_accepted_via_both_headers(client, api_key):
    assert client.get("/tools", headers=auth_header(api_key)).status_code == 200
    assert client.get("/tools", headers={"X-API-Key": api_key}).status_code == 200


def test_identity_is_attached_to_request_state(client, api_key):
    """The middleware exposes the resolved key so endpoints can use it."""
    r = client.post(
        "/v1/agent/run",
        json={"task": "Say hello", "wait": True},
        headers=auth_header(api_key),
    )
    assert r.status_code == 200
    assert r.json()["api_key"]["name"] == "test-key"


# ══════════════════════════════════════════════════════════════════════════════
# Rate limiting
# ══════════════════════════════════════════════════════════════════════════════
def test_rate_limit_headers_are_advertised(client, api_key):
    r = client.get("/tools", headers=auth_header(api_key))
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "60"
    assert r.headers["X-RateLimit-Remaining"] == "59"
    assert int(r.headers["X-RateLimit-Reset"]) > 0


def test_rate_limit_exceeded_returns_429_with_headers(client):
    raw, _ = get_api_key_store().create(
        "limited", rate_limit_requests=3, rate_limit_window_seconds=60
    )
    headers = auth_header(raw)

    for _ in range(3):
        assert client.get("/tools", headers=headers).status_code == 200

    r = client.get("/tools", headers=headers)
    assert r.status_code == 429
    body = r.json()
    assert body["error"] == "rate_limited"
    assert body["code"] == "rate_limit_exceeded"
    assert body["retry_after"] >= 1
    # The standard rate-limit headers plus Retry-After must be present.
    assert r.headers["X-RateLimit-Limit"] == "3"
    assert r.headers["X-RateLimit-Remaining"] == "0"
    assert int(r.headers["X-RateLimit-Reset"]) > 0
    assert int(r.headers["Retry-After"]) >= 1


def test_rate_limits_are_isolated_per_key(client):
    a, _ = get_api_key_store().create("a", rate_limit_requests=1)
    b, _ = get_api_key_store().create("b", rate_limit_requests=1)

    assert client.get("/tools", headers=auth_header(a)).status_code == 200
    assert client.get("/tools", headers=auth_header(a)).status_code == 429
    # A different key has its own budget.
    assert client.get("/tools", headers=auth_header(b)).status_code == 200


def test_rate_limiter_sliding_window_unit():
    limiter = RateLimiter(requests=2, window_seconds=60)
    assert limiter.check("h").allowed is True
    assert limiter.check("h").allowed is True
    blocked = limiter.check("h")
    assert blocked.allowed is False
    assert blocked.remaining == 0
    assert blocked.retry_after >= 1
    # A different bucket is unaffected.
    assert limiter.check("other").allowed is True
    limiter.reset("h")
    assert limiter.check("h").allowed is True


# ══════════════════════════════════════════════════════════════════════════════
# POST /v1/agent/run
# ══════════════════════════════════════════════════════════════════════════════
def test_v1_run_synchronous_returns_full_result(client, api_key):
    r = client.post(
        "/v1/agent/run",
        json={"task": "Say hello", "wait": True},
        headers=auth_header(api_key),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["task_id"]
    assert body["status"] == "completed"
    assert body["result"]["answer"]
    assert body["approval_id"] is None


def test_v1_run_async_returns_task_id_immediately(client, api_key):
    r = client.post(
        "/v1/agent/run",
        json={"task": "Say hello"},
        headers=auth_header(api_key),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert body["task_id"]
    assert body["status_url"] == f"/v1/agent/status/{body['task_id']}"


def test_v1_run_requires_a_key(client):
    r = client.post("/v1/agent/run", json={"task": "Say hello"})
    assert r.status_code == 401


def test_v1_run_validates_the_body(client, api_key):
    r = client.post(
        "/v1/agent/run", json={"task": ""}, headers=auth_header(api_key)
    )
    assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# GET /v1/agent/status/{task_id}
# ══════════════════════════════════════════════════════════════════════════════
def test_v1_status_for_a_known_task(client, api_key):
    headers = auth_header(api_key)
    task_id = client.post(
        "/v1/agent/run", json={"task": "Say hello", "wait": True}, headers=headers
    ).json()["task_id"]

    r = client.get(f"/v1/agent/status/{task_id}", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["task_id"] == task_id
    assert body["status"] == "completed"
    assert body["progress"]["steps_completed"] >= 1
    assert body["progress"]["percent"] == 100.0
    assert body["result"] is not None
    assert body["cost_usd"] >= 0.0
    assert body["tokens"] >= 0


def test_v1_status_after_async_run_completes(client, api_key):
    """The background task must have settled by the time the client polls."""
    headers = auth_header(api_key)
    task_id = client.post(
        "/v1/agent/run", json={"task": "Say hello"}, headers=headers
    ).json()["task_id"]

    body = client.get(f"/v1/agent/status/{task_id}", headers=headers).json()
    assert body["status"] == "completed"
    assert body["result"] is not None


def test_v1_status_unknown_task_returns_404(client, api_key):
    r = client.get("/v1/agent/status/does-not-exist", headers=auth_header(api_key))
    assert r.status_code == 404
    assert "Unknown task id" in r.json()["detail"]


def test_v1_status_requires_a_key(client):
    assert client.get("/v1/agent/status/anything").status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# High-risk pause path through /v1/agent/run
# ══════════════════════════════════════════════════════════════════════════════
def test_v1_run_high_risk_action_pauses_for_approval(client, api_key):
    headers = auth_header(api_key)
    r = client.post(
        "/v1/agent/run",
        json={
            "task": "Email the customer list",
            "action_type": "email.send",
            "payload": {"to": "external@example.com"},
            "wait": True,
        },
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending_approval"
    assert body["approval_id"]
    # Nothing executed.
    assert body["result"]["steps"] == []


def test_v1_paused_run_reports_approval_id_in_status(client, api_key):
    headers = auth_header(api_key)
    task_id = client.post(
        "/v1/agent/run",
        json={"task": "Delete the users table", "action_type": "db.delete", "wait": True},
        headers=headers,
    ).json()["task_id"]

    body = client.get(f"/v1/agent/status/{task_id}", headers=headers).json()
    assert body["status"] == "pending_approval"
    assert body["approval_id"]


def test_v1_paused_run_can_be_approved_and_resumed(client, api_key):
    """The approval webhook resumes the run started through /v1."""
    headers = auth_header(api_key)
    approval_id = client.post(
        "/v1/agent/run",
        json={"task": "Send the invoice", "action_type": "payment.transfer", "wait": True},
        headers=headers,
    ).json()["approval_id"]

    r = client.post(
        "/agent/approve",
        json={"approval_id": approval_id, "decision": "approve", "approver": "arif"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "completed"


def test_v1_low_risk_action_executes_normally(client, api_key):
    r = client.post(
        "/v1/agent/run",
        json={"task": "Search the web", "action_type": "web_search", "wait": True},
        headers=auth_header(api_key),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    assert r.json()["approval_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# Key management endpoints
# ══════════════════════════════════════════════════════════════════════════════
def test_create_key_endpoint_returns_raw_key_once(client, api_key):
    r = client.post(
        "/v1/keys",
        json={"name": "new-key", "owner_id": "team-b"},
        headers=auth_header(api_key),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["api_key"].startswith("aql1_")
    assert body["key"]["name"] == "new-key"
    assert "key_hash" not in body["key"]
    assert "cannot be retrieved again" in body["warning"]

    # The freshly minted key works.
    assert client.get("/tools", headers=auth_header(body["api_key"])).status_code == 200


def test_list_keys_endpoint(client, api_key):
    r = client.get("/v1/keys", headers=auth_header(api_key))
    assert r.status_code == 200
    names = [k["name"] for k in r.json()["keys"]]
    assert "test-key" in names
    assert api_key not in str(r.json())


def test_revoke_key_endpoint(client, api_key):
    key_id = get_api_key_store().list()[0].key_id
    r = client.delete(f"/v1/keys/{key_id}", headers=auth_header(api_key))
    assert r.status_code == 200
    assert r.json()["revoked"] is True
    assert r.json()["key"]["active"] is False


def test_revoke_unknown_key_returns_404(client, api_key):
    r = client.delete("/v1/keys/nope", headers=auth_header(api_key))
    assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Graceful degradation
# ══════════════════════════════════════════════════════════════════════════════
def test_auth_disabled_lets_requests_through(open_client):
    """AUTH_ENABLED=false is the local-dev escape hatch."""
    assert open_client.get("/tools").status_code == 200
    r = open_client.post("/v1/agent/run", json={"task": "Say hello", "wait": True})
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    # No key identity is attached when auth is off.
    assert r.json()["api_key"] == {}


def test_no_keys_configured_still_serves_public_routes(client):
    """With an empty store, public routes work and protected ones 401."""
    assert get_api_key_store().list() == []
    assert client.get("/health").status_code == 200
    assert client.get("/tools").status_code == 401


def test_store_survives_a_broken_backend(monkeypatch):
    """A failing store degrades to a 401, never a 500."""
    store = get_api_key_store()

    def boom(_key_hash: str):
        raise RuntimeError("supabase is down")

    monkeypatch.setattr(store._state, "get_api_key", boom)
    client = TestClient(create_app(auth_enabled=True))
    r = client.get("/tools", headers=auth_header("aql1_anything"))
    assert r.status_code == 401
    assert r.json()["code"] == "auth_error"
