"""Smoke tests for the AQL-1 backend."""

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_tools_listed():
    r = client.get("/tools")
    assert r.status_code == 200
    names = [t["function"]["name"] for t in r.json()["tools"]]
    assert "echo" in names and "now" in names


def test_agent_run():
    r = client.post("/agent/run", json={"task": "Say hello"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["answer"]


def test_memory_roundtrip():
    client.post("/memory", json={"text": "AQL-1 is an agent operating layer"})
    r = client.post("/memory/query", json={"text": "agent operating layer", "top_k": 3})
    assert r.status_code == 200
    assert len(r.json()["results"]) >= 1
