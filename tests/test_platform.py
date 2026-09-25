"""HTTP-level checks using an isolated SQLite database for every case."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import sys
from datetime import datetime

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def platform(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGPROOF_DATA", str(tmp_path))
    monkeypatch.delenv("LOGPROOF_PUBLIC_DEMO", raising=False)
    monkeypatch.delenv("LOGPROOF_ACCESS_KEY", raising=False)
    sys.modules.pop("backend.main", None)
    api = importlib.import_module("backend.main")
    with TestClient(api.app) as client:
        yield api, client
    api.stop()
    sys.modules.pop("backend.main", None)


def test_seeded_sources_have_ist_receipts_and_matching_event_instants(platform):
    api, client = platform
    events = client.get("/api/events").json()
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(events) == len(api.SOURCES) == 10
    assert all(item["quality"]["status"] == "accepted" for item in events)
    for item in events:
        received = datetime.fromisoformat(item["received_at"])
        event_time = datetime.fromisoformat(item["normalized"]["event_time"].replace("Z", "+00:00"))
        assert item["received_at"].endswith("+05:30")
        assert abs((received - event_time).total_seconds()) < 2
        evidence = client.get(f"/api/evidence/{item['receipt_id']}").json()
        assert evidence["hash_verified"] is True
        assert hashlib.sha256(bytes.fromhex(evidence["raw_hex"])).hexdigest() == item["sha256"]


def test_ingest_search_and_export_round_trip(platform):
    _, client = platform
    raw = b'{"timestamp":"2026-09-24T18:04:56+05:30","message":"test marker"}'
    response = client.post("/api/ingest/json_application", content=raw)
    assert response.status_code == 200
    item = response.json()
    assert item["normalized"]["event_time"] == "2026-09-24T12:34:56Z"
    assert item["received_at"].endswith("+05:30")
    page = client.get("/api/events/page", params={"q": item["receipt_id"]}).json()
    assert page["total"] == 1 and page["items"][0]["event_id"] == item["event_id"]
    exported = [json.loads(line) for line in client.get("/api/events/export.ndjson").text.splitlines()]
    assert next(record for record in exported if record["event_id"] == item["event_id"])["raw"].encode() == raw


def test_binary_batch_preserves_bytes_and_rejects_bad_records(platform):
    _, client = platform
    raw = b"\xff\x00unreadable"
    lines = [
        {"source_id": "json_application", "raw_base64": base64.b64encode(raw).decode()},
        {"source_id": "json_application", "raw_base64": "%%%"},
        {"source_id": "missing", "raw": "hello"},
    ]
    response = client.post("/api/ingest/batch", content="\n".join(map(json.dumps, lines)))
    assert response.status_code == 200
    result = response.json()
    assert (result["submitted"], result["quarantined"], result["rejected"]) == (3, 1, 2)
    exported = client.get("/api/events/export.ndjson").text
    assert base64.b64encode(raw).decode() in exported


def test_size_limits_reject_before_storing(platform):
    api, client = platform
    before = client.get("/api/overview").json()["accepted"]
    too_large = b"x" * (api.MAX_EVENT_BYTES + 1)
    assert client.post("/api/ingest/json_application", content=too_large).status_code == 413
    assert client.post("/api/ingest/batch", content=b"x" * (api.MAX_BATCH_BYTES + 1)).status_code == 413
    batch = "\n".join(json.dumps({"source_id": "json_application", "raw": "x"}) for _ in range(api.MAX_BATCH_EVENTS + 1))
    assert client.post("/api/ingest/batch", content=batch).status_code == 413
    assert client.get("/api/overview").json()["accepted"] == before


def test_deeply_nested_input_is_quarantined_without_server_error(platform):
    _, client = platform
    raw = b'{"timestamp":"2026-09-24T18:04:56+05:30","message":"nested","extra":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"
    response = client.post("/api/ingest/json_application", content=raw)
    assert response.status_code == 200
    item = response.json()
    assert item["quality"]["status"] == "quarantined"
    assert client.get(f"/api/evidence/{item['receipt_id']}").json()["hash_verified"] is True


def test_malformed_drift_replay_and_registry_gates(platform):
    _, client = platform
    drift = client.post("/api/simulator/scenario/mapping-failure").json()["events"][0]
    assert drift["quality"]["status"] == "quarantined"
    assert drift["quality"]["drift_detected"] is True
    assert client.post("/api/simulator/scenario/malformed").json()["events"][0]["quality"]["status"] == "quarantined"
    evaluation = client.get("/api/parser/evaluation").json()
    assert evaluation["source_count"] == 10 and evaluation["case_count"] == 20
    assert evaluation["overall"]["fixture_pass_rate"] == 1
    replay = client.post("/api/replay").json()
    assert replay["promotion_ready"] is False
    assert client.post("/api/parser/approve", json={"approved_by": "Test operator"}).status_code == 409
    assert client.post("/api/simulator/scenario/reset").status_code == 200
    replay = client.post("/api/replay").json()
    assert replay["promotion_ready"] and replay["golden_passed"] == replay["golden_total"]
    assert client.post("/api/parser/approve", json={"approved_by": " "}).status_code in (400, 422)
    assert client.post("/api/parser/approve", json={"approved_by": "Test operator"}).json()["state"]["active"] == "1.4.3"
    assert client.post("/api/parser/rollback").json()["state"]["active"] == "1.4.2"


def test_unknown_ids_search_bounds_and_cors(platform):
    _, client = platform
    assert client.get("/api/events/does-not-exist").status_code == 404
    assert client.get("/api/evidence/does-not-exist").status_code == 404
    assert client.get("/api/events/page", params={"q": "x" * 201}).status_code == 422
    assert client.get("/api/events/page", params={"q": "%' OR 1=1 --"}).json()["total"] == 0
    headers = {"Origin": "https://untrusted.example", "Access-Control-Request-Method": "POST"}
    assert client.options("/api/ingest/json_application", headers=headers).status_code == 400


def test_public_demo_blocks_uploads_import_and_approval(platform, monkeypatch):
    api, client = platform
    monkeypatch.setattr(api, "PUBLIC_DEMO", True)
    forbidden = (
        ("/api/ingest/json_application", b"secret"),
        ("/api/ingest/batch", b"secret"),
        ("/api/datasets/witfoo/import", b"{}"),
        ("/api/parser/approve", b"{}"),
        ("/api/parser/rollback", b"{}"),
    )
    before = client.get("/api/events/page").json()["total"]
    for path, body in forbidden:
        assert client.post(path, content=body).status_code == 403
    assert client.get("/api/events/page").json()["total"] == before
    monkeypatch.setattr(api, "MAX_PUBLIC_EVENTS", before)
    assert client.post("/api/simulator/source/json_application/emit").status_code == 429
    assert client.get("/api/events/page").json()["total"] == before


def test_public_demo_uses_separate_data_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGPROOF_DATA", str(tmp_path))
    monkeypatch.delenv("LOGPROOF_PUBLIC_DEMO", raising=False)
    sys.modules.pop("backend.main", None)
    local = importlib.import_module("backend.main")
    local.ingest_bytes("json_application", b'{"timestamp":"2026-09-24T12:34:56Z","message":"private marker"}')
    local.stop()
    sys.modules.pop("backend.main", None)
    monkeypatch.setenv("LOGPROOF_PUBLIC_DEMO", "1")
    api = importlib.import_module("backend.main")
    try:
        assert api.DATA == tmp_path / "public-demo"
        assert api.DB.parent == api.DATA
        assert api.DB.exists()
        assert (tmp_path / "logproof.sqlite3").exists()
        with TestClient(api.app) as client:
            assert client.get("/api/events/page").json()["total"] == 10
            assert "private marker" not in client.get("/api/events/export.ndjson").text
    finally:
        api.stop()
        sys.modules.pop("backend.main", None)


def test_hosted_key_unlocks_full_workflow_and_protects_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGPROOF_DATA", str(tmp_path))
    monkeypatch.setenv("LOGPROOF_PUBLIC_DEMO", "1")
    monkeypatch.setenv("LOGPROOF_ACCESS_KEY", "test-secret-key")
    sys.modules.pop("backend.main", None)
    api = importlib.import_module("backend.main")
    try:
        with TestClient(api.app) as client:
            raw = b'{"timestamp":"2026-09-24T18:04:56+05:30","message":"hosted marker","user":"analyst"}'
            assert client.get("/api/health").status_code == 200
            for path in ("/api/overview", "/api/events", "/api/events/export.ndjson", "/api/parser/registry"):
                assert client.get(path).status_code == 401
            assert client.post("/api/ingest/json_application", content=raw).status_code == 401
            assert client.get("/api/events", headers={"X-LogProof-Key": "wrong"}).status_code == 401
            client.headers["X-LogProof-Key"] = "test-secret-key"
            item = client.post("/api/ingest/json_application", content=raw).json()
            assert item["quality"]["status"] == "accepted"
            assert client.get(f"/api/evidence/{item['receipt_id']}").json()["hash_verified"] is True
            assert b"hosted marker" in client.get("/api/events/export.ndjson").content
            result = client.post("/api/ingest/batch", content=json.dumps({
                "source_id": "json_application", "raw": raw.decode()
            })).json()
            assert result["accepted"] == 1
            assert client.post("/api/simulator/scenario/reset").status_code == 200
            assert client.post("/api/replay").json()["promotion_ready"] is True
            assert client.post("/api/parser/approve", json={"approved_by": "Hosted test"}).status_code == 200
            assert client.post("/api/parser/rollback").status_code == 200
    finally:
        api.stop()
        sys.modules.pop("backend.main", None)
