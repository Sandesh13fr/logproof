"""Deterministic local pipeline check without an HTTP server."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

with tempfile.TemporaryDirectory(prefix="logproof-smoke-") as directory:
    os.environ["LOGPROOF_DATA"] = directory
    from backend.main import Approval, approve, events, evidence, overview, pack_valid, replay_result, rollback, scenario

    scenario("reset")
    assert overview()["accepted"] == 5
    assert all(item["normalized"]["event_time"].endswith("Z") for item in events())
    assert pack_valid("1.4.2") and pack_valid("1.4.3")
    changed = scenario("mapping-failure")["events"][0]
    assert changed["quality"]["status"] == "quarantined"
    assert changed["quality"]["drift_detected"]
    assert evidence(changed["receipt_id"])["hash_verified"]
    replay = replay_result()
    assert replay["golden_passed"] == replay["golden_total"] == 2
    assert replay["promotion_ready"] and replay["regressions"] == 0
    assert approve(Approval(approved_by="Smoke operator"))["state"]["active"] == "1.4.3"
    assert rollback()["state"]["active"] == "1.4.2"
    malformed = scenario("malformed")["events"][0]
    assert malformed["quality"]["status"] == "quarantined"
    assert evidence(malformed["receipt_id"])["hash_verified"]
    print("LogProof smoke check passed: ingest, drift, evidence, replay, promotion, rollback")
