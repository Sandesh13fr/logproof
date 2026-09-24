"""Deterministic local pipeline check without an HTTP server."""
from __future__ import annotations

import os
import sys
import tempfile
import asyncio
import base64
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

with tempfile.TemporaryDirectory(prefix="logproof-smoke-") as directory:
    os.environ["LOGPROOF_DATA"] = directory
    from backend.main import Approval, approve, events, evidence, export_events, import_ndjson, ingest_bytes, overview, pack_valid, parser_evaluation_result, replay_result, rollback, sample, scenario

    scenario("reset")
    assert overview()["accepted"] == 10
    assert all(item["normalized"]["event_time"].endswith("Z") for item in events())
    source_events = {item["source_id"]: item for item in events()}
    assert source_events["syslog_rfc5424"]["quality"]["status"] == "accepted"
    assert source_events["syslog_rfc5424"]["normalized"]["application"] == "sshd"
    assert source_events["cef_security"]["quality"]["status"] == "accepted"
    assert source_events["cef_security"]["normalized"]["src"] == {"ip": "198.51.100.23", "port": 51642, "host": None}
    assert source_events["windows_event_xml"]["quality"]["status"] == "accepted"
    assert source_events["windows_event_xml"]["normalized"]["user"]["id"] == "analyst"
    assert source_events["csv_network"]["quality"]["status"] == "accepted"
    assert source_events["csv_network"]["normalized"]["src"]["port"] == 52340
    assert source_events["leef_security"]["quality"]["status"] == "accepted"
    assert source_events["leef_security"]["normalized"]["event_code"] == "BLOCKED_FLOW"
    assert source_events["leef_security"]["normalized"]["severity"] == 8
    leef_v1 = ingest_bytes("leef_security", b"LEEF:1.0|IBM|QRadar|1.0|LOGIN|devTime=2026-09-24T12:34:56Z\tusrName=analyst\tcat=Login succeeded\tsev=5")
    assert leef_v1["quality"]["status"] == "accepted"
    leef_hex_delimiter = ingest_bytes("leef_security", b"LEEF:2.0|IBM|QRadar|1.0|LOGIN|x7c|devTime=2026-09-24T12:34:56Z|usrName=analyst|cat=Login succeeded|sev=5")
    assert leef_hex_delimiter["quality"]["status"] == "accepted"
    assert len({item["raw_format"] for item in events()}) >= 6
    assert pack_valid("1.4.2") and pack_valid("1.4.3")
    changed = scenario("mapping-failure")["events"][0]
    assert changed["quality"]["status"] == "quarantined"
    assert changed["quality"]["drift_detected"]
    assert evidence(changed["receipt_id"])["hash_verified"]
    replay = replay_result()
    assert replay["golden_passed"] == replay["golden_total"] == 2
    assert replay["promotion_ready"] and replay["regressions"] == 0
    evaluation_event_count = len(events())
    evaluation = parser_evaluation_result()
    assert evaluation["source_count"] == 10 and evaluation["case_count"] == 20
    assert evaluation["overall"]["field_f1"] == 1.0
    assert evaluation["overall"]["quarantine_recall"] == 1.0
    assert evaluation["overall"]["fixture_pass_rate"] == 1.0
    assert all(source["cases"] == 2 and source["fixture_pass_rate"] == 1.0 for source in evaluation["sources"])
    assert len(events()) == evaluation_event_count
    assert approve(Approval(approved_by="Smoke operator"))["state"]["active"] == "1.4.3"
    assert rollback()["state"]["active"] == "1.4.2"
    malformed = scenario("malformed")["events"][0]
    assert malformed["quality"]["status"] == "quarantined"
    assert evidence(malformed["receipt_id"])["hash_verified"]
    bad_xml = ingest_bytes("windows_event_xml", b"<Event><System>")
    assert bad_xml["quality"]["status"] == "quarantined"
    bad_syslog = ingest_bytes("syslog_rfc5424", b"<999>1 2026-09-24T12:34:56Z host app 1 ID - test")
    assert bad_syslog["quality"]["status"] == "quarantined"
    lines = [
        {"source_id": "csv_network", "raw": sample("csv_network", 55).decode()},
        {"source_id": "leef_security", "raw": sample("leef_security", 56).decode()},
        {"source_id": "unknown_source", "raw": "one event"},
    ]
    imported = import_ndjson("\n".join(json.dumps(line) for line in lines).encode())
    assert (imported["submitted"], imported["accepted"], imported["rejected"]) == (3, 2, 1)
    async def read_export(response):
        chunks = [chunk async for chunk in response.body_iterator]
        return "".join(chunk.decode() if isinstance(chunk, bytes) else chunk for chunk in chunks)
    binary_raw = b"\xff\x00non-UTF8 application record"
    binary_event = ingest_bytes("json_application", binary_raw)
    stream = export_events()
    exported_binary = json.loads(next(
        line for line in asyncio.run(read_export(stream)).splitlines()
        if binary_event["event_id"] in line
    ))
    assert exported_binary["raw_base64"] == base64.b64encode(binary_raw).decode()
    roundtrip = import_ndjson(json.dumps({"source_id": "json_application", "raw_base64": exported_binary["raw_base64"]}).encode())
    assert roundtrip["quarantined"] == 1
    assert roundtrip["items"][0]["event"]["sha256"] == binary_event["sha256"]
    exported = asyncio.run(read_export(export_events())).splitlines()
    assert all(isinstance(json.loads(line), dict) for line in exported)
    assert len(exported) == overview()["accepted"] + overview()["quarantined"]
    print("LogProof smoke check passed: 10 source families, 20 parser evaluation fixtures, CSV, LEEF, UTF-8/base64 NDJSON import/export round trip, quarantine, evidence, replay, promotion, rollback")
