"""Local LogProof demonstration API. Raw bytes are committed before parsing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("LOGPROOF_DATA", ROOT / "data")).resolve()
RAW = DATA / "raw"
DB = DATA / "logproof.sqlite3"
RAW.mkdir(parents=True, exist_ok=True)
SOURCES = {
    "paloalto_firewall": ("Firewall", "JSON"),
    "cisco_router": ("Cisco router", "Syslog"),
    "nginx_access": ("NGINX access", "Combined log"),
    "windows_security": ("Windows security", "JSON"),
    "json_application": ("Application", "JSON"),
}
PARSER_ID = "paloalto-traffic"
BASE_VERSION = "1.4.2"
CANDIDATE_VERSION = "1.4.3"
PACK_FILES = ("manifest.yaml", "rules.yaml", "golden_samples.jsonl", "expected_outputs.jsonl")
LOCK = threading.RLock()
STOP = threading.Event()
WORKER: threading.Thread | None = None
RATES = {source: 1 for source in SOURCES}
ENABLED = {source: True for source in SOURCES}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize() -> None:
    with LOCK, connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY, receipt_id TEXT UNIQUE NOT NULL, source_id TEXT NOT NULL,
          received_at TEXT NOT NULL, raw_path TEXT NOT NULL, sha256 TEXT NOT NULL,
          parser_version TEXT NOT NULL, normalized TEXT NOT NULL, quality TEXT NOT NULL,
          field_map TEXT NOT NULL, shape TEXT NOT NULL, drift TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS registry (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        for key, value in {"active": BASE_VERSION, "rollback": "", "approved_by": "", "approved_at": ""}.items():
            db.execute("INSERT OR IGNORE INTO registry VALUES (?, ?)", (key, value))


initialize()
app = FastAPI(title="LogProof local API", version="0.1.0")
allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
allowed_origins.extend(
    origin.strip().rstrip("/")
    for origin in os.environ.get("LOGPROOF_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


def registry() -> dict[str, str]:
    with connect() as db:
        return {row["key"]: row["value"] for row in db.execute("SELECT * FROM registry")}


def set_registry(**values: str) -> None:
    with LOCK, connect() as db:
        for key, value in values.items():
            db.execute("INSERT OR REPLACE INTO registry VALUES (?, ?)", (key, value))


def shape_of(value: Any, prefix: str = "") -> dict[str, str]:
    if not isinstance(value, dict):
        return {prefix or "$": type(value).__name__}
    result: dict[str, str] = {}
    for key in sorted(value):
        path = f"{prefix}.{key}" if prefix else key
        child = value[key]
        result[path] = "object" if isinstance(child, dict) else "array" if isinstance(child, list) else type(child).__name__
        if isinstance(child, dict):
            result.update(shape_of(child, path))
    return result


def source_value(raw: bytes, key: str, value: Any) -> dict[str, Any]:
    needle = json.dumps(key).encode("utf-8")
    start = raw.find(needle)
    if start < 0:
        needle = str(value).encode("utf-8")
        start = raw.find(needle)
    end = start + len(needle) if start >= 0 else None
    return {"source_key": key, "byte_start": start if start >= 0 else None,
            "byte_end": end, "transform": "direct extraction", "confidence": 1.0}


def pack_dir(version: str) -> Path:
    if version not in (BASE_VERSION, CANDIDATE_VERSION):
        raise ValueError("Unknown parser version")
    return ROOT / "parsers" / PARSER_ID / version


def pack_checksum(version: str) -> str:
    digest = hashlib.sha256()
    for name in PACK_FILES:
        digest.update(name.encode())
        digest.update((pack_dir(version) / name).read_bytes())
    return digest.hexdigest()


def pack_valid(version: str) -> bool:
    try:
        return (pack_dir(version) / "checksum.sha256").read_text(encoding="utf-8").strip() == pack_checksum(version)
    except OSError:
        return False


def parse(raw: bytes, source: str, version: str) -> tuple[dict[str, Any], dict[str, Any], list[str], dict[str, str]]:
    text = raw.decode("utf-8", errors="replace")
    errors: list[str] = []
    fields: dict[str, Any] = {}
    mapping: dict[str, Any] = {}
    event: dict[str, Any] = {}
    if source in ("paloalto_firewall", "windows_security", "json_application"):
        try:
            event = json.loads(text)
            if not isinstance(event, dict):
                raise ValueError("Expected an object")
        except (json.JSONDecodeError, ValueError):
            return fields, mapping, ["malformed_json"], {}
        keys = {
            "paloalto_firewall": {"event_time": "timestamp", "action": "action", "src.ip": "src_ip", "dst.ip": "dst_ip", "rule": "rule"},
            "windows_security": {"event_time": "TimeCreated", "action": "EventID", "user.id": "TargetUserName"},
            "json_application": {"event_time": "timestamp", "action": "message", "user.id": "user"},
        }[source]
        for normalized_key, source_key in keys.items():
            if source_key not in event:
                errors.append(f"missing:{source_key}")
                continue
            value = event[source_key]
            if source == "paloalto_firewall" and source_key == "rule":
                rules = json.loads((pack_dir(version) / "rules.yaml").read_text(encoding="utf-8"))
                if isinstance(value, dict) and rules["rule_path"] == "rule.name" and isinstance(value.get("name"), str):
                    source_key = "rule.name"
                    value = value["name"]
                elif not isinstance(value, str):
                    errors.append("invalid_type:rule expected string")
                    continue
            fields[normalized_key] = value
            mapping[normalized_key] = source_value(raw, source_key, value)
        if source == "paloalto_firewall" and "event_time" in fields:
            stamp = fields["event_time"]
            if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
                errors.append("invalid_timestamp_pattern")
        if source == "paloalto_firewall":
            fields["category"] = "network_activity"
            if "severity" in event:
                fields["severity"] = event["severity"]
                mapping["severity"] = source_value(raw, "severity", event["severity"])
    elif source == "cisco_router":
        match = re.search(r"(?P<timestamp>\w+ +\d+ \d\d:\d\d:\d\d).*?%\w+-(?P<severity>\d)-\w+: (?P<action>.*)", text)
        if not match:
            errors.append("syslog_pattern_mismatch")
        else:
            try:
                parsed_time = datetime.strptime(f"{datetime.now(timezone.utc).year} {match['timestamp']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                event_time = parsed_time.isoformat().replace("+00:00", "Z")
            except ValueError:
                event_time = match["timestamp"]
                errors.append("invalid_timestamp_pattern")
            fields.update(category="network_activity", action=match["action"], severity=int(match["severity"]), event_time=event_time)
            mapping = {k: source_value(raw, k, v) for k, v in fields.items() if k != "category"}
            mapping["event_time"] = source_value(raw, "timestamp", match["timestamp"])
            mapping["event_time"]["transform"] = "RFC3164 time + receipt year to UTC"
    elif source == "nginx_access":
        match = re.match(r'(?P<ip>\S+) .*?\[(?P<timestamp>[^]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d+)', text)
        if not match:
            errors.append("access_pattern_mismatch")
        else:
            try:
                parsed_time = datetime.strptime(match["timestamp"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
                event_time = parsed_time.isoformat().replace("+00:00", "Z")
            except ValueError:
                event_time = match["timestamp"]
                errors.append("invalid_timestamp_pattern")
            fields.update(category="web_activity", action=f'{match["method"]} {match["path"]}', **{"src.ip": match["ip"], "severity": 2 if int(match["status"]) >= 400 else 1, "event_time": event_time})
            mapping = {k: source_value(raw, k, v) for k, v in fields.items() if k != "category"}
            mapping["event_time"] = source_value(raw, "timestamp", match["timestamp"])
            mapping["event_time"]["transform"] = "combined-log time to UTC"
    return fields, mapping, errors, shape_of(event) if event else {"$": "str"}


def baseline_shape() -> dict[str, str]:
    return shape_of({"timestamp": "", "action": "", "src_ip": "", "dst_ip": "", "rule": "", "severity": 1})


def drift_for(source: str, shape: dict[str, str], version: str) -> list[str]:
    if source != "paloalto_firewall":
        return []
    base = baseline_shape()
    if version == CANDIDATE_VERSION and shape.get("rule") == "object" and shape.get("rule.name") == "str":
        base.pop("rule")
        base.update({"rule": "object", "rule.name": "str", "rule.revision": "int"})
    changes = [f"type:{key} {old}→{shape[key]}" for key, old in base.items() if key in shape and old != shape[key]]
    changes += [f"missing:{key}" for key in base if key not in shape]
    changes += [f"new:{key}" for key in shape if key not in base]
    return changes


def ingest_bytes(source: str, raw: bytes) -> dict[str, Any]:
    if source not in SOURCES:
        raise HTTPException(404, "Unknown source")
    if not raw or len(raw) > 256_000:
        raise HTTPException(400, "Raw event must be 1 to 256000 bytes")
    with LOCK:
        receipt = f"rcpt_{uuid.uuid4().hex[:16]}"
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        path = RAW / f"{receipt}.bin"
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        received = now()
        version = registry()["active"] if source == "paloalto_firewall" else "1.0.0"
        try:
            fields, mapping, errors, shape = parse(raw, source, version)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            fields, mapping, shape = {}, {}, {}
            errors = ["parser_unavailable" if isinstance(exc, OSError) else "parser_failure"]
        drift = drift_for(source, shape, version)
        if "invalid_timestamp_pattern" in errors:
            drift.append("timestamp:pattern_changed")
        required = ["event_time", "action"] + (["rule"] if source == "paloalto_firewall" else [])
        missing = [key for key in required if key not in fields]
        status = "quarantined" if errors or missing else "accepted"
        normalized = {"event_id": event_id, "receipt_id": receipt, "source_id": source, "received_at": received,
                      "event_time": fields.get("event_time"), "schema": {"name": "logproof-canonical", "version": "1.0"},
                      "category": fields.get("category", "system_activity"), "action": fields.get("action"),
                      "severity": fields.get("severity"), "src": {"ip": fields.get("src.ip"), "port": None},
                      "dst": {"ip": fields.get("dst.ip"), "port": None}, "user": {"id": fields.get("user.id")},
                      "rule": fields.get("rule")}
        quality = {"status": status, "confidence": round(len(required) - len(missing), 2) / len(required),
                   "missing_required_fields": missing, "validation_errors": errors, "drift_detected": bool(drift)}
        normalized["evidence"] = {"raw_path": str(path.relative_to(DATA)), "sha256": digest,
                                  "parser_id": PARSER_ID if source == "paloalto_firewall" else source,
                                  "parser_version": version, "field_map": mapping}
        normalized["quality"] = quality
        with connect() as db:
            db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (event_id, receipt, source, received, str(path.relative_to(DATA)), digest, version,
                        json.dumps(normalized), json.dumps(quality), json.dumps(mapping), json.dumps(shape), json.dumps(drift)))
        return get_event(event_id)


def row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    item = {key: row[key] for key in ("event_id", "receipt_id", "source_id", "received_at", "raw_path", "sha256", "parser_version")}
    for key in ("normalized", "quality", "field_map", "shape", "drift"):
        item[key] = json.loads(row[key])
    item["raw_format"] = SOURCES[item["source_id"]][1]
    return item


def get_event(event_id: str) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Event not found")
    return row_to_event(row)


def sample(source: str, sequence: int, drift: bool = False) -> bytes:
    stamp = "2026-09-24T12:34:56Z"
    if source == "paloalto_firewall":
        obj = {"timestamp": stamp, "action": "allow", "src_ip": f"10.24.8.{(sequence % 200) + 10}", "dst_ip": "172.16.4.20",
               "rule": {"name": "allow-web", "revision": 2} if drift else "allow-web", "severity": 2}
        return json.dumps(obj, separators=(",", ":")).encode()
    if source == "cisco_router":
        return b"Sep 24 12:34:56 edge-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1 changed state to up"
    if source == "nginx_access":
        return b'203.0.113.14 - - [24/Sep/2026:12:34:56 +0000] "GET /api/health HTTP/1.1" 200 52'
    if source == "windows_security":
        return json.dumps({"TimeCreated": stamp, "EventID": "4624", "TargetUserName": "analyst"}, separators=(",", ":")).encode()
    return json.dumps({"timestamp": stamp, "message": "Job completed", "user": "scheduler"}, separators=(",", ":")).encode()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local"}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    with connect() as db:
        counts = {r["quality"]: r["count"] for r in db.execute("SELECT json_extract(quality,'$.status') AS quality, count(*) AS count FROM events GROUP BY quality")}
        drifts = db.execute("SELECT count(*) FROM events WHERE drift!='[]'").fetchone()[0]
    return {"accepted": counts.get("accepted", 0), "quarantined": counts.get("quarantined", 0),
            "drift_alerts": drifts, "sources": [{"id": key, "name": value[0], "format": value[1], "enabled": ENABLED[key], "rate": RATES[key]} for key, value in SOURCES.items()],
            "registry": registry(), "simulator_running": bool(WORKER and WORKER.is_alive())}


@app.post("/api/ingest/{source_id}")
async def ingest(source_id: str, request: Request) -> dict[str, Any]:
    return ingest_bytes(source_id, await request.body())


@app.get("/api/events")
def events(limit: int = 60) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (max(1, min(limit, 250)),)).fetchall()
    return [row_to_event(row) for row in rows]


@app.get("/api/events/{event_id}")
def event(event_id: str) -> dict[str, Any]:
    return get_event(event_id)


@app.get("/api/evidence/{receipt_id}")
def evidence(receipt_id: str) -> dict[str, Any]:
    started = time.perf_counter()
    with connect() as db:
        row = db.execute("SELECT * FROM events WHERE receipt_id=?", (receipt_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Receipt not found")
    raw = (DATA / row["raw_path"]).read_bytes()
    return {"receipt_id": receipt_id, "raw_path": row["raw_path"], "raw_text": raw.decode("utf-8", errors="replace"),
            "raw_hex": raw.hex(), "sha256": row["sha256"], "hash_verified": hashlib.sha256(raw).hexdigest() == row["sha256"],
            "parser_version": row["parser_version"], "field_map": json.loads(row["field_map"]),
            "retrieval_time_ms": round((time.perf_counter() - started) * 1000, 2)}


@app.get("/api/quarantine")
def quarantine() -> list[dict[str, Any]]:
    return [item for item in events(250) if item["quality"]["status"] == "quarantined"]


@app.get("/api/drift")
def drift() -> list[dict[str, Any]]:
    return [item for item in events(250) if item["drift"]]


@app.post("/api/simulator/scenario/{scenario_id}")
def scenario(scenario_id: str) -> dict[str, Any]:
    if scenario_id == "baseline":
        created = [ingest_bytes(source, sample(source, index)) for index, source in enumerate(SOURCES)]
    elif scenario_id == "mapping-failure":
        created = [ingest_bytes("paloalto_firewall", sample("paloalto_firewall", 7, True))]
    elif scenario_id == "malformed":
        created = [ingest_bytes("paloalto_firewall", b'{"timestamp":"2026-09-24T12:34:56Z","rule":')]
    elif scenario_id == "reset":
        STOP.set()
        if WORKER and WORKER.is_alive():
            WORKER.join(timeout=3)
        with LOCK, connect() as db:
            db.execute("DELETE FROM events")
            for path in RAW.glob("rcpt_*.bin"):
                path.unlink()
        set_registry(active=BASE_VERSION, rollback="", approved_by="", approved_at="")
        created = [ingest_bytes(source, sample(source, index)) for index, source in enumerate(SOURCES)]
    else:
        raise HTTPException(404, "Unknown scenario")
    return {"scenario": scenario_id, "events": created}


class SourceControl(BaseModel):
    source_id: str | None = None
    rate: int = Field(default=1, ge=1, le=5)


def generator() -> None:
    counter = 0
    while not STOP.wait(1):
        for source in SOURCES:
            if ENABLED[source]:
                for _ in range(RATES[source]):
                    ingest_bytes(source, sample(source, counter))
                    counter += 1


@app.post("/api/simulator/start")
def start() -> dict[str, bool]:
    global WORKER
    if not WORKER or not WORKER.is_alive():
        STOP.clear()
        WORKER = threading.Thread(target=generator, daemon=True)
        WORKER.start()
    return {"running": True}


@app.post("/api/simulator/stop")
def stop() -> dict[str, bool]:
    STOP.set()
    return {"running": False}


@app.post("/api/simulator/source")
def source_control(control: SourceControl) -> dict[str, Any]:
    if control.source_id not in SOURCES:
        raise HTTPException(404, "Unknown source")
    RATES[control.source_id] = control.rate
    ENABLED[control.source_id] = True
    return {"source_id": control.source_id, "rate": control.rate, "enabled": True}


@app.post("/api/simulator/source/{source_id}/pause")
def pause_source(source_id: str) -> dict[str, Any]:
    if source_id not in SOURCES:
        raise HTTPException(404, "Unknown source")
    ENABLED[source_id] = False
    return {"source_id": source_id, "enabled": False}


@app.post("/api/simulator/source/{source_id}/emit")
def emit_one(source_id: str) -> dict[str, Any]:
    if source_id not in SOURCES:
        raise HTTPException(404, "Unknown source")
    return ingest_bytes(source_id, sample(source_id, int(time.time()) % 200))


def replay_result() -> dict[str, Any]:
    started = time.perf_counter()
    golden_lines = (pack_dir(CANDIDATE_VERSION) / "golden_samples.jsonl").read_text(encoding="utf-8").splitlines()
    expected = [json.loads(line) for line in (pack_dir(CANDIDATE_VERSION) / "expected_outputs.jsonl").read_text(encoding="utf-8").splitlines()]
    corpus = [line.encode("utf-8") for line in golden_lines]
    with connect() as db:
        for row in db.execute("SELECT raw_path FROM events WHERE source_id=? ORDER BY rowid DESC LIMIT 20", ("paloalto_firewall",)):
            raw = (DATA / row["raw_path"]).read_bytes()
            if raw not in corpus:
                corpus.append(raw)
    diffs = []
    old_pass = candidate_pass = 0
    regressions = 0
    for index, raw in enumerate(corpus):
        old, _, old_errors, _ = parse(raw, "paloalto_firewall", BASE_VERSION)
        new, _, new_errors, _ = parse(raw, "paloalto_firewall", CANDIDATE_VERSION)
        old_ok = not old_errors and all(key in old for key in ("event_time", "action", "rule"))
        new_ok = not new_errors and all(key in new for key in ("event_time", "action", "rule"))
        old_pass += int(old_ok)
        candidate_pass += int(new_ok)
        regressions += int(old_ok and not new_ok)
        if old.get("rule") != new.get("rule"):
            diffs.append({"sample": index + 1, "field": "rule", "old": old.get("rule"), "candidate": new.get("rule"), "result": "mapping restored" if new.get("rule") else "unresolved"})
    golden = []
    for raw, target in zip(corpus[:len(expected)], expected):
        actual, _, errors, _ = parse(raw, "paloalto_firewall", CANDIDATE_VERSION)
        golden.append(not errors and all(actual.get(key) == value for key, value in target.items()))
    return {"old_parser": BASE_VERSION, "candidate_parser": CANDIDATE_VERSION, "corpus_size": len(corpus),
            "old_pass": old_pass, "candidate_pass": candidate_pass, "golden_passed": sum(golden), "golden_total": len(golden),
            "regressions": regressions, "old_coverage": round(old_pass / len(corpus) * 100),
            "candidate_coverage": round(candidate_pass / len(corpus) * 100),
            "duration_ms": round((time.perf_counter() - started) * 1000, 2), "diffs": diffs,
            "promotion_ready": all(golden) and len(golden) == len(expected) == len(golden_lines) and regressions == 0 and candidate_pass == len(corpus) and bool(diffs) and pack_valid(CANDIDATE_VERSION)}


@app.post("/api/replay")
def replay() -> dict[str, Any]:
    return replay_result()


@app.get("/api/parser/registry")
def parser_registry() -> dict[str, Any]:
    state = registry()
    packs = []
    for version in (BASE_VERSION, CANDIDATE_VERSION):
        path = pack_dir(version) / "manifest.yaml"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        checksum = pack_checksum(version)
        packs.append({**manifest, "checksum": checksum, "checksum_valid": pack_valid(version), "status": "active" if state["active"] == version else "candidate" if version == CANDIDATE_VERSION and state["active"] != version else "rollback"})
    return {"packs": packs, "state": state}


class Approval(BaseModel):
    approved_by: str = Field(min_length=2, max_length=80)


@app.post("/api/parser/approve")
def approve(approval: Approval) -> dict[str, Any]:
    if len(approval.approved_by.strip()) < 2:
        raise HTTPException(400, "Approver name must contain at least two characters")
    if registry()["active"] == CANDIDATE_VERSION:
        raise HTTPException(409, "Candidate parser is already active")
    result = replay_result()
    if not result["promotion_ready"]:
        raise HTTPException(409, "Replay gates have not passed")
    previous = registry()["active"]
    set_registry(active=CANDIDATE_VERSION, rollback=previous, approved_by=approval.approved_by.strip(), approved_at=now())
    return parser_registry()


@app.post("/api/parser/rollback")
def rollback() -> dict[str, Any]:
    state = registry()
    if not state["rollback"]:
        raise HTTPException(409, "No rollback version available")
    set_registry(active=state["rollback"], rollback="", approved_by="", approved_at=now())
    return parser_registry()


with connect() as _seed_db:
    _needs_seed = _seed_db.execute("SELECT count(*) FROM events").fetchone()[0] == 0
if _needs_seed:
    scenario("baseline")
