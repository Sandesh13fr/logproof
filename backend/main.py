"""Local LogProof demonstration API. Raw bytes are committed before parsing."""

from __future__ import annotations

import hashlib
import csv
import base64
import binascii
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DEMO = os.environ.get("LOGPROOF_PUBLIC_DEMO", "").lower() in ("1", "true", "yes")
MAX_PUBLIC_EVENTS = 1000
DATA = Path(os.environ.get("LOGPROOF_DATA", ROOT / "data")).resolve()
if PUBLIC_DEMO:
    DATA = DATA / "public-demo"
RAW = DATA / "raw"
DB = DATA / "logproof.sqlite3"
RAW.mkdir(parents=True, exist_ok=True)
SOURCES = {
    "paloalto_firewall": ("Firewall", "JSON"),
    "cisco_router": ("Cisco router", "Syslog"),
    "syslog_rfc5424": ("Syslog event", "Syslog · RFC 5424"),
    "cef_security": ("CEF security event", "CEF · ArcSight format"),
    "nginx_access": ("NGINX access", "Combined log"),
    "windows_security": ("Windows security", "JSON"),
    "windows_event_xml": ("Windows Event", "Windows Event XML"),
    "json_application": ("Application", "JSON"),
    "csv_network": ("Network flow", "CSV"),
    "leef_security": ("Security device", "LEEF"),
}
MAX_EVENT_BYTES = 256_000
MAX_BATCH_BYTES = 2_000_000
MAX_BATCH_EVENTS = 100
PARSER_ID = "paloalto-traffic"
BASE_VERSION = "1.4.2"
CANDIDATE_VERSION = "1.4.3"
PACK_FILES = ("manifest.yaml", "rules.yaml", "golden_samples.jsonl", "expected_outputs.jsonl")
WITFOO_SOURCE = "witfoo_soc"
WITFOO_DATASET = "witfoo/precinct6-cybersecurity-100m"
WITFOO_DATASET_URL = "https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m"
LOCK = threading.RLock()
STOP = threading.Event()
WORKER: threading.Thread | None = None
RATES = {source: 1 for source in SOURCES}
ENABLED = {source: True for source in SOURCES}
IST = timezone(timedelta(hours=5, minutes=30))


def now() -> str:
    return datetime.now(IST).isoformat(timespec="seconds")


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
        CREATE TABLE IF NOT EXISTS dataset_imports (
          artifact_id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, row_index INTEGER NOT NULL
        );
        """)
        for key, value in {"active": BASE_VERSION, "rollback": "", "approved_by": "", "approved_at": ""}.items():
            db.execute("INSERT OR IGNORE INTO registry VALUES (?, ?)", (key, value))


initialize()
app = FastAPI(title="LogProof local API", version="0.1.0")


@app.middleware("http")
async def public_demo_guard(request: Request, call_next: Any) -> Any:
    if PUBLIC_DEMO and request.method == "POST" and (
        request.url.path.startswith("/api/ingest/")
        or request.url.path in (
            "/api/datasets/witfoo/import", "/api/parser/approve", "/api/parser/rollback"
        )
    ):
        return JSONResponse(status_code=403, content={"detail": "This public demo accepts synthetic simulator events only"})
    return await call_next(request)
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://logproof.younix.xyz",
    "https://logproof.vercel.app",
    "https://logproof-sandeshs-projects-4c5434f4.vercel.app",
]
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
        start = raw.find(key.encode("utf-8"))
        if start >= 0:
            needle = key.encode("utf-8")
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


def parse(raw: bytes, source: str, version: str, source_context: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any], list[str], dict[str, str]]:
    text = raw.decode("utf-8", errors="replace")
    errors: list[str] = []
    fields: dict[str, Any] = {}
    mapping: dict[str, Any] = {}
    event: dict[str, Any] = {}
    if source == "csv_network":
        try:
            reader = csv.DictReader(io.StringIO(text, newline=""))
            rows = list(reader)
            if not reader.fieldnames or len(rows) != 1:
                raise ValueError("CSV event must contain a header and exactly one data row")
            event = {str(key or "").strip(): value for key, value in rows[0].items() if key}
            aliases = {re.sub(r"[^a-z0-9]", "", key.casefold()): key for key in event}
            def csv_value(*names: str) -> tuple[str | None, Any]:
                for name in names:
                    source_key = aliases.get(re.sub(r"[^a-z0-9]", "", name.casefold()))
                    if source_key is not None and event[source_key] not in (None, ""):
                        return source_key, event[source_key]
                return None, None
            for output, candidates in {
                "event_time": ("timestamp", "event_time", "time", "starttime"),
                "action": ("action", "event", "message", "protocol"),
                "src.ip": ("src_ip", "src", "source_ip", "source"),
                "dst.ip": ("dst_ip", "dst", "destination_ip", "destination"),
                "src.port": ("src_port", "source_port"), "dst.port": ("dst_port", "destination_port"),
                "protocol": ("protocol", "proto"), "severity": ("severity", "sev"),
            }.items():
                source_key, value = csv_value(*candidates)
                if source_key is None:
                    continue
                if output in ("src.port", "dst.port", "severity"):
                    try:
                        value = int(value)
                    except (TypeError, ValueError):
                        errors.append(f"invalid_type:{source_key}")
                        continue
                if output == "event_time":
                    try:
                        value = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    except (TypeError, ValueError):
                        errors.append("invalid_timestamp_pattern")
                        continue
                fields[output] = value
                mapping[output] = source_value(raw, source_key, value)
                if output == "event_time":
                    mapping[output]["transform"] = "CSV timestamp normalized to UTC"
            fields["category"] = "network_activity"
        except (csv.Error, ValueError):
            errors.append("malformed_csv_event")
    elif source == "leef_security":
        leef_start = text.find("LEEF:")
        text = text[leef_start:] if leef_start >= 0 else text
        header_version = text[5:].split("|", 1)[0] if text.startswith("LEEF:") else ""
        version_number = header_version.split(".", 1)[0]
        maxsplit = 6 if version_number == "2" else 5
        parts = re.split(r"(?<!\\)\|", text, maxsplit=maxsplit)
        expected_parts = 7 if version_number == "2" else 6
        if not text.startswith("LEEF:") or len(parts) != expected_parts or version_number not in ("1", "2"):
            errors.append("leef_pattern_mismatch")
        else:
            if version_number == "2":
                # LEEF 2.0 adds a delimiter token before the extension.
                header = parts[:5]
                delimiter_value, extension = parts[5], parts[6]
            else:
                header = parts[:5]
                delimiter_value = "\t"
                extension = parts[5]
            if not errors:
                delimiter_aliases = {"\\t": "\t", "tab": "\t"}
                delimiter = delimiter_aliases.get(delimiter_value.casefold(), delimiter_value)
                hex_delimiter = re.fullmatch(r"(?:0x|x)([0-9a-f]{1,4})", delimiter_value, re.IGNORECASE)
                if hex_delimiter:
                    try:
                        delimiter = chr(int(hex_delimiter.group(1), 16))
                    except (ValueError, OverflowError):
                        errors.append("invalid_leef_delimiter")
                attrs: dict[str, str] = {}
                for token in extension.split(delimiter):
                    if "=" in token:
                        key, value = token.split("=", 1)
                        attrs[key.strip()] = value.strip()
                event = {"leef_version": header[0], "vendor": header[1], "product": header[2],
                         "device_version": header[3], "event_id": header[4], "attributes": attrs}
                timestamp = attrs.get("devTime") or attrs.get("rt")
                if timestamp:
                    try:
                        if timestamp.isdigit():
                            timestamp_value = int(timestamp)
                            unit = (attrs.get("devTimeFormat") or "").casefold()
                            seconds = timestamp_value if unit in ("epoch", "seconds", "unix") or timestamp_value < 10_000_000_000 else timestamp_value / 1000
                            event_time = datetime.fromtimestamp(seconds, timezone.utc)
                        else:
                            event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
                        fields["event_time"] = event_time.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    except (OverflowError, OSError, TypeError, ValueError):
                        errors.append("invalid_timestamp_pattern")
                else:
                    errors.append("missing:devTime")
                event_id = header[4] if len(header) > 4 else ""
                action = attrs.get("action") or attrs.get("cat") or attrs.get("name") or event_id
                fields.update(category="security_event", action=action, event_code=event_id,
                              device_vendor=header[1], device_product=header[2])
                aliases = {"src.ip": ("src", "srcIp"), "dst.ip": ("dst", "dstIp"),
                           "src.port": ("srcPort",), "dst.port": ("dstPort",),
                           "protocol": ("proto", "protocol"), "severity": ("sev", "severity")}
                for output, candidates in aliases.items():
                    key = next((candidate for candidate in candidates if attrs.get(candidate) not in (None, "")), None)
                    if key is None:
                        continue
                    value: Any = attrs[key]
                    if output in ("src.port", "dst.port", "severity"):
                        try:
                            value = int(value)
                        except ValueError:
                            errors.append(f"invalid_type:{key}")
                            continue
                    fields[output] = value
                    mapping[output] = source_value(raw, f"{key}=", value)
                fields["action"] = action
                for output, key, value in (("event_time", "devTime" if attrs.get("devTime") else "rt", timestamp),
                                           ("action", next((k for k in ("action", "cat", "name") if attrs.get(k)), ""), action)):
                    if output in fields and key:
                        mapping[output] = source_value(raw, f"{key}=", value)
                mapping["event_code"] = source_value(raw, event_id, event_id)
                if "event_time" in mapping:
                    mapping["event_time"]["transform"] = "LEEF device time normalized to UTC"
    elif source in ("paloalto_firewall", "windows_security", "json_application"):
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
            try:
                if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", stamp):
                    raise ValueError("timestamp needs an explicit timezone")
                fields["event_time"] = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                mapping["event_time"]["transform"] = "Firewall timestamp normalized to UTC"
            except ValueError:
                errors.append("invalid_timestamp_pattern")
        elif source in ("windows_security", "json_application") and "event_time" in fields:
            try:
                stamp = datetime.fromisoformat(str(fields["event_time"]).replace("Z", "+00:00"))
                fields["event_time"] = stamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                mapping["event_time"]["transform"] = "Source timestamp normalized to UTC"
            except ValueError:
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
                parsed_time = datetime.strptime(f"{datetime.now(IST).year} {match['timestamp']}", "%Y %b %d %H:%M:%S").replace(tzinfo=IST)
                event_time = parsed_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except ValueError:
                event_time = match["timestamp"]
                errors.append("invalid_timestamp_pattern")
            fields.update(category="network_activity", action=match["action"], severity=int(match["severity"]), event_time=event_time)
            mapping = {k: source_value(raw, k, v) for k, v in fields.items() if k != "category"}
            mapping["event_time"] = source_value(raw, "timestamp", match["timestamp"])
            mapping["event_time"]["transform"] = "RFC3164 time assumed IST + receipt year to UTC"
    elif source == "syslog_rfc5424":
        match = re.match(
            r"<(?P<pri>\d{1,3})>1 (?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<sd>(?:\[[^\]]*\]|-))(?: (?P<message>.*))?",
            text,
        )
        if not match or int(match["pri"]) > 191:
            errors.append("syslog_rfc5424_pattern_mismatch")
        else:
            timestamp = match["timestamp"]
            try:
                parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                fields["event_time"] = parsed_time.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            except (TypeError, ValueError):
                errors.append("invalid_timestamp_pattern")
            severity = int(match["pri"]) % 8
            fields.update(
                category="system_activity", action=(match["message"] or match["msgid"] or match["app"]),
                severity=severity, facility=int(match["pri"]) // 8, host=match["host"],
                application=match["app"], process_id=match["procid"], event_code=match["msgid"],
            )
            mapping = {key: source_value(raw, match_key, value) for key, match_key, value in (
                ("action", "message", fields["action"]), ("severity", "pri", severity),
                ("facility", "pri", fields["facility"]), ("host", "host", match["host"]),
                ("application", "app", match["app"]), ("event_code", "msgid", match["msgid"]),
            )}
            if "event_time" in fields:
                mapping["event_time"] = source_value(raw, "timestamp", timestamp)
                mapping["event_time"]["transform"] = "RFC 5424 timestamp normalized to UTC"
    elif source == "cef_security":
        parts = re.split(r"(?<!\\)\|", text, maxsplit=7)
        if len(parts) != 8 or not parts[0].startswith("CEF:"):
            errors.append("cef_pattern_mismatch")
        else:
            header = [part.replace("\\|", "|").replace("\\\\", "\\") for part in parts[:7]]
            version = header[0][4:]
            extension = {
                key: value[1:-1] if value.startswith('"') and value.endswith('"') else value
                for key, value in re.findall(r'(?:^|\s)([A-Za-z][A-Za-z0-9]*)=("(?:\\.|[^"])*"|\S*)', parts[7])
            }
            name = header[5]
            fields.update(category="security_event", action=extension.get("act") or name,
                          event_code=header[4], device_vendor=header[1], device_product=header[2],
                          device=extension.get("dvc"), protocol=extension.get("proto"),
                          source_host=extension.get("shost"), destination_host=extension.get("dhost"))
            for key, source_key, cast in (
                ("src.ip", "src", str), ("dst.ip", "dst", str), ("src.port", "spt", int),
                ("dst.port", "dpt", int), ("severity", "severity", int),
            ):
                value = extension.get(source_key, header[6] if source_key == "severity" else None)
                if value not in (None, ""):
                    try:
                        fields[key] = cast(value)
                    except (TypeError, ValueError):
                        errors.append(f"invalid_type:{source_key}")
            event_time = extension.get("rt")
            if event_time:
                try:
                    if event_time.isdigit():
                        fields["event_time"] = datetime.fromtimestamp(int(event_time) / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    else:
                        fields["event_time"] = datetime.fromisoformat(event_time.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                except (OverflowError, OSError, TypeError, ValueError):
                    errors.append("invalid_timestamp_pattern")
            else:
                errors.append("missing:rt")
            for key, source_key in (("action", "act"), ("src.ip", "src"), ("dst.ip", "dst"),
                                    ("src.port", "spt"), ("dst.port", "dpt"), ("protocol", "proto"),
                                    ("event_time", "rt"), ("severity", "severity")):
                if key in fields:
                    value = extension.get(source_key, header[6] if source_key == "severity" else fields[key])
                    mapping[key] = source_value(raw, f"{source_key}=", value)
            mapping["event_code"] = source_value(raw, header[4], header[4])
            if "event_time" in mapping:
                mapping["event_time"]["transform"] = "CEF receipt time normalized to UTC"
    elif source == "windows_event_xml":
        try:
            root = ET.fromstring(text)
            def xml_name(element: ET.Element) -> str:
                return element.tag.rsplit("}", 1)[-1]
            system = next((element for element in root.iter() if xml_name(element) == "System"), None)
            if system is None:
                raise ValueError("missing System element")
            system_values: dict[str, str] = {}
            for element in system.iter():
                name = xml_name(element)
                if name == "TimeCreated":
                    system_values["event_time"] = element.attrib.get("SystemTime", "")
                elif name == "Provider":
                    system_values["provider"] = element.attrib.get("Name", "")
                elif name == "EventID":
                    system_values["event_code"] = (element.text or "").strip()
                elif name == "Level":
                    system_values["severity"] = (element.text or "").strip()
                elif name == "Computer":
                    system_values["host"] = (element.text or "").strip()
                elif name == "Channel":
                    system_values["channel"] = (element.text or "").strip()
            event_data = next((element for element in root.iter() if xml_name(element) == "EventData"), None)
            data_values = {
                element.attrib.get("Name", ""): (element.text or "").strip()
                for element in event_data.iter() if xml_name(element) == "Data"
            } if event_data is not None else {}
            event_code = system_values.get("event_code", "")
            user_name = data_values.get("TargetUserName") or data_values.get("SubjectUserName")
            source_ip = data_values.get("IpAddress") or data_values.get("SourceAddress")
            if event_code:
                fields["event_code"] = event_code
            fields.update(category="identity_activity" if user_name else "security_event",
                          action=f"Windows Event ID {event_code}" if event_code else "Windows security event",
                          provider=system_values.get("provider"), host=system_values.get("host"),
                          channel=system_values.get("channel"))
            if system_values.get("severity"):
                fields["severity"] = int(system_values["severity"])
            if user_name:
                fields["user.id"] = user_name
            if source_ip and source_ip not in ("-", "::1"):
                fields["src.ip"] = source_ip
            if system_values.get("event_time"):
                timestamp = system_values["event_time"]
                fields["event_time"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            else:
                errors.append("missing:TimeCreated/SystemTime")
            for key, source_key in (("event_time", system_values.get("event_time")),
                                    ("event_code", event_code), ("provider", system_values.get("provider")),
                                    ("host", system_values.get("host")), ("channel", system_values.get("channel")),
                                    ("user.id", user_name), ("src.ip", source_ip),
                                    ("severity", system_values.get("severity"))):
                if key in fields and source_key:
                    mapping[key] = source_value(raw, source_key, source_key)
                    mapping[key]["source_key"] = f"WindowsEvent.{key}"
            if "event_time" in mapping:
                mapping["event_time"]["transform"] = "Windows Event SystemTime normalized to UTC"
        except (ET.ParseError, ValueError, TypeError, OverflowError):
            errors.append("malformed_windows_event_xml")
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
    elif source == WITFOO_SOURCE:
        context = source_context or {}
        try:
            event_timestamp = context.get("event_time")
            timestamp_source = "event_time"
            if event_timestamp is None:
                event_timestamp = context.get("timestamp")
                timestamp_source = "timestamp"
            if event_timestamp is not None:
                if isinstance(event_timestamp, (int, float)):
                    fields["event_time"] = datetime.fromtimestamp(float(event_timestamp), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                else:
                    parsed = datetime.fromisoformat(str(event_timestamp).replace("Z", "+00:00"))
                    fields["event_time"] = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                mapping["event_time"] = {"source_key": f"WitFoo.{timestamp_source}", "byte_start": None, "byte_end": None,
                                         "transform": "source event time → ISO 8601 UTC" if timestamp_source == "event_time" else "artifact ingest time → ISO 8601 UTC (source event time unavailable)",
                                         "confidence": 1.0 if timestamp_source == "event_time" else 0.85}
            else:
                errors.append("missing:timestamp")
        except (OverflowError, OSError, TypeError, ValueError):
            errors.append("invalid_timestamp")

        message_type = str(context.get("message_type") or "").casefold()
        category = "identity_activity" if any(token in message_type for token in ("auth", "logon", "login", "pam", "user")) else \
            "network_activity" if any(token in message_type for token in ("network", "firewall", "flow", "connection", "access_log", "management")) else \
            "system_activity" if any(token in message_type for token in ("system", "process", "service", "diagnostic", "file")) else "security_event"
        fields["category"] = category
        mapping["category"] = {"source_key": "WitFoo.message_type", "byte_start": None, "byte_end": None,
                                "transform": "event type → LogProof category", "confidence": 0.9}

        message_match = re.search(
            r"(?:%[A-Z0-9_-]+-\d+-[A-Z0-9_-]+:\s*|(?:sshd|systemd|CROND|sudo|pam_unix)(?:\[[^]]+\])?:\s*|(?:<\d+>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z]{2,5})?\s+\S+\s+[^:]+:\s*)(?P<message>.*)$",
            text,
            re.IGNORECASE,
        )
        action = context.get("action") or (message_match.group("message").strip() if message_match else text.strip())
        if action:
            fields["action"] = str(action)
            mapping["action"] = source_value(raw, "message_sanitized", action)
            mapping["action"]["transform"] = "extracted event message from sanitized source log"

        context_fields = {"src.ip": "src_ip", "dst.ip": "dst_ip", "src.port": "src_port", "dst.port": "dst_port",
                          "protocol": "protocol", "src.host": "src_host", "dst.host": "dst_host", "user.id": "username",
                          "severity": "severity", "vendor_code": "vendor_code"}
        for normalized_key, source_key in context_fields.items():
            value = context.get(source_key)
            if value not in (None, ""):
                fields[normalized_key] = value
                mapping[normalized_key] = source_value(raw, source_key, value)
                mapping[normalized_key]["source_key"] = f"WitFoo.{source_key}"
                if mapping[normalized_key]["byte_start"] is None:
                    mapping[normalized_key]["transform"] = "retained from publisher's structured event context"
        fields["source_event_type"] = context.get("message_type")
        fields["source_stream"] = context.get("stream_name")
        fields["source_label"] = context.get("label_binary")
        mapping["source_label"] = {"source_key": "WitFoo.label_binary", "byte_start": None, "byte_end": None,
                                   "transform": "publisher-provided machine-derived label; retained as context", "confidence": 1.0}
    return fields, mapping, errors, shape_of(event) if event else {"$": "str"}


def parser_evaluation_result() -> dict[str, Any]:
    """Evaluate parsers against hand-authored local fixtures without storing events."""
    started = time.perf_counter()
    fixture_path = ROOT / "backend" / "fixtures" / "parser_evaluation.jsonl"
    fixtures = [json.loads(line) for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    active_firewall_version = registry()["active"]
    required_fields = {
        source: ["event_time", "action"] + (["rule"] if source == "paloalto_firewall" else [])
        for source in SOURCES
    }
    per_source: dict[str, dict[str, Any]] = {}
    totals = {key: 0 for key in ("tp", "fp", "fn", "quarantine_tp", "quarantine_fp", "quarantine_fn", "passed", "cases", "fields_expected")}

    def fresh_scores() -> dict[str, int]:
        return {key: 0 for key in ("tp", "fp", "fn", "quarantine_tp", "quarantine_fp", "quarantine_fn", "passed", "cases", "fields_expected")}

    def ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 1.0

    for fixture in fixtures:
        source = fixture["source_id"]
        scores = per_source.setdefault(source, fresh_scores())
        version = active_firewall_version if source == "paloalto_firewall" else "1.0.0"
        expected = fixture.get("expected_fields", {})
        ignored = set(fixture.get("ignored_fields", []))
        expected = {key: value for key, value in expected.items() if key not in ignored}
        actual_fields, _, errors, _ = parse(fixture["raw"].encode("utf-8"), source, version)
        actual = {key: value for key, value in actual_fields.items() if key not in ignored and value is not None}
        expected_quarantine = bool(fixture["expected_quarantine"])
        missing = [key for key in required_fields[source] if key not in actual_fields]
        predicted_quarantine = bool(errors or missing)
        case_passed = predicted_quarantine == expected_quarantine

        if expected_quarantine:
            if predicted_quarantine:
                scores["quarantine_tp"] += 1
            else:
                scores["quarantine_fn"] += 1
        elif predicted_quarantine:
            scores["quarantine_fp"] += 1
        for key, expected_value in expected.items():
            scores["fields_expected"] += 1
            if key in actual and actual[key] == expected_value:
                scores["tp"] += 1
            else:
                scores["fn"] += 1
                case_passed = False
                if key in actual:
                    scores["fp"] += 1
        for key in actual.keys() - expected.keys():
            scores["fp"] += 1
            case_passed = False
        scores["cases"] += 1
        scores["passed"] += int(case_passed)

    for source, scores in per_source.items():
        for key in totals:
            totals[key] += scores[key]

    def metrics(scores: dict[str, int]) -> dict[str, Any]:
        precision = ratio(scores["tp"], scores["tp"] + scores["fp"])
        recall = ratio(scores["tp"], scores["tp"] + scores["fn"])
        quarantine_precision = ratio(scores["quarantine_tp"], scores["quarantine_tp"] + scores["quarantine_fp"])
        quarantine_recall = ratio(scores["quarantine_tp"], scores["quarantine_tp"] + scores["quarantine_fn"])
        return {
            **scores,
            "field_precision": precision,
            "field_recall": recall,
            "field_f1": ratio(2 * precision * recall, precision + recall),
            "quarantine_precision": quarantine_precision,
            "quarantine_recall": quarantine_recall,
            "quarantine_f1": ratio(2 * quarantine_precision * quarantine_recall, quarantine_precision + quarantine_recall),
            "fixture_pass_rate": ratio(scores["passed"], scores["cases"]),
        }

    return {
        "evaluation_type": "curated_synthetic_golden_fixtures",
        "scope_note": "Fixture scores are deterministic checks of these examples, not estimates of production accuracy or source coverage.",
        "active_firewall_parser": active_firewall_version,
        "source_count": len(per_source),
        "case_count": totals["cases"],
        "field_count": totals["fields_expected"],
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "overall": metrics(totals),
        "sources": [
            {"source_id": source, "display_name": SOURCES[source][0],
             "parser_version": active_firewall_version if source == "paloalto_firewall" else "1.0.0",
             **metrics(scores)}
            for source, scores in per_source.items()
        ],
    }


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


def ingest_bytes(source: str, raw: bytes, source_context: dict[str, Any] | None = None) -> dict[str, Any]:
    if source not in SOURCES and source != WITFOO_SOURCE:
        raise HTTPException(404, "Unknown source")
    if not raw or len(raw) > MAX_EVENT_BYTES:
        raise HTTPException(400, "Raw event must be 1 to 256000 bytes")
    with LOCK:
        if PUBLIC_DEMO:
            with connect() as db:
                if db.execute("SELECT count(*) FROM events").fetchone()[0] >= MAX_PUBLIC_EVENTS:
                    raise HTTPException(429, "Public demo event limit reached; reset the demo to continue")
        receipt = f"rcpt_{uuid.uuid4().hex[:16]}"
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        path = RAW / f"{receipt}.bin"
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        received = now()
        version = registry()["active"] if source == "paloalto_firewall" else "1.0.0"
        try:
            fields, mapping, errors, shape = parse(raw, source, version, source_context)
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
        "severity": fields.get("severity"),
        "src": {"ip": fields.get("src.ip"), "port": fields.get("src.port"), "host": fields.get("src.host")},
        "dst": {"ip": fields.get("dst.ip"), "port": fields.get("dst.port"), "host": fields.get("dst.host")},
        "user": {"id": fields.get("user.id")}, "rule": fields.get("rule"),
        "protocol": fields.get("protocol"), "event_code": fields.get("event_code"),
        "source_host": fields.get("host"), "application": fields.get("application"),
        "provider": fields.get("provider"), "channel": fields.get("channel"),
        "facility": fields.get("facility")}
        if source == WITFOO_SOURCE:
            normalized["category"] = fields.get("category", "security_event")
            normalized["src"] = {"ip": fields.get("src.ip"), "port": fields.get("src.port"), "host": fields.get("src.host")}
            normalized["dst"] = {"ip": fields.get("dst.ip"), "port": fields.get("dst.port"), "host": fields.get("dst.host")}
            normalized["user"] = {"id": fields.get("user.id")}
            normalized["protocol"] = fields.get("protocol")
            normalized["source_event_type"] = fields.get("source_event_type")
            normalized["source_stream"] = fields.get("source_stream")
            normalized["source_label"] = fields.get("source_label")
            normalized["source_context"] = {
                key: value for key, value in (source_context or {}).items()
                if value not in (None, "")
            }
        quality = {"status": status, "confidence": round(len(required) - len(missing), 2) / len(required),
                   "missing_required_fields": missing, "validation_errors": errors, "drift_detected": bool(drift)}
        normalized["evidence"] = {"raw_path": str(path.relative_to(DATA)), "sha256": digest,
                                  "parser_id": PARSER_ID if source == "paloalto_firewall" else source,
                                  "parser_version": version, "field_map": mapping}
        if source == WITFOO_SOURCE and source_context:
            normalized["evidence"]["dataset"] = {
                "name": WITFOO_DATASET, "url": WITFOO_DATASET_URL, "license": "Apache-2.0",
                "artifact_id": source_context.get("artifact_id"), "row_index": source_context.get("row_index"),
                "organization": source_context.get("org_id"), "pipeline": source_context.get("pipeline"),
                "label_note": "Publisher-provided machine-derived label; not analyst-confirmed ground truth.",
            }
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
    item["raw_format"] = "WitFoo sanitized syslog" if item["source_id"] == WITFOO_SOURCE else SOURCES[item["source_id"]][1]
    return item


def get_event(event_id: str) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Event not found")
    return row_to_event(row)


def sample(source: str, sequence: int, drift: bool = False) -> bytes:
    generated_at = datetime.now(IST)
    stamp = generated_at.isoformat(timespec="seconds")
    if source == "paloalto_firewall":
        obj = {"timestamp": stamp, "action": "allow", "src_ip": f"10.24.8.{(sequence % 200) + 10}", "dst_ip": "172.16.4.20",
               "rule": {"name": "allow-web", "revision": 2} if drift else "allow-web", "severity": 2}
        return json.dumps(obj, separators=(",", ":")).encode()
    if source == "cisco_router":
        return f"{generated_at:%b %d %H:%M:%S} edge-01 %LINK-3-UPDOWN: Interface GigabitEthernet0/1 changed state to up".encode()
    if source == "syslog_rfc5424":
        return f'<165>1 {generated_at.isoformat(timespec="milliseconds")} edge-01 sshd 1842 AUTH_SUCCESS [origin ip="192.0.2.44" software="sshd"] Accepted publickey for analyst'.encode()
    if source == "cef_security":
        stamp_ms = int(generated_at.timestamp() * 1000)
        return f"CEF:0|Palo Alto Networks|PAN-OS|11.1|THREAT|Suspicious connection|8|rt={stamp_ms} src=198.51.100.23 dst=203.0.113.40 spt=51642 dpt=443 proto=TCP act=deny msg=Blocked outbound connection".encode()
    if source == "nginx_access":
        return f'203.0.113.14 - - [{generated_at:%d/%b/%Y:%H:%M:%S %z}] "GET /api/health HTTP/1.1" 200 52'.encode()
    if source == "windows_security":
        return json.dumps({"TimeCreated": stamp, "EventID": "4624", "TargetUserName": "analyst"}, separators=(",", ":")).encode()
    if source == "windows_event_xml":
        return (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
            f'<Level>4</Level><TimeCreated SystemTime="{generated_at.isoformat(timespec="milliseconds")}"/>'
            '<Channel>Security</Channel><Computer>WORKSTATION-07</Computer></System>'
            '<EventData><Data Name="TargetUserName">analyst</Data>'
            '<Data Name="IpAddress">198.51.100.23</Data></EventData></Event>'
        ).encode()
    if source == "csv_network":
        return (
            "timestamp,action,src_ip,dst_ip,src_port,dst_port,protocol,severity\n"
            f"{stamp},allowed,198.51.100.{(sequence % 100) + 1},203.0.113.10,52340,443,TCP,2\n"
        ).encode()
    if source == "leef_security":
        return (
            "LEEF:2.0|LogProof Labs|Edge Sensor|1.0|BLOCKED_FLOW|^|"
            f"devTime={stamp}^src=198.51.100.23^dst=203.0.113.40^srcPort=51642^dstPort=443^proto=TCP^sev=8^cat=Blocked outbound connection^action=deny"
        ).encode()
    return json.dumps({"timestamp": stamp, "message": "Job completed", "user": "scheduler"}, separators=(",", ":")).encode()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local"}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    with connect() as db:
        counts = {r["status"]: r["count"] for r in db.execute(
            "SELECT json_extract(events.quality,'$.status') AS status, count(*) AS count "
            "FROM events GROUP BY json_extract(events.quality,'$.status')"
        )}
        drifts = db.execute("SELECT count(*) FROM events WHERE drift!='[]'").fetchone()[0]
        dataset_samples = db.execute("SELECT count(*) FROM dataset_imports").fetchone()[0]
    return {"accepted": counts.get("accepted", 0), "quarantined": counts.get("quarantined", 0),
            "drift_alerts": drifts, "sources": [{"id": key, "name": value[0], "format": value[1], "enabled": ENABLED[key], "rate": RATES[key]} for key, value in SOURCES.items()],
            "dataset_samples": dataset_samples,
            "registry": registry(), "simulator_running": bool(WORKER and WORKER.is_alive())}


def import_ndjson(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > MAX_BATCH_BYTES:
        raise HTTPException(413 if len(payload) > MAX_BATCH_BYTES else 400,
                            f"NDJSON batch must be 1 to {MAX_BATCH_BYTES} bytes")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "NDJSON batch must be UTF-8") from exc
    records = [(line_number, line) for line_number, line in enumerate(lines, start=1) if line.strip()]
    if len(records) > MAX_BATCH_EVENTS:
        raise HTTPException(413, f"NDJSON batch is limited to {MAX_BATCH_EVENTS} records")
    items: list[dict[str, Any]] = []
    accepted = quarantined = rejected = 0
    for line_number, line in records:
        try:
            envelope = json.loads(line)
            if not isinstance(envelope, dict):
                raise ValueError("Each line must be a JSON object")
            source_id, raw_text, raw_base64 = envelope.get("source_id"), envelope.get("raw"), envelope.get("raw_base64")
            if not isinstance(source_id, str):
                raise ValueError("Each object needs a string field 'source_id'")
            if isinstance(raw_text, str) and raw_base64 is None:
                raw = raw_text.encode("utf-8")
            elif isinstance(raw_base64, str) and raw_text is None:
                try:
                    raw = base64.b64decode(raw_base64, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError("raw_base64 must be valid base64") from exc
            else:
                raise ValueError("Each object needs exactly one of the string fields 'raw' or 'raw_base64'")
            if not raw or len(raw) > MAX_EVENT_BYTES:
                raise ValueError(f"raw must be 1 to {MAX_EVENT_BYTES} UTF-8 bytes")
            item = ingest_bytes(source_id, raw)
            state = item["quality"]["status"]
            accepted += state == "accepted"
            quarantined += state == "quarantined"
            items.append({"line": line_number, "source_id": source_id, "status": state, "event": item})
        except HTTPException as exc:
            rejected += 1
            items.append({"line": line_number, "status": "rejected", "error": str(exc.detail)})
        except (json.JSONDecodeError, ValueError) as exc:
            rejected += 1
            items.append({"line": line_number, "status": "rejected", "error": str(exc)})
    return {"submitted": len(records), "accepted": accepted, "quarantined": quarantined,
            "rejected": rejected, "items": items}


@app.post("/api/ingest/batch")
async def ingest_batch(request: Request) -> dict[str, Any]:
    declared_length = request.headers.get("content-length")
    if declared_length and declared_length.isdigit() and int(declared_length) > MAX_BATCH_BYTES:
        raise HTTPException(413, f"NDJSON batch is limited to {MAX_BATCH_BYTES} bytes")
    chunks: list[bytes] = []
    byte_count = 0
    async for chunk in request.stream():
        byte_count += len(chunk)
        if byte_count > MAX_BATCH_BYTES:
            raise HTTPException(413, f"NDJSON batch is limited to {MAX_BATCH_BYTES} bytes")
        chunks.append(chunk)
    return import_ndjson(b"".join(chunks))


@app.post("/api/ingest/{source_id}")
async def ingest(source_id: str, request: Request) -> dict[str, Any]:
    declared_length = request.headers.get("content-length")
    if declared_length and declared_length.isdigit() and int(declared_length) > MAX_EVENT_BYTES:
        raise HTTPException(413, f"Raw event is limited to {MAX_EVENT_BYTES} bytes")
    chunks: list[bytes] = []
    byte_count = 0
    async for chunk in request.stream():
        byte_count += len(chunk)
        if byte_count > MAX_EVENT_BYTES:
            raise HTTPException(413, f"Raw event is limited to {MAX_EVENT_BYTES} bytes")
        chunks.append(chunk)
    return ingest_bytes(source_id, b"".join(chunks))


@app.get("/api/events/export.ndjson")
def export_events() -> StreamingResponse:
    def lines() -> Iterator[str]:
        with connect() as db:
            cursor = db.execute("SELECT * FROM events ORDER BY rowid ASC")
            for row in cursor:
                record = row_to_event(row)
                raw = (DATA / row["raw_path"]).read_bytes()
                try:
                    record["raw"] = raw.decode("utf-8")
                except UnicodeDecodeError:
                    record["raw_base64"] = base64.b64encode(raw).decode("ascii")
                yield json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    return StreamingResponse(lines(), media_type="application/x-ndjson",
                             headers={"Content-Disposition": "attachment; filename=logproof-events.ndjson"})


@app.get("/api/datasets/witfoo/status")
def witfoo_status() -> dict[str, Any]:
    with connect() as db:
        imported = db.execute("SELECT count(*) FROM dataset_imports").fetchone()[0]
        next_row = db.execute("SELECT coalesce(max(row_index) + 1, 0) FROM dataset_imports").fetchone()[0]
    return {"dataset": WITFOO_DATASET, "url": WITFOO_DATASET_URL, "license": "Apache-2.0",
            "imported": imported, "next_offset": next_row}


class WitFooImportRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=50)
    offset: int = Field(default=0, ge=0, le=114_421_340)


@app.post("/api/datasets/witfoo/import")
def import_witfoo(request_body: WitFooImportRequest) -> dict[str, Any]:
    query = urllib.parse.urlencode({"dataset": WITFOO_DATASET, "config": "signals", "split": "train",
                                    "offset": request_body.offset, "length": request_body.limit})
    url = f"https://datasets-server.huggingface.co/rows?{query}"
    payload = None
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LogProof-local-demo/1.0"})
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read(8_000_001)
            if len(body) > 8_000_000:
                raise ValueError("Hugging Face sample response exceeded the 8 MB safety limit")
            payload = json.loads(body.decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                break
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            if attempt == 2:
                break
        time.sleep(0.4 * (attempt + 1))

    used_preview_fallback = False
    if payload is None and request_body.offset == 0:
        preview_query = urllib.parse.urlencode({"dataset": WITFOO_DATASET, "config": "signals", "split": "train"})
        preview_url = f"https://datasets-server.huggingface.co/first-rows?{preview_query}"
        try:
            req = urllib.request.Request(preview_url, headers={"User-Agent": "LogProof-local-demo/1.0"})
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read(8_000_001)
            if len(body) > 8_000_000:
                raise ValueError("Hugging Face preview response exceeded the 8 MB safety limit")
            payload = json.loads(body.decode("utf-8"))
            payload["rows"] = payload.get("rows", [])[:request_body.limit]
            used_preview_fallback = True
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
    if payload is None:
        raise HTTPException(502, "Could not reach the public Hugging Face dataset preview. Retry when online.") from last_error

    imported: list[dict[str, Any]] = []
    skipped = 0
    for item in payload.get("rows", []):
        row = item.get("row", {})
        message = row.get("message_sanitized")
        artifact_id = row.get("artifact_id")
        if not isinstance(message, str) or not message.strip() or not isinstance(artifact_id, str):
            skipped += 1
            continue
        with connect() as db:
            existing = db.execute("SELECT receipt_id FROM dataset_imports WHERE artifact_id=?", (artifact_id,)).fetchone()
        if existing:
            skipped += 1
            continue
        context = {key: row.get(key) for key in (
            "timestamp", "event_time", "artifact_id", "org_id", "message_type", "stream_name", "pipeline",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "src_host", "dst_host", "username",
            "action", "severity", "vendor_code", "label_binary", "label_confidence", "attack_techniques", "attack_tactics",
        )}
        context["row_index"] = item.get("row_idx", request_body.offset + len(imported))
        event = ingest_bytes(WITFOO_SOURCE, message.encode("utf-8"), context)
        with LOCK, connect() as db:
            db.execute("INSERT OR IGNORE INTO dataset_imports VALUES (?,?,?)",
                       (artifact_id, event["receipt_id"], int(context["row_index"])))
        imported.append(event)
    return {"dataset": WITFOO_DATASET, "requested": request_body.limit, "offset": request_body.offset,
            "preview_fallback": used_preview_fallback,
            "imported": len(imported), "skipped": skipped, "items": imported}


@app.get("/api/events")
def events(limit: int = 60) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (max(1, min(limit, 250)),)).fetchall()
    return [row_to_event(row) for row in rows]


@app.get("/api/events/page")
def events_page(limit: int = 20, offset: int = 0, q: str = Query(default="", max_length=200)) -> dict[str, Any]:
    page_limit = max(1, min(limit, 100))
    page_offset = max(0, offset)
    search = q.strip()
    clauses: list[str] = []
    params: list[Any] = []
    if search:
        normalized_search = re.sub(r"[^a-z0-9]", "", search.casefold())
        source_ids = [
            source_id
            for source_id, (name, _) in SOURCES.items()
            if search.casefold() in source_id.casefold()
            or search.casefold() in name.casefold()
            or normalized_search
            in re.sub(r"[^a-z0-9]", "", source_id.casefold())
        ]
        if any(term in search.casefold() for term in ("witfoo", "dataset", "soc sample")):
            source_ids.append(WITFOO_SOURCE)
        search_clauses = ["receipt_id LIKE ?"]
        params.append(f"%{search}%")
        if source_ids:
            search_clauses.append(f"source_id IN ({','.join('?' for _ in source_ids)})")
            params.extend(source_ids)
        clauses.append(f"({' OR '.join(search_clauses)})")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as db:
        total = db.execute(f"SELECT count(*) FROM events {where}", params).fetchone()[0]
        rows = db.execute(
            f"SELECT * FROM events {where} ORDER BY rowid DESC LIMIT ? OFFSET ?",
            [*params, page_limit, page_offset],
        ).fetchall()
    return {
        "items": [row_to_event(row) for row in rows],
        "total": total,
        "limit": page_limit,
        "offset": page_offset,
    }


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
        created = [ingest_bytes("paloalto_firewall", f'{{"timestamp":"{now()}","rule":'.encode())]
    elif scenario_id == "reset":
        STOP.set()
        if WORKER and WORKER.is_alive():
            WORKER.join(timeout=3)
        with LOCK, connect() as db:
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM dataset_imports")
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
                    try:
                        ingest_bytes(source, sample(source, counter))
                    except HTTPException as exc:
                        if PUBLIC_DEMO and exc.status_code == 429:
                            STOP.set()
                            return
                        raise
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


@app.get("/api/parser/evaluation")
def parser_evaluation() -> dict[str, Any]:
    return parser_evaluation_result()


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
