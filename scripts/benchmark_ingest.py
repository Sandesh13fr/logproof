"""Run a bounded, single-process raw-ingest benchmark in temporary storage."""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) * fraction + 0.999999)) - 1))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=1000, help="Events to process (1–5000; default: 1000)")
    args = parser.parse_args()
    if not 1 <= args.count <= 5000:
        parser.error("--count must be between 1 and 5000")

    with tempfile.TemporaryDirectory(prefix="logproof-benchmark-") as directory:
        os.environ["LOGPROOF_DATA"] = directory
        from backend.main import SOURCES, connect, ingest_bytes, sample

        source_ids = list(SOURCES)
        with connect() as db:
            persisted_before = db.execute("SELECT count(*) FROM events").fetchone()[0]
        latencies_ms: list[float] = []
        raw_bytes = 0
        started = time.perf_counter()
        for index in range(args.count):
            source = source_ids[index % len(source_ids)]
            raw = sample(source, index)
            event_started = time.perf_counter_ns()
            ingest_bytes(source, raw)
            latencies_ms.append((time.perf_counter_ns() - event_started) / 1_000_000)
            raw_bytes += len(raw)
        elapsed_seconds = time.perf_counter() - started
        with connect() as db:
            persisted_after = db.execute("SELECT count(*) FROM events").fetchone()[0]

        print(json.dumps({
            "workload": "bounded synchronous raw ingest; parse, hash, raw-file write, SQLite receipt write",
            "events_requested": args.count,
            "events_persisted": persisted_after - persisted_before,
            "seed_events_present_during_run": persisted_before,
            "source_families": len(source_ids),
            "source_ids": source_ids,
            "raw_bytes": raw_bytes,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "events_per_second": round(args.count / elapsed_seconds, 2),
            "event_latency_ms": {
                "median": round(statistics.median(latencies_ms), 3),
                "p95": round(percentile(latencies_ms, 0.95), 3),
                "max": round(max(latencies_ms), 3),
            },
            "storage": "temporary local filesystem and SQLite database",
            "execution": "single process, sequential, no HTTP, no concurrency",
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "interpretation": "Local microbenchmark only; not a production capacity or multi-node scale claim.",
        }, indent=2))


if __name__ == "__main__":
    main()
