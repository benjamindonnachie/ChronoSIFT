#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Summarize ChronoSift JSONL telemetry.")
    p.add_argument("telemetry_jsonl", help="Path to telemetry JSONL emitted by run_chronosift_sidecar_cli.py")
    p.add_argument("--top", type=int, default=10, help="How many top partitions to report, default: 10")
    p.add_argument("--json-out", default=None, help="Optional path to save the summary as JSON")
    return p


def load_events(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def main() -> int:
    args = build_arg_parser().parse_args()
    events = load_events(args.telemetry_jsonl)
    stage_end = [e for e in events if e.get("event") == "stage_end"]

    by_stage: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "total_s": 0.0,
        "max_s": 0.0,
        "max_rss_mb": 0.0,
        "worst_partition": None,
    })
    by_partition_stage: Dict[Tuple[int, int], Dict[str, float]] = defaultdict(dict)
    peak_rss_mb = 0.0

    for e in stage_end:
        stage = str(e.get("stage"))
        duration_s = float(e.get("duration_s") or 0.0)
        rss_mb = float(e.get("rss_mb") or 0.0)
        peak_rss_mb = max(peak_rss_mb, rss_mb)

        rec = by_stage[stage]
        rec["count"] += 1
        rec["total_s"] += duration_s
        rec["max_s"] = max(rec["max_s"], duration_s)
        rec["max_rss_mb"] = max(rec["max_rss_mb"], rss_mb)

        year = e.get("year")
        month = e.get("month")
        if year is not None and month is not None:
            part_key = (int(year), int(month))
            by_partition_stage[part_key][stage] = duration_s
            if rec["worst_partition"] is None or duration_s > float(rec["worst_partition"]["duration_s"]):
                rec["worst_partition"] = {
                    "year": int(year),
                    "month": int(month),
                    "duration_s": duration_s,
                    "rss_mb": rss_mb,
                }

    top_partitions = []
    for (year, month), stages in by_partition_stage.items():
        total_s = float(sum(stages.values()))
        top_partitions.append({
            "year": year,
            "month": month,
            "total_stage_s": total_s,
            "atomic_stage_s": float(stages.get("atomic_stage", 0.0)),
            "load_partition_window_s": float(stages.get("load_partition_window", 0.0)),
            "contextual_non_temporal_stage_s": float(stages.get("contextual_non_temporal_stage", 0.0)),
            "contextual_temporal_stage_s": float(stages.get("contextual_temporal_stage", 0.0)),
            "write_output_partition_s": float(stages.get("write_output_partition", 0.0)),
            "prepare_output_partition_s": float(stages.get("prepare_output_partition", 0.0)),
        })
    top_partitions.sort(key=lambda x: x["total_stage_s"], reverse=True)

    summary = {
        "events": len(events),
        "stage_end_events": len(stage_end),
        "peak_rss_mb": peak_rss_mb,
        "stages": {
            stage: {
                "count": rec["count"],
                "total_s": round(float(rec["total_s"]), 6),
                "max_s": round(float(rec["max_s"]), 6),
                "max_rss_mb": round(float(rec["max_rss_mb"]), 2),
                "worst_partition": rec["worst_partition"],
            }
            for stage, rec in sorted(by_stage.items(), key=lambda kv: kv[1]["total_s"], reverse=True)
        },
        "top_partitions": top_partitions[: args.top],
    }

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
