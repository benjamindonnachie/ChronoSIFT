#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any, Dict, List, Optional, Sequence, Tuple


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Summarize one ChronoSift telemetry stream or aggregate amplifier "
            "engagement across a corpus of streams."
        )
    )
    p.add_argument(
        "telemetry_jsonl",
        nargs="+",
        help=(
            "One or more JSONL telemetry paths emitted by "
            "run_chronosift_sidecar_cli.py"
        ),
    )
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


def _optional_int(value: Any, *, field: str, source: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{source}: {field} must be an integer, not a boolean")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source}: {field} must be an integer") from exc


def _optional_float(value: Any, *, field: str, source: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{source}: {field} must be numeric, not a boolean")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source}: {field} must be numeric") from exc


def _numeric_summary(values: Sequence[int]) -> Dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "minimum": None,
            "maximum": None,
            "mean": None,
            "median": None,
        }
    numeric = [int(value) for value in values]
    return {
        "count": len(numeric),
        "minimum": min(numeric),
        "maximum": max(numeric),
        "mean": round(float(sum(numeric)) / len(numeric), 6),
        "median": float(median(numeric)),
    }


def _profile_record(path: str, events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    profile_events = [event for event in events if event.get("event") == "profile_validation"]
    if len(profile_events) > 1:
        raise ValueError(
            f"{path}: expected at most one profile_validation event, found {len(profile_events)}"
        )

    run_start = next(
        (event for event in events if event.get("event") == "run_start"),
        {},
    )
    record: Dict[str, Any] = {
        "telemetry_jsonl": path,
        "dataset_root": run_start.get("dataset_root"),
        "run_complete": any(event.get("event") == "run_end" for event in events),
        "profile_validation_present": bool(profile_events),
    }
    if not profile_events:
        record.update({
            "selection_mode": None,
            "accepted": None,
            "reason": None,
            "source_event_count": None,
            "selected_event_count": None,
            "complete_week_count": None,
            "amplifiable_hour_count": None,
            "simultaneous_upper_radius": None,
            "engaged": None,
            "engagement_reason": "profile_validation_missing",
        })
        return record

    event = profile_events[0]
    accepted_value = event.get("accepted")
    if accepted_value is not None and not isinstance(accepted_value, bool):
        raise ValueError(f"{path}: accepted must be a JSON boolean")
    accepted = accepted_value if isinstance(accepted_value, bool) else None
    amplifiable_hour_count = _optional_int(
        event.get("amplifiable_hour_count"),
        field="amplifiable_hour_count",
        source=path,
    )

    engaged: Optional[bool]
    engagement_reason: str
    if accepted is None or amplifiable_hour_count is None:
        engaged = None
        engagement_reason = (
            "accepted_missing"
            if accepted is None
            else "amplifiable_hour_count_missing"
        )
    else:
        engaged = bool(accepted and amplifiable_hour_count > 0)
        emitted_engaged = event.get("engaged")
        if emitted_engaged is not None:
            if not isinstance(emitted_engaged, bool):
                raise ValueError(f"{path}: engaged must be a JSON boolean")
            if emitted_engaged != engaged:
                raise ValueError(
                    f"{path}: engaged is inconsistent with accepted and "
                    "amplifiable_hour_count"
                )
        if engaged:
            engagement_reason = "engaged"
        elif not accepted:
            engagement_reason = str(event.get("reason") or "rejected_without_reason")
        else:
            engagement_reason = "accepted_without_amplifiable_hours"

    record.update({
        "selection_mode": event.get("selection_mode"),
        "accepted": accepted,
        "reason": event.get("reason"),
        "source_event_count": _optional_int(
            event.get("source_event_count"),
            field="source_event_count",
            source=path,
        ),
        "selected_event_count": _optional_int(
            event.get("selected_event_count"),
            field="selected_event_count",
            source=path,
        ),
        "complete_week_count": _optional_int(
            event.get("complete_week_count"),
            field="complete_week_count",
            source=path,
        ),
        "amplifiable_hour_count": amplifiable_hour_count,
        "simultaneous_upper_radius": _optional_float(
            event.get("simultaneous_upper_radius"),
            field="simultaneous_upper_radius",
            source=path,
        ),
        "engaged": engaged,
        "engagement_reason": engagement_reason,
    })
    return record


def _amplifier_engagement_summary(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    profiles = [record for record in records if record["profile_validation_present"]]
    complete = [record for record in records if record["run_complete"]]
    known = [
        record
        for record in profiles
        if record["run_complete"] and record["engaged"] is not None
    ]
    engaged = [record for record in known if record["engaged"]]
    not_engaged = [record for record in known if not record["engaged"]]
    unknown = [
        record
        for record in records
        if not (
            record["run_complete"]
            and record["profile_validation_present"]
            and record["engaged"] is not None
        )
    ]

    selection_modes = Counter(
        str(record.get("selection_mode") or "unspecified") for record in known
    )
    reasons = Counter(str(record.get("reason") or "unspecified") for record in known)
    non_engagement_reasons = Counter(
        str(record["engagement_reason"]) for record in not_engaged
    )
    unknown_reasons = Counter(
        "run_incomplete"
        if not record["run_complete"]
        else str(record["engagement_reason"])
        for record in unknown
    )

    complete_weeks = [
        int(record["complete_week_count"])
        for record in known
        if record["complete_week_count"] is not None
    ]
    amplifiable_hours = [
        int(record["amplifiable_hour_count"])
        for record in known
        if record["amplifiable_hour_count"] is not None
    ]
    accepted_count = sum(record.get("accepted") is True for record in known)
    rejected_count = sum(record.get("accepted") is False for record in known)
    known_count = len(known)

    return {
        "corpus_run_count": len(records),
        "complete_run_count": len(complete),
        "incomplete_run_count": len(records) - len(complete),
        "profile_validation_record_count": len(profiles),
        "profile_validation_missing_count": len(records) - len(profiles),
        "engagement_known_count": known_count,
        "engagement_unknown_count": len(records) - known_count,
        "engaged_count": len(engaged),
        "not_engaged_count": len(not_engaged),
        "engagement_rate": (
            round(float(len(engaged)) / known_count, 6) if known_count else None
        ),
        "engagement_rate_denominator": known_count,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "acceptance_unknown_count": known_count - accepted_count - rejected_count,
        "selection_mode_counts": dict(sorted(selection_modes.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "non_engagement_reason_counts": dict(sorted(non_engagement_reasons.items())),
        "unknown_engagement_reason_counts": dict(sorted(unknown_reasons.items())),
        "complete_week_count": _numeric_summary(complete_weeks),
        "amplifiable_hour_count": _numeric_summary(amplifiable_hours),
        "runs": list(records),
    }


def summarize_telemetry_files(paths: Sequence[str], top: int = 10) -> Dict[str, Any]:
    if not paths:
        raise ValueError("At least one telemetry JSONL path is required")
    if top < 1:
        raise ValueError("top must be at least 1")

    resolved_paths = sorted(str(Path(path).resolve()) for path in paths)
    if len(set(resolved_paths)) != len(resolved_paths):
        raise ValueError("Telemetry JSONL paths must be unique")

    events: List[Dict[str, Any]] = []
    profile_records: List[Dict[str, Any]] = []
    for path in resolved_paths:
        file_events = load_events(path)
        run_start = next(
            (event for event in file_events if event.get("event") == "run_start"),
            {},
        )
        dataset_root = run_start.get("dataset_root")
        for event in file_events:
            tagged = dict(event)
            tagged["_telemetry_jsonl"] = path
            tagged["_dataset_root"] = dataset_root
            events.append(tagged)
        profile_records.append(_profile_record(path, file_events))

    stage_end = [event for event in events if event.get("event") == "stage_end"]

    by_stage: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "total_s": 0.0,
        "max_s": 0.0,
        "max_rss_mb": 0.0,
        "worst_partition": None,
    })
    by_partition_stage: Dict[Tuple[str, int, int], Dict[str, float]] = defaultdict(dict)
    partition_dataset_roots: Dict[Tuple[str, int, int], Any] = {}
    peak_rss_mb = 0.0

    for event in stage_end:
        stage = str(event.get("stage"))
        duration_s = float(event.get("duration_s") or 0.0)
        rss_mb = float(event.get("rss_mb") or 0.0)
        peak_rss_mb = max(peak_rss_mb, rss_mb)

        rec = by_stage[stage]
        rec["count"] += 1
        rec["total_s"] += duration_s
        rec["max_s"] = max(rec["max_s"], duration_s)
        rec["max_rss_mb"] = max(rec["max_rss_mb"], rss_mb)

        year = event.get("year")
        month = event.get("month")
        if year is not None and month is not None:
            telemetry_jsonl = str(event["_telemetry_jsonl"])
            part_key = (telemetry_jsonl, int(year), int(month))
            by_partition_stage[part_key][stage] = duration_s
            partition_dataset_roots[part_key] = event.get("_dataset_root")
            if (
                rec["worst_partition"] is None
                or duration_s > float(rec["worst_partition"]["duration_s"])
            ):
                rec["worst_partition"] = {
                    "telemetry_jsonl": telemetry_jsonl,
                    "dataset_root": event.get("_dataset_root"),
                    "year": int(year),
                    "month": int(month),
                    "duration_s": duration_s,
                    "rss_mb": rss_mb,
                }

    top_partitions = []
    for (telemetry_jsonl, year, month), stages in by_partition_stage.items():
        total_s = float(sum(stages.values()))
        top_partitions.append({
            "telemetry_jsonl": telemetry_jsonl,
            "dataset_root": partition_dataset_roots[(telemetry_jsonl, year, month)],
            "year": year,
            "month": month,
            "total_stage_s": total_s,
            "atomic_stage_s": float(stages.get("atomic_stage", 0.0)),
            "load_partition_window_s": float(stages.get("load_partition_window", 0.0)),
            "contextual_non_temporal_stage_s": float(
                stages.get("contextual_non_temporal_stage", 0.0)
            ),
            "contextual_temporal_stage_s": float(
                stages.get("contextual_temporal_stage", 0.0)
            ),
            "write_output_partition_s": float(stages.get("write_output_partition", 0.0)),
            "prepare_output_partition_s": float(stages.get("prepare_output_partition", 0.0)),
        })
    top_partitions.sort(
        key=lambda value: (
            -float(value["total_stage_s"]),
            str(value["telemetry_jsonl"]),
            int(value["year"]),
            int(value["month"]),
        )
    )

    return {
        "telemetry_file_count": len(resolved_paths),
        "telemetry_files": resolved_paths,
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
            for stage, rec in sorted(
                by_stage.items(),
                key=lambda item: (-float(item[1]["total_s"]), item[0]),
            )
        },
        "top_partitions": top_partitions[:top],
        "amplifier_engagement": _amplifier_engagement_summary(profile_records),
    }


def write_summary(summary: Dict[str, Any], path: str) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        summary = summarize_telemetry_files(args.telemetry_jsonl, top=args.top)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.json_out:
        write_summary(summary, args.json_out)
    else:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
