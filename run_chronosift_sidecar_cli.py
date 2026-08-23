#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import warnings
from pathlib import Path

import chronoSIFT_v2_31 as chronosift_module
from chronoSIFT_v2_31 import ChronoSiftEngine
from summarize_chronosift_telemetry import summarize_telemetry_files, write_summary


def build_arg_parser() -> argparse.ArgumentParser:
    # The runner stays intentionally thin: the engine owns pipeline semantics,
    # while this CLI standardises reproducible invocation and artifact naming.
    p = argparse.ArgumentParser(description="Run ChronoSift against a parquet base dataset and write full or sidecar output.")
    p.add_argument("dataset_root", help="Input parquet dataset root")
    p.add_argument("output_root", help="Output parquet dataset root")
    p.add_argument("--rules-yaml", default="rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml")
    p.add_argument("--weights-yaml", default="rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml")
    p.add_argument("--overlap", default="24h")
    p.add_argument("--output-mode", default="sidecar", choices=["full", "sidecar"])
    p.add_argument("--reports-json", default=None, help="Optional path for the run reports JSON")
    p.add_argument("--telemetry-jsonl", default=None, help="Optional path for JSONL stage telemetry")
    p.add_argument("--telemetry-summary-json", default=None, help="Optional path for telemetry summary JSON")
    p.add_argument("--profile-manifest-path", default=None, help="Optional reusable profile manifest path")
    p.add_argument("--file-hit-manifest-path", default=None, help="Optional reusable referenced-file manifest path")
    p.add_argument(
        "--yara-metadata-path",
        default=None,
        help="Run-specific override for detector_policy YARA metadata.path",
    )
    p.add_argument("--geoip-city-db", default=None, help="Optional MaxMind GeoLite2 City .mmdb")
    p.add_argument("--geoip-asn-db", default=None, help="Optional MaxMind GeoLite2 ASN .mmdb")
    p.add_argument("--av-csv-path", default=None, help="Optional hash-keyed ClamAV results CSV")
    p.add_argument("--luhn-csv-path", default=None, help="Optional hash-keyed Luhn results CSV")
    p.add_argument("--nsrl-parquet-path", default=None, help="Optional locally prepared NSRL Parquet lookup")
    p.add_argument(
        "--retain-zero-weight-lifecycle-signals",
        action="store_true",
        help="Retain generic file_created/file_modified/file_deleted payloads even when their configured weight is zero",
    )
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    return p


def _artifact_prefix(output_root: str) -> Path:
    path = Path(output_root)
    if path.suffix.lower() == ".parquet":
        return path.with_suffix("")
    return path


def _default_artifact_paths(args: argparse.Namespace) -> dict[str, str]:
    # Deriving companion artifacts from output_root keeps reruns reproducible
    # and lets callers reuse manifests without separately managing file names.
    prefix = _artifact_prefix(args.output_root)
    return {
        "reports_json": str(prefix.with_name(prefix.name + ".reports.json")),
        "telemetry_jsonl": str(prefix.with_name(prefix.name + ".telemetry.jsonl")),
        "telemetry_summary_json": str(prefix.with_name(prefix.name + ".telemetry.summary.json")),
        "profile_manifest_path": str(prefix.with_name(prefix.name + ".profile_manifest.json")),
        "file_hit_manifest_path": str(prefix.with_name(prefix.name + ".file_hit_manifest.json")),
    }


def _write_telemetry_summary(telemetry_jsonl: str, out_json: str, top: int = 10) -> None:
    # Use the same implementation as the standalone corpus summariser so a
    # normal run and a later batch aggregate report identical profile fields.
    write_summary(summarize_telemetry_files([telemetry_jsonl], top=top), out_json)


def _is_compiled_chronosift_module() -> bool:
    # The compiled Cython module can trigger pandas' Copy-on-Write /
    # chained-assignment FutureWarning heuristics even when the equivalent
    # pure-Python engine emits no warning and the dataframe mutation is valid.
    # Keep the compiled-path detection in one place so the runner can suppress
    # only that known false-positive warning family at the boundary.
    module_path = str(getattr(chronosift_module, "__file__", ""))
    return module_path.endswith(".so")


def main() -> int:
    args = build_arg_parser().parse_args()
    logging.getLogger().setLevel(getattr(logging, str(args.log_level).upper()))
    defaults = _default_artifact_paths(args)
    reports_json = args.reports_json or defaults["reports_json"]
    telemetry_jsonl = args.telemetry_jsonl or defaults["telemetry_jsonl"]
    telemetry_summary_json = args.telemetry_summary_json or defaults["telemetry_summary_json"]
    profile_manifest_path = args.profile_manifest_path or defaults["profile_manifest_path"]
    file_hit_manifest_path = args.file_hit_manifest_path or defaults["file_hit_manifest_path"]

    # Treat the rules and weights YAML as benchmark provenance: changing them
    # changes the engine behaviour even if the code and dataset stay constant.
    engine = ChronoSiftEngine.from_yaml(
        args.rules_yaml,
        args.weights_yaml,
        yara_metadata_path=args.yara_metadata_path,
    )
    if _is_compiled_chronosift_module():
        with warnings.catch_warnings():
            # This suppression is intentionally narrow. We still want all other
            # FutureWarnings to surface. The conditional exists because this
            # specific pandas warning has been observed as a Cython-only false
            # positive: compiled-path runs can warn while the same pure-Python
            # execution path stays clean, so we suppress it only when loading
            # the compiled `.so`.
            warnings.filterwarnings(
                "ignore",
                message=r".*ChainedAssignmentError: behaviour will change in pandas 3\.0!.*",
                category=FutureWarning,
            )
            reports = engine.process_parquet_dataset_partitioned(
                args.dataset_root,
                args.output_root,
                overlap=args.overlap,
                materialise_event_columns=True,
                materialise_explain_columns=True,
                geoip_city_db=args.geoip_city_db,
                geoip_asn_db=args.geoip_asn_db,
                av_csv_path=args.av_csv_path,
                luhn_csv_path=args.luhn_csv_path,
                nsrl_parquet_path=args.nsrl_parquet_path,
                output_mode=args.output_mode,
                profile_manifest_path=profile_manifest_path,
                file_hit_manifest_path=file_hit_manifest_path,
                telemetry_jsonl_path=telemetry_jsonl,
                retain_zero_weight_lifecycle_signals=args.retain_zero_weight_lifecycle_signals,
            )
    else:
        reports = engine.process_parquet_dataset_partitioned(
            args.dataset_root,
            args.output_root,
            overlap=args.overlap,
            materialise_event_columns=True,
            materialise_explain_columns=True,
            geoip_city_db=args.geoip_city_db,
            geoip_asn_db=args.geoip_asn_db,
            av_csv_path=args.av_csv_path,
            luhn_csv_path=args.luhn_csv_path,
            nsrl_parquet_path=args.nsrl_parquet_path,
            output_mode=args.output_mode,
            profile_manifest_path=profile_manifest_path,
            file_hit_manifest_path=file_hit_manifest_path,
            telemetry_jsonl_path=telemetry_jsonl,
            retain_zero_weight_lifecycle_signals=args.retain_zero_weight_lifecycle_signals,
        )

    reports_path = Path(reports_json)
    reports_path.parent.mkdir(parents=True, exist_ok=True)
    reports_path.write_text(json.dumps(reports, indent=2, default=str), encoding="utf-8")

    if telemetry_jsonl:
        _write_telemetry_summary(telemetry_jsonl, telemetry_summary_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
