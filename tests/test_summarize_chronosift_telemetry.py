"""Tests for single-run and corpus-level ChronoSIFT telemetry summaries."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import summarize_chronosift_telemetry as telemetry


class ChronoSiftTelemetrySummaryTest(unittest.TestCase):
    @staticmethod
    def _write_events(path: Path, events: list[dict[str, object]]) -> None:
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )

    def test_corpus_summary_reports_engagement_and_rejection_causes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            accepted_path = root / "image-a.telemetry.jsonl"
            rejected_path = root / "image-b.telemetry.jsonl"
            self._write_events(accepted_path, [
                {
                    "event": "run_start",
                    "dataset_root": "/evidence/image-a.parquet",
                },
                {
                    "event": "profile_validation",
                    "selection_mode": "filtered",
                    "accepted": True,
                    "reason": "accepted",
                    "source_event_count": 20000,
                    "selected_event_count": 1600,
                    "complete_week_count": 8,
                    "amplifiable_hour_count": 113,
                    "simultaneous_upper_radius": 0.0039,
                },
                {
                    "event": "stage_end",
                    "stage": "atomic_stage",
                    "year": 2024,
                    "month": 1,
                    "duration_s": 2.0,
                    "rss_mb": 120.0,
                },
                {"event": "run_end"},
            ])
            self._write_events(rejected_path, [
                {
                    "event": "run_start",
                    "dataset_root": "/evidence/image-b.parquet",
                },
                {
                    "event": "profile_validation",
                    "selection_mode": "filtered",
                    "accepted": False,
                    "reason": "no_confidently_low_activity_hours",
                    "source_event_count": 2000,
                    "selected_event_count": 200,
                    "complete_week_count": 8,
                    "amplifiable_hour_count": 0,
                    "simultaneous_upper_radius": 0.01018,
                },
                {
                    "event": "stage_end",
                    "stage": "atomic_stage",
                    "year": 2024,
                    "month": 1,
                    "duration_s": 3.0,
                    "rss_mb": 140.0,
                },
                {"event": "run_end"},
            ])

            summary = telemetry.summarize_telemetry_files(
                [str(rejected_path), str(accepted_path)]
            )

        engagement = summary["amplifier_engagement"]
        self.assertEqual(summary["telemetry_file_count"], 2)
        self.assertEqual(
            summary["telemetry_files"],
            ["image-a.telemetry.jsonl", "image-b.telemetry.jsonl"],
        )
        self.assertEqual(engagement["corpus_run_count"], 2)
        self.assertEqual(engagement["complete_run_count"], 2)
        self.assertEqual(engagement["incomplete_run_count"], 0)
        self.assertEqual(engagement["profile_validation_record_count"], 2)
        self.assertEqual(engagement["engaged_count"], 1)
        self.assertEqual(engagement["not_engaged_count"], 1)
        self.assertEqual(engagement["engagement_rate"], 0.5)
        self.assertEqual(engagement["engagement_rate_denominator"], 2)
        self.assertEqual(engagement["selection_mode_counts"], {"filtered": 2})
        self.assertEqual(
            engagement["non_engagement_reason_counts"],
            {"no_confidently_low_activity_hours": 1},
        )
        self.assertEqual(
            engagement["complete_week_count"],
            {
                "count": 2,
                "minimum": 8,
                "maximum": 8,
                "mean": 8.0,
                "median": 8.0,
            },
        )
        self.assertEqual(engagement["amplifiable_hour_count"]["maximum"], 113)
        self.assertEqual(
            [record["dataset_name"] for record in engagement["runs"]],
            ["image-a.parquet", "image-b.parquet"],
        )
        self.assertEqual(len(summary["top_partitions"]), 2)
        self.assertNotEqual(
            summary["top_partitions"][0]["telemetry_file"],
            summary["top_partitions"][1]["telemetry_file"],
        )

    def test_missing_or_legacy_profile_fields_are_unknown_not_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            legacy_path = root / "legacy.telemetry.jsonl"
            incomplete_path = root / "incomplete.telemetry.jsonl"
            missing_path = root / "missing.telemetry.jsonl"
            disabled_path = root / "profiling-disabled.telemetry.jsonl"
            self._write_events(legacy_path, [
                {"event": "run_start", "dataset_root": "/evidence/legacy"},
                {
                    "event": "profile_validation",
                    "selection_mode": "filtered",
                    "accepted": True,
                    "reason": "accepted",
                    "complete_week_count": 7,
                },
                {"event": "run_end"},
            ])
            self._write_events(incomplete_path, [
                {"event": "run_start", "dataset_root": "/evidence/incomplete"},
                {
                    "event": "profile_validation",
                    "selection_mode": "filtered",
                    "accepted": True,
                    "reason": "accepted",
                    "complete_week_count": 10,
                    "amplifiable_hour_count": 120,
                },
            ])
            self._write_events(missing_path, [
                {"event": "run_start", "dataset_root": "/evidence/missing"},
                {"event": "run_end"},
            ])
            self._write_events(disabled_path, [
                {"event": "run_start", "dataset_root": "/evidence/disabled"},
                {
                    "event": "profile_validation",
                    "selection_mode": "disabled",
                    "accepted": False,
                    "reason": "profiling_disabled",
                    "complete_week_count": 0,
                    "amplifiable_hour_count": 0,
                    "engaged": False,
                },
                {"event": "run_end"},
            ])

            summary = telemetry.summarize_telemetry_files(
                [
                    str(legacy_path),
                    str(incomplete_path),
                    str(missing_path),
                    str(disabled_path),
                ]
            )

        engagement = summary["amplifier_engagement"]
        self.assertEqual(engagement["complete_run_count"], 3)
        self.assertEqual(engagement["incomplete_run_count"], 1)
        self.assertEqual(engagement["profile_validation_record_count"], 3)
        self.assertEqual(engagement["profile_validation_missing_count"], 1)
        self.assertEqual(engagement["engagement_known_count"], 1)
        self.assertEqual(engagement["engagement_unknown_count"], 3)
        self.assertEqual(engagement["engagement_rate"], 0.0)
        self.assertEqual(engagement["selection_mode_counts"], {"disabled": 1})
        self.assertEqual(
            engagement["non_engagement_reason_counts"],
            {"profiling_disabled": 1},
        )
        self.assertEqual(
            engagement["unknown_engagement_reason_counts"],
            {
                "amplifiable_hour_count_missing": 1,
                "profile_validation_missing": 1,
                "run_incomplete": 1,
            },
        )

    def test_duplicate_input_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run.telemetry.jsonl"
            self._write_events(path, [{"event": "run_start"}])

            with self.assertRaisesRegex(ValueError, "paths must be unique"):
                telemetry.summarize_telemetry_files([str(path), str(path)])

    def test_duplicate_basename_is_rejected_to_preserve_portable_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first" / "run.telemetry.jsonl"
            second = root / "second" / "run.telemetry.jsonl"
            first.parent.mkdir()
            second.parent.mkdir()
            self._write_events(first, [{"event": "run_start"}])
            self._write_events(second, [{"event": "run_start"}])

            with self.assertRaisesRegex(
                ValueError,
                "basenames must be unique for portable summaries",
            ):
                telemetry.summarize_telemetry_files([str(first), str(second)])

    def test_summary_is_path_independent_across_machines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "machine-a" / "image.telemetry.jsonl"
            second = root / "machine-b" / "image.telemetry.jsonl"
            first.parent.mkdir()
            second.parent.mkdir()

            def events(dataset_root: str) -> list[dict[str, object]]:
                return [
                    {"event": "run_start", "dataset_root": dataset_root},
                    {
                        "event": "profile_validation",
                        "selection_mode": "filtered",
                        "accepted": False,
                        "reason": "insufficient_complete_weeks",
                        "complete_week_count": 2,
                        "amplifiable_hour_count": 0,
                        "engaged": False,
                    },
                    {
                        "event": "stage_end",
                        "stage": "atomic_stage",
                        "year": 2024,
                        "month": 6,
                        "duration_s": 1.25,
                        "rss_mb": 100.0,
                    },
                    {"event": "run_end"},
                ]

            self._write_events(
                first,
                events("/Volumes/evidence/image.parquet"),
            )
            self._write_events(
                second,
                events("D:\\evidence\\image.parquet"),
            )

            first_summary = telemetry.summarize_telemetry_files([str(first)])
            second_summary = telemetry.summarize_telemetry_files([str(second)])

        self.assertEqual(first_summary, second_summary)

    def test_duplicate_profile_validation_event_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run.telemetry.jsonl"
            self._write_events(path, [
                {"event": "profile_validation", "accepted": False},
                {"event": "profile_validation", "accepted": False},
            ])

            with self.assertRaisesRegex(
                ValueError,
                "expected at most one profile_validation event",
            ):
                telemetry.summarize_telemetry_files([str(path)])

    def test_malformed_json_error_names_file_and_line(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "malformed.telemetry.jsonl"
            path.write_text('{"event": "run_start"}\nnot-json\n', encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                rf"{path}:2: invalid JSON",
            ):
                telemetry.summarize_telemetry_files([str(path)])

    def test_inconsistent_explicit_engagement_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run.telemetry.jsonl"
            self._write_events(path, [
                {"event": "run_start"},
                {
                    "event": "profile_validation",
                    "accepted": True,
                    "amplifiable_hour_count": 12,
                    "engaged": False,
                },
                {"event": "run_end"},
            ])

            with self.assertRaisesRegex(ValueError, "engaged is inconsistent"):
                telemetry.summarize_telemetry_files([str(path)])


if __name__ == "__main__":
    unittest.main()
