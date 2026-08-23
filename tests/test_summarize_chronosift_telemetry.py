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
            [record["dataset_root"] for record in engagement["runs"]],
            ["/evidence/image-a.parquet", "/evidence/image-b.parquet"],
        )
        self.assertEqual(len(summary["top_partitions"]), 2)
        self.assertNotEqual(
            summary["top_partitions"][0]["telemetry_jsonl"],
            summary["top_partitions"][1]["telemetry_jsonl"],
        )

    def test_missing_or_legacy_profile_fields_are_unknown_not_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            legacy_path = root / "legacy.telemetry.jsonl"
            incomplete_path = root / "incomplete.telemetry.jsonl"
            missing_path = root / "missing.telemetry.jsonl"
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

            summary = telemetry.summarize_telemetry_files(
                [str(legacy_path), str(incomplete_path), str(missing_path)]
            )

        engagement = summary["amplifier_engagement"]
        self.assertEqual(engagement["complete_run_count"], 2)
        self.assertEqual(engagement["incomplete_run_count"], 1)
        self.assertEqual(engagement["profile_validation_record_count"], 2)
        self.assertEqual(engagement["profile_validation_missing_count"], 1)
        self.assertEqual(engagement["engagement_known_count"], 0)
        self.assertEqual(engagement["engagement_unknown_count"], 3)
        self.assertIsNone(engagement["engagement_rate"])
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
