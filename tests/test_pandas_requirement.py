"""Dependency-floor and wide-timestamp preservation regressions (audit F-01)."""

import importlib.util
import json
import lzma
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

import pandas as pd
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
EPOCH_US = [-11644473600000000, 1718562120000001,
            1718562120000001, 16725225600000000, 1344260469241068412]


def load_module(filename):
    name = "pandas_floor_" + Path(filename).stem
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def source_frame():
    return pd.DataFrame({"timestamp": EPOCH_US,
                         "chronosift_row_id": [30, 12, 11, 25, 9]},
                        index=[7, 2, 2, 8, 0])


class PandasRequirementTest(unittest.TestCase):
    def test_metadata_requires_tested_pandas_floor(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            metadata = tomllib.load(handle)
        self.assertIn("pandas>=3.0.3", metadata["project"]["dependencies"])

    def check_unsupported(self, filename):
        for version in ("2.2.0", "2.3.3", "2.10.0", "3.0.0", "3.0.2", "3.0.3rc1"):
            with self.subTest(version=version), mock.patch.object(pd, "__version__", version):
                with self.assertRaisesRegex(ImportError, r"requires pandas>=3\.0\.3"):
                    load_module(filename)

    def test_engine_rejects_unsupported_pandas_before_processing(self):
        self.check_unsupported("chronoSIFT_v2_31.py")

    def test_standalone_rejects_unsupported_pandas_before_processing(self):
        self.check_unsupported("jsonl_to_parquet_cli_logging.py")

    def test_both_normalisers_preserve_wide_dates_duplicate_ids_and_microseconds(self):
        engine = load_module("chronoSIFT_v2_31.py")
        ingest = load_module("jsonl_to_parquet_cli_logging.py")
        expected = dict(zip(source_frame()["chronosift_row_id"], EPOCH_US))
        for name, normalise in (
            ("engine", lambda frame: engine.normalise_for_parquet(frame, verbose=False)[0]),
            ("standalone", ingest.normalise_chunk),
        ):
            with self.subTest(path=name):
                result = normalise(source_frame())
                actual = dict(zip(result["chronosift_row_id"], result.index.as_unit("us").asi8))
                self.assertEqual(actual, expected)
                self.assertEqual(len(result), 5)
                self.assertEqual(result.index.year.tolist(), [1601, 2024, 2024, 2500, 44567])

    def test_partition_fallback_preserves_wide_dates_and_source_index(self):
        engine = load_module("chronoSIFT_v2_31.py")
        for utc in (True, False):
            with self.subTest(utc=utc):
                result = engine._get_partition_datetime_series(source_frame(), utc=utc)
                self.assertEqual(result.index.tolist(), [7, 2, 2, 8, 0])
                self.assertEqual(result.dt.as_unit("us").astype("int64").tolist(), EPOCH_US)
                self.assertEqual(str(result.dt.tz), "UTC" if utc else "None")

    def test_engine_partition_writer_roundtrips_every_wide_timestamp(self):
        engine = load_module("chronoSIFT_v2_31.py")
        with tempfile.TemporaryDirectory() as tmp:
            engine.write_time_partitioned_parquet(source_frame(), tmp, normalise=True, verbose=False)
            files = sorted(Path(tmp).rglob("*.parquet"))
            frames = [pq.ParquetFile(path).read().to_pandas() for path in files]
            result = pd.concat(frames)
            self.assertEqual(len(result), 5)
            self.assertEqual(sorted(result.index.as_unit("us").asi8.tolist()), sorted(EPOCH_US))
            self.assertEqual(sorted(result["chronosift_row_id"].tolist()), [9, 11, 12, 25, 30])
            self.assertEqual({path.parent.parent.name for path in files},
                             {"year=1601", "year=2024", "year=2500", "year=44567"})

    def test_streaming_converter_roundtrips_wide_dates_with_original_row_ids(self):
        ingest = load_module("jsonl_to_parquet_cli_logging.py")
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "events.jsonl.xz"
            with lzma.open(input_path, "wt") as handle:
                for epoch in EPOCH_US:
                    handle.write(json.dumps({"timestamp": epoch}) + "\n")
            output = Path(tmp) / "parquet"
            ingest.jsonl_xz_to_partitioned_parquet(input_path, output, chunksize=2)
            frames = [pq.ParquetFile(path).read().to_pandas()
                      for path in output.rglob("*.parquet")]
            result = pd.concat(frames).sort_values("chronosift_row_id")
            self.assertEqual(result["chronosift_row_id"].tolist(), list(range(5)))
            self.assertEqual(result["datetime"].dt.as_unit("us").astype("int64").tolist(), EPOCH_US)


if __name__ == "__main__":
    unittest.main()
