"""Regression tests for JSONL.XZ-to-Parquet normalisation."""

import importlib.util
import pathlib
import sys
import unittest

import pandas as pd


MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "jsonl_to_parquet_cli_logging.py"
)
SPEC = importlib.util.spec_from_file_location(
    "jsonl_to_parquet_cli_logging_test_target", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class JsonlToParquetNormalisationTest(unittest.TestCase):
    def test_preserves_timestamp_with_year_beyond_int16(self):
        source = pd.DataFrame({
            "timestamp": [
                1718562120000000,
                1344260469241068412,
            ],
            "parser": ["filestat", "utmp"],
        })

        normalised = MODULE.normalise_chunk(source)

        self.assertEqual(len(normalised), 2)
        self.assertEqual(str(normalised["year"].dtype), "Int32")
        self.assertEqual(normalised["year"].tolist(), [2024, 44567])


if __name__ == "__main__":
    unittest.main()
