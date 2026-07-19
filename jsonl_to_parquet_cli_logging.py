#!/usr/bin/env python3

"""
Stream large .jsonl.xz files into a partitioned Parquet dataset.

Features:
- Low RAM usage
- Chunked processing
- Timestamp normalisation to UTC datetime
- Partitioned output by year/month
- No full-data concat in memory
- argparse-driven CLI
- logging-driven progress output

Output layout:
    /path/to/output_dataset/
        year=2024/
            month=01/
                part-000001-....parquet
            month=02/
                part-000002-....parquet
        year=2025/
            month=03/
                part-000003-....parquet
"""

from __future__ import annotations

import argparse
import json
import logging
import lzma
import uuid
from pathlib import Path
from typing import Iterator

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


logger = logging.getLogger(__name__)

JSON_TEXT_COLS = [
    "chronosift_signals",
    "chronosift_explain",
    "pathspec",
    "attribute_names",
    "yara_match",
    "section_names",
    "date_time",
]

DROP_COLS_IF_PRESENT = [
#    "date_time",   # drop if your datetime index already replaces it
]

ROW_ID_COLUMN = "chronosift_row_id"


def configure_logging(level: str) -> None:
    numeric = getattr(logging, str(level).upper(), None)
    if not isinstance(numeric, int):
        raise ValueError(f"invalid log level: {level!r}")
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Convert a .jsonl.xz file to a partitioned Parquet dataset")
    p.add_argument("in_path", help="Input .jsonl.xz file path")
    p.add_argument("out_dir", help="Output Parquet dataset directory")
    p.add_argument(
        "--chunksize",
        type=int,
        default=100_000,
        help="Number of JSONL records per processing chunk, default: 100000",
    )
    p.add_argument(
        "--compression",
        default="zstd",
        choices=["zstd", "snappy", "gzip", "brotli", "lz4", "none"],
        help="Parquet compression codec, default: zstd",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level, default: INFO",
    )
    return p


# -----------------------------
# JSONL.XZ -> DataFrame chunks
# -----------------------------

def iter_jsonl_xz_to_df(
    path: str | Path,
    chunksize: int = 100_000,
    encoding: str = "utf-8",
) -> Iterator[pd.DataFrame]:
    """
    Stream a .jsonl.xz file and yield pandas DataFrame chunks.
    """

    path = Path(path)
    rows: list[dict] = []
    next_row_id = 0

    logger.info("Reading JSONL.XZ stream from %s", path)

    with lzma.open(path, mode="rt", encoding=encoding, errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON error on line {line_no}: {e}") from e

            if ROW_ID_COLUMN in row:
                raise ValueError(
                    f"Input JSONL already contains reserved persistent row-id field {ROW_ID_COLUMN!r} on line {line_no}"
                )

            row[ROW_ID_COLUMN] = next_row_id
            next_row_id += 1
            rows.append(row)

            if len(rows) >= chunksize:
                logger.debug("Yielding DataFrame chunk at line %d with %d rows", line_no, len(rows))
                yield pd.DataFrame.from_records(rows)
                rows.clear()

        if rows:
            logger.debug("Yielding final DataFrame chunk with %d rows", len(rows))
            yield pd.DataFrame.from_records(rows)


def _to_json_text(value):
    """Convert dict/list payloads to JSON text; preserve missing values."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if pd.isna(value):
        return pd.NA
    return str(value)


# -----------------------------
# Normalise timestamp
# -----------------------------

def normalise_chunk(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert timestamp to UTC datetime, set as index, sort, and
    add partition columns year/month.

    Assumes 'timestamp' is microseconds since epoch.
    """

    changes: list[dict[str, str]] = []

    if "timestamp" not in df.columns:
        raise KeyError("Input chunk does not contain a 'timestamp' column")

    logger.info("Normalising chunk with %d rows", len(df))

    df["datetime"] = pd.to_datetime(
        df["timestamp"],
        unit="us",
        errors="coerce",
        utc=True,
    )

    df = df.dropna(subset=["datetime"])
    df = df.set_index("datetime").sort_index()

    df["year"] = pd.Series(df.index.year, index=df.index, dtype="Int16")
    df["month"] = pd.Series(df.index.month, index=df.index, dtype="Int8")

    for col in DROP_COLS_IF_PRESENT:
        if col in df.columns:
            df = df.drop(columns=[col])
            changes.append({
                "column": col,
                "action": "drop_redundant",
                "detail": "dropped by policy",
            })

    if "pid" in df.columns:
        before = str(df["pid"].dtype)
        df["pid"] = df["pid"].astype("string")
        changes.append({
            "column": "pid",
            "action": "coerce_string",
            "detail": f"{before} -> string",
        })

    for col in JSON_TEXT_COLS:
        if col in df.columns:
            before = str(df[col].dtype)
            df[col] = df[col].map(_to_json_text).astype("string")
            changes.append({
                "column": col,
                "action": "json_text",
                "detail": f"{before} -> string(JSON text)",
            })

    for col in df.columns:
        if str(df[col].dtype) != "object":
            continue

        series = df[col]
        non_null = series.dropna()

        if non_null.empty:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "empty_object_to_string",
                "detail": "object column with only missing values after prior cleanup",
            })
            continue

        types = non_null.map(type).value_counts()

        if len(types) == 1 and str in types.index:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "stringify",
                "detail": "object[str] -> string",
            })
        elif len(types) == 1 and bool in types.index:
            df[col] = series.astype("boolean")
            changes.append({
                "column": col,
                "action": "bool_normalise",
                "detail": "object[bool] -> boolean",
            })
        elif len(types) == 1 and int in types.index:
            df[col] = pd.to_numeric(series, errors="coerce").astype("Int64")
            changes.append({
                "column": col,
                "action": "int_normalise",
                "detail": "object[int] -> Int64",
            })
        elif len(types) == 1 and float in types.index:
            df[col] = pd.to_numeric(series, errors="coerce")
            changes.append({
                "column": col,
                "action": "float_normalise",
                "detail": "object[float] -> float",
            })
        else:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "fallback_string",
                "detail": f"mixed object types {list(types.index)} -> string",
            })

    report = pd.DataFrame(changes, columns=["column", "action", "detail"])

    logger.info("Normalisation complete: %d rows, %d columns", len(df), len(df.columns))
    logger.debug("Dtype summary:\n%s", df.dtypes.astype(str).value_counts().to_string())
    if not report.empty:
        logger.debug("Changes made:\n%s", report.to_string(index=False))

    return df


# -----------------------------
# Write partitioned parquet
# -----------------------------

def jsonl_xz_to_partitioned_parquet(
    in_path: str | Path,
    out_dir: str | Path,
    chunksize: int = 100_000,
    compression: str = "zstd",
) -> None:
    """
    Convert .jsonl.xz -> partitioned parquet dataset by year/month.

    Writes each chunk immediately to disk to minimise RAM use.
    """

    in_path = Path(in_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Input: %s", in_path)
    logger.info("Output dir: %s", out_dir)
    logger.info("Chunksize: %d", chunksize)
    logger.info("Compression: %s", compression)

    total_rows = 0
    chunk_count = 0
    for chunk_count, df in enumerate(iter_jsonl_xz_to_df(in_path, chunksize), start=1):
        logger.info("Processing chunk %d", chunk_count)
        df = normalise_chunk(df)

        if df.empty:
            logger.info("Chunk %d skipped after normalisation (0 rows)", chunk_count)
            continue

        n = len(df)
        to_write = df.reset_index()
        basename = f"part-{chunk_count:06d}-{uuid.uuid4().hex}-{{i}}.parquet"

        table = pa.Table.from_pandas(to_write, preserve_index=False)

        pq.write_to_dataset(
            table,
            root_path=str(out_dir),
            partition_cols=["year", "month"],
            compression=compression,
            basename_template=basename,
        )

        total_rows += n

        logger.info(
            "Chunk %d written: rows=%d total_rows=%d",
            chunk_count,
            n,
            total_rows,
        )

        del df
        del to_write
        del table

    logger.info("Finished conversion: chunks_written=%d rows_total=%d", chunk_count, total_rows)


# -----------------------------
# Read parquet dataset
# -----------------------------

def read_parquet_dataset(path: str | Path) -> pd.DataFrame:
    """
    Read the full parquet dataset back into a pandas DataFrame.

    Warning:
        This loads the full dataset into RAM.
    """

    logger.info("Reading full Parquet dataset into pandas from %s", path)
    df = pd.read_parquet(path)

    if "datetime" in df.columns:
        df["datetime"] = pd.to_datetime(df["datetime"], utc=True, errors="coerce")
        df = df.set_index("datetime").sort_index()

    return df


def main() -> int:
    args = build_arg_parser().parse_args()
    configure_logging(args.log_level)

    jsonl_xz_to_partitioned_parquet(
        in_path=args.in_path,
        out_dir=args.out_dir,
        chunksize=args.chunksize,
        compression=args.compression,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
