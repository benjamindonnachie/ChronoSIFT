# Pandas requirement and audit F-01

ChronoSIFT requires **pandas >=3.0.3**. This is a forensic-correctness requirement,
not merely a performance preference. The declared dependency and the engine and
standalone JSONL converter's early import guards enforce the same minimum.

On pandas 2.3.3, the existing epoch-microsecond conversion produces a nanosecond
datetime array. Dates outside approximately 1677–2262 become `NaT`, and the
normaliser drops those rows. The audit's two existing year-44567 regressions were
reproduced before this change. Such dates can be meaningful evidence of tampering
or corruption and must not be discarded simply for being implausible.

The chosen resolution is to require the already-tested pandas 3.0.3 release,
rather than backporting timestamp conversion to pandas 2.x. No scoring policy,
row-ID assignment, timestamp conversion, or partition algorithm was changed.
The guards also reject earlier pandas 3.0 releases and a 3.0.3 release candidate;
later releases are permitted by the minimum-version constraint, not certified by
this test run. Install this checkout's dependencies into the intended environment
with `uv pip install -e .`; do not upgrade a shared running job's environment.

Regression coverage includes the declared minimum, early rejection by both
entry points, years 1601/2500/44567, microsecond precision, duplicate timestamps
with distinct row IDs, the raw-timestamp partition fallback, and both engine and
streaming JSONL-to-Parquet round trips.

Changing the dependency does not reconstruct rows already lost in a prior
pandas-2.x extraction. If such an extraction is identified, recovery requires
regenerating the affected Parquet from its original JSONL/Plaso evidence, not
merely rescoring the incomplete Parquet. No existing evidence or historical
outputs were changed by this fix.
