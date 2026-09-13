# Whole-frame Python API

`ChronoSiftEngine.apply(frame, ...)` composes the public atomic and contextual
stages. It is intended for an already loaded timeline; production large-corpus
sidecars use the partitioned driver rather than this convenience method.
The frame must have a datetime index. Preserve the original timestamp resolution
and persistent integer `chronosift_row_id`; tied timestamps are distinct events.
Processing may mutate the supplied frame, and callers must use the returned frame
because joins/normalisation can return a new frame object. No defensive whole-frame
copy is part of this API contract.

By default, temporal evaluation and profiling are enabled, required fields are
ensured, and event signals/explanations are materialised. The atomic call always
keeps these payloads sparse until the contextual call. With
`materialise_event_columns=False`, the sparse signal/explanation maps remain in
`result.attrs['chronosift_sparse']`; this is not a request to skip scoring.
`apply_temporal=False` is forwarded to contextual evaluation, not a promise to
disable all contextual detectors. Profiling is passed to both stages.

GeoIP paths, AV/Luhn paths, NSRL path/cache and the profile manifest are forwarded
to atomic processing. The file-hit manifest is passed to contextual processing.
The returned `chronosift_metadata` records GeoIP file metadata and enrichment paths.
This is not a complete portable run bundle: for reproducibility preserve the engine,
exact rules/weights, enrichment files, input identity and all execution options.

GeoIP remains optional and is enabled when both City and ASN paths are supplied.
An address genuinely absent from one database leaves its fields missing without
preventing the other lookup. Invalid and non-global addresses are not queried.
Unexpected database/reader/response errors propagate through `apply()` and the
native pipeline; they are not equivalent to an absent address. Resources are closed
on success or failure. A failure does not roll back in-place frame mutations or
delete previously completed sidecars; discard a failed call's partial result and
correct the resource before rerunning into a fresh output location.

`tests/test_public_apply.py` directly verifies stage composition on generic Linux,
Windows and web behaviours, default options, all explicit argument routes, sparse
materialisation, score accounting, tied nanosecond timestamps, large integer IDs,
wide dates, empty input and error propagation. `tests/test_geoip_failures.py`
separately exercises real invalid-file opening, expected misses, independent City/
ASN results, wrong/corrupt readers, invalid addresses, deduplication and cleanup.
These tests validate orchestration and failure behaviour; they are not a substitute
for complete-corpus performance or ground-truth evaluation.
