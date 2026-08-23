# ChronoSIFT — Forensic Data Assumptions

This document records the core data-handling assumptions retained in ChronoSIFT v2.31. For the current pipeline scope, supported inputs, enrichment stages, and limitations, see the public [README](../README.md).

## Philosophy

ChronoSift intentionally avoids discarding anomalous artefacts that may
represent anti‑forensic activity.

Data irregularities are treated as potential signals rather than noise.

------------------------------------------------------------------------

## Timestamp Anomalies

Timelines frequently contain implausible timestamps.

Examples observed:

1906 1916 1969 2055

Possible causes:

-   parser errors
-   corrupted metadata
-   timezone conversion issues
-   timestomping

ChronoSift retains these rows.

------------------------------------------------------------------------

## Recommended Future Signal

timestamp_outlier

This would flag events outside a plausible system lifetime range without
removing them from analysis.

------------------------------------------------------------------------

## Parser Artefacts

Plaso parsers sometimes emit placeholder values:

"-" "N/A" "None"

ChronoSift treats these as semantic nulls to prevent false rule matches.

------------------------------------------------------------------------

## IP Address Recovery

Some Windows EVTX events contain IP addresses only within XML fields.

ChronoSift performs structured recovery by parsing:

xml_string strings url fields

before falling back to message scanning.

------------------------------------------------------------------------

## GeoIP Enrichment

GeoIP is applied via unique-IP lookup tables. The input is the configured
canonical IP-recovery field, and the six City/ASN output column names are
declared under the mandatory `geoip_enrichment.outputs` mapping. Geographic-
continuity and impossible-travel input bindings are checked against that schema
at startup.

Advantages:

-   deterministic enrichment
-   faster processing
-   reproducible results

Private and non‑routable IP addresses are intentionally not enriched.
GeoLite2 data is an external, time-varying input; record both database versions,
hashes, and build metadata with every run.

------------------------------------------------------------------------

## Hour-of-week time basis and comparability

ChronoSIFT currently normalises timestamps to UTC and constructs its 168-bin
activity profile from UTC weekday and hour values. This preserves a single
forensic time basis, but it does not reconstruct the subject's local wall
clock. A recurring local-time habit in a daylight-saving zone can therefore
occupy adjacent UTC bins on opposite sides of a clock transition. The split
may weaken predictive validation or reduce amplification; investigators should
record the subject timezone and whether the retained interval crosses a clock
transition when interpreting the profile. Changing the timezone supplied to
an upstream Plaso export does not change this behaviour because ChronoSIFT
normalises timestamps to UTC on ingestion.

The activity-deficit factor also reflects evidence volume. The simultaneous
uncertainty band normally narrows as more events and informative complete weeks
are retained, allowing the same underlying hourly proportions to receive a
larger factor. Out-of-hours scores should therefore be compared within a
dataset, not treated as directly comparable measurements between images with
different retention or event volumes. Preserve the profile manifest, selected
event count, complete-week count, validation result, simultaneous radius, and
amplifiable-hour count with every reported result.

The shipped profile fails closed when its filtered host-resident selection is
too small, invalid, inconclusive, or operationally inert. It does not replace
that selection with the full timeline because removing the parser, filename,
and NSRL exclusions changes the quantity being estimated and may allow package
management or update scheduling to shape the amplifier. The configurable
`full_dataset` action is suitable only for a separately identified experiment.
Do not combine its results with filtered-profile results. Report
`selection_mode`, source and selected event counts, validation status/reason,
complete-week count, amplifiable-hour count, and simultaneous radius in every
results table that uses the factor.

For a multi-image corpus, preserve one telemetry stream per image and generate
the corpus `amplifier_engagement` summary with
`summarize_chronosift_telemetry.py`. Report its corpus run count, known
engagement denominator, engaged count and rate, selection modes, and
non-engagement reasons. An incomplete run, a missing profile event, or an older
event without an amplifiable-hour count is an unknown observation, not evidence
that the factor failed to engage. Retain the aggregate's per-image records and
profile manifests so every count remains attributable to its selection and
validation decision.

Profiling-disabled ablations are retained as explicit known non-engagement with
`selection_mode: disabled` and `reason: profiling_disabled`; they should not be
interpreted as a failure of the retained data to support a profile. Summary
artefacts use portable telemetry and dataset basenames, while the raw JSONL
retains the original paths as execution provenance. Basenames must be unique
within an aggregate. Corpus summarisation validates all inputs before writing
an output and deliberately fails on a malformed, duplicate, or inconsistent
record. Validate the complete telemetry set before deriving results tables;
do not remove a failing image merely to obtain a partial engagement rate.

“Out of hours” means dataset-relative off-peak activity below the uniform
hour-of-week reference. It is not synonymous with the optional tenth-quantile
quiet annotation or with a rare event; a regular office-hours profile may
identify a broad part of the week as off peak.

------------------------------------------------------------------------

## Evidence Preservation

ChronoSift prioritises:

-   deterministic processing
-   artefact retention
-   explainable outputs

This ensures results remain suitable for forensic reporting and academic
evaluation.
