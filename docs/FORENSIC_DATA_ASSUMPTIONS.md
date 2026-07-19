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

GeoIP is applied via unique‑IP lookup tables.

Advantages:

-   deterministic enrichment
-   faster processing
-   reproducible results

Private and non‑routable IP addresses are intentionally not enriched.

------------------------------------------------------------------------

## Evidence Preservation

ChronoSift prioritises:

-   deterministic processing
-   artefact retention
-   explainable outputs

This ensures results remain suitable for forensic reporting and academic
evaluation.
