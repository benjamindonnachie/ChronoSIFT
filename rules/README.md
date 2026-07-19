# Rules, weights, and enrichment inputs

The two YAML files in this directory are the versioned ChronoSIFT v2.31 baseline:

- `rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml` defines normalisation, atomic rules, temporal rules, behavioural continuity, detection terms, and engine configuration.
- `weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml` assigns each emitted signal a numeric contribution and defines the maximum event score.

Copy and version these files when tuning ChronoSIFT. A run is only reproducible when its engine version, rules, weights, overlap, and enrichment inputs are recorded together.

## Optional local inputs

Large or independently licensed resources are not committed. Pass their paths on the command line.

| Input | Required fields or format | Purpose |
|---|---|---|
| YARA Forge metadata | A YARA Forge `.yar` bundle | Category and quality metadata for rule matches already present in the timeline |
| ClamAV CSV | `sha256,av_signature,av_hit,av_product` | Hash-indexed AV enrichment and signature-family categorisation |
| Luhn CSV | `sha256,luhn_hit` | Hash-indexed structured-number findings |
| NSRL Parquet | SHA-256 plus an application-type field | Known-file enrichment and baseline noise reduction; convert the NSRL RDS source before use |
| GeoLite2 City | MaxMind City `.mmdb` | City, country, coordinates, and travel distance |
| GeoLite2 ASN | MaxMind ASN `.mmdb` | ASN and organisation continuity |

The engine consumes these results but does not perform YARA, ClamAV, Luhn, or NSRL acquisition/scanning itself. The original NSRL RDS distribution is not accepted directly; it must first be converted to the Parquet lookup schema above. Keep source versions, hashes, conversion details, and acquisition dates with research outputs. All external inputs remain subject to their respective licences and terms.
