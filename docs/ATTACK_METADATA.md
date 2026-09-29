# Evidence-qualified ATT&CK attribution (rules v24)

Audit F-02 is addressed with metadata, not detector or scoring changes. Rules v24
have the same scoring configuration as v23; weights v21 remain unchanged. The CLI
defaults to v26/v22, which adds [note-content and web-name qualification](NOTE_WEB_EVIDENCE.md)
to the previously documented [semantic gates](SEMANTIC_EVIDENCE.md).
Existing explicitly selected policies remain supported.

## Interpretation

Each configured detector emission, atomic rule and temporal rule is reviewed in
YAML. A firing explanation carries `attack_ref`, a producer-specific policy path,
plus `attack_ids` and `attack_basis` when a mapping is warranted:

- `observed_behaviour`: the recorded action matches the technique; it can still be legitimate.
- `attempted_behaviour`: a concerning attempt, not confirmed success.
- `contextual_inference`: a qualified contextual association, not direct proof.
- `artefact_capability`: capability of a matched artefact, not execution on this host.
- `unmapped`: no warranted technique assertion; no extra per-event fields or score reduction.

The actual producer supplies the reference, not a lookup by shared signal name.
Generic context and score modifiers do not acquire labels by association. The
existing `chronosift_attack_techniques` column remains the legacy web summary;
the general attribution is in `chronosift_explain`, not a replacement summary.

## Offline catalogue and provenance

Enterprise ATT&CK 19.2 is pinned by source commit and SHA-256 in
`chronosift_data/enterprise-attack-19.2.json`, with MITRE's licence alongside it.
Processing does not contact MITRE or VirusTotal. Policy IDs must be valid in the
bundled catalogue; retired IDs require an explicit, used `legacy_ids` rationale.
Missing annotations, malformed fields, unknown IDs, checksum errors and unconsumed
producer mappings fail before evidence processing.

Each native output directory receives `_chronosift_attack_metadata.json`, including
catalogue/version/source hashes, mapping hash, producer rationales and technique
names/URLs. It is written before partition processing, so its presence alone does
not imply a successful run. The inventory describes configured mappings, including
disabled producers, not actual firings or empirically validated detection coverage.
The whole small technique catalogue is stored once per run to resolve external IDs.
For in-memory API use, obtain the same payload from
`engine.attack_metadata.run_metadata()`; it is not attached to DataFrame attrs.

AV attribution uses only IDs attached to the matched per-hash findings. It never
unions a capability category's entire vocabulary. `attack_reported_ids` preserves
reported IDs and `attack_diagnostics` records unknown/retired IDs; original evidence
and source provenance remain intact. Current recognized IDs populate `attack_ids`.
Retired external IDs are not silently replaced or used to change confidence.

## Payment-card exposure is a different framework

Luhn-supported potential plaintext payment-card data remains an investigative
signal: it can expose data to an attacker or corroborate database dumping/access.
It is not automatically an ATT&CK credential-theft technique. PCI DSS v4.0.1
requirement 3.5.1 is the separate relevant stored-PAN protection reference
([PCI SSC FAQ 1222](https://www.pcisecuritystandards.org/faqs/1222/)). Display
masking is a distinct requirement, 3.4.1
([PCI SSC FAQ 1492](https://www.pcisecuritystandards.org/faqs/1492/)).

A checksum hit alone establishes neither genuine card data nor a compliance
violation. Investigators should confirm content, scope and storage/access context;
decrypted forensic views, sanctioned exports or test numbers need interpretation.
Confirmed plaintext PAN plus suspicious creation/download context is stronger
evidence of exposure or access. These qualifications do not lower existing scores.
PCI references live in YAML rationales and the generated inventory, not in ATT&CK
ID fields, and do not constitute a compliance assessment.

## Maintaining the mapping

Edit `rules/attack_mapping_review_v24.yaml`, then run:

```sh
python benchmarks/build_attack_metadata_policy.py
python benchmarks/build_attack_metadata_policy.py --check
```

The review is bound to the exact v23 source hash. A changed base requires a new
review, not automatic carry-forward. Generated v24 and its
[versioned inventory](ATTACK_MATRIX_V24.md) are retained. V25's reviewed changes
are in `build_semantic_evidence_policy.py`: narrower admission retains qualified
source mappings; changed outcome/dump claims explicitly update their basis and
rationale. The [current inventory](ATTACK_MATRIX_CURRENT.md) is derived from v26.
The [historical matrix](ATTACK_MATRIX.md) remains historical. New policy semantics
must remain YAML-owned and require tests; technique labels confer no score.
