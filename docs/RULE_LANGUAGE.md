# ChronoSift -- Rule Language Specification

Historical note: this document began as the v2.27 rule-language description and may not cover every v2.31 parser or temporal feature. Treat the included [v2.31 rules](../rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml) as the authoritative executable configuration.

## Purpose

ChronoSift uses a YAML-based rule language to define behavioural
detection logic. The language is designed to be:

-   deterministic
-   explainable
-   tolerant of missing fields
-   easy to audit

Rules emit **signals**, which are later combined into behavioural
scores.

------------------------------------------------------------------------

# Rule Types

ChronoSift supports two rule categories:

1.  **Atomic Rules** -- operate on a single event
2.  **Temporal Rules** -- operate on multiple events within a time
    window

------------------------------------------------------------------------

# Atomic Rules

Atomic rules evaluate conditions on a single row of the timeline.

## Example

``` yaml
- rule_id: suspicious_powershell
  description: Encoded PowerShell execution
  priority: 10

  when_all:
    - field: message
      op: contains_ci
      value: powershell

    - field: message
      op: contains
      value: -enc

  emit:
    signals:
      - name: encoded_powershell
        value: 1
```

------------------------------------------------------------------------

## Atomic Rule Structure

  Field         Description
  ------------- ----------------------------------
  rule_id       unique rule identifier
  description   human readable explanation
  priority      rule evaluation ordering
  scope_any     optional scope conditions
  scope_all     optional scope conditions
  when_any      conditions where any must match
  when_all      conditions where all must match
  emit          signals produced when rule fires

------------------------------------------------------------------------

# Conditions

Conditions evaluate a field using an operator.

## Structure

``` yaml
- field: username
  op: eq
  value: administrator
```

------------------------------------------------------------------------

## Supported Operators

  Operator      Meaning
  ------------- -----------------------------
  exists        field contains a value
  eq            equals
  in            value in list
  in_ci         case-insensitive membership
  contains      substring
  contains_ci   case-insensitive substring
  regex         regular expression
  lt            numeric less-than
  lte           numeric less-or-equal
  gt            numeric greater-than
  gte           numeric greater-or-equal

Operators are **missing-safe**.

If a field is absent or null, the condition evaluates to False.

------------------------------------------------------------------------

# Emit Section

Rules emit signals.

Example:

``` yaml
emit:
  signals:
    - name: suspicious_command
      value: 1
```

Signals may be numeric or metadata.

Numeric signals contribute to the final score.

------------------------------------------------------------------------

# Temporal Rules

Temporal rules detect patterns across multiple events.

## Example

``` yaml
- rule_id: repeated_auth_failures
  description: Multiple failed logins followed by success

  key_by:
    - username

  lookback: 10m
  mode: sequence

  sequence:
    - signal: auth_failure
      min_count: 2

    - signal: auth_success
      min_count: 1

  emit:
    signals:
      - name: brute_force_pattern
        value: 1
```

------------------------------------------------------------------------

## Temporal Rule Fields

  Field         Description
  ------------- -----------------------------
  rule_id       unique identifier
  description   human readable description
  key_by        actor grouping keys
  lookback      sliding time window
  mode          temporal rule type
  sequence      ordered signal requirements
  cooccur_all   signals required in window
  field         used for change detection
  emit          signals produced

------------------------------------------------------------------------

# Temporal Modes

## sequence

Signals must appear in order within the lookback window.

Example:

    auth_fail → auth_fail → auth_success

------------------------------------------------------------------------

## cooccur

Signals must occur within the window regardless of order.

------------------------------------------------------------------------

## first_seen_value

Triggers when a value appears for the first time.

------------------------------------------------------------------------

## change_detected

Triggers when a field changes value within the window.

------------------------------------------------------------------------

# Signal Weighting

Signals contribute to event scores using `weights.yaml`.

Example:

``` yaml
weights:
  encoded_powershell: 8
  brute_force_pattern: 10
```

Final event score:

    score = Σ(signal_value × weight)

Scores are capped by `max_event_score`.

------------------------------------------------------------------------

# Explainability

Each rule firing records an explanation entry.

Example output:

``` json
{
  "rule_id": "repeated_auth_failures",
  "description": "Multiple failed logins followed by success",
  "confidence": "medium",
  "evidence": {
    "temporal": "sequence",
    "key_by": "username"
  }
}
```

This supports forensic review and research reproducibility.

------------------------------------------------------------------------

# Design Goals

The ChronoSift rule language emphasises:

-   deterministic behaviour
-   missing-field tolerance
-   human readability
-   forensic explainability

Rules should prioritise **behavioural semantics** rather than static
signatures.

------------------------------------------------------------------------

# Future Extensions

Possible enhancements:

-   rule namespaces
-   rule versioning
-   probabilistic modifiers
-   behavioural templates
-   automatic rule validation
