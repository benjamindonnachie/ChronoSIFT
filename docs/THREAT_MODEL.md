# ChronoSIFT — Threat Model

This document summarises the threat assumptions retained in ChronoSIFT v2.31. The engine combines deterministic behavioural detection with optional YARA, ClamAV, Luhn, NSRL, and GeoLite2 enrichment and referenced-file propagation. For current pipeline scope and limitations, see the public [README](../README.md); for implemented dead-box ATT&CK coverage, see the [ATT&CK matrix](ATTACK_MATRIX.md).

## Purpose

This document defines the attacker behaviours ChronoSIFT is designed to
detect. It provides context for rule development and explains the
behavioural assumptions behind the detection logic.

ChronoSIFT focuses on **post-compromise behavioural signals** rather
than signature-based malware detection.

------------------------------------------------------------------------

# Detection Philosophy

ChronoSIFT assumes that attackers leave behavioural traces across a
timeline even when individual artefacts appear benign.

The engine therefore looks for:

-   behavioural sequences
-   abnormal contextual patterns
-   improbable activity timing
-   artefact correlations

Detection is based on **deterministic rules and explainable signals**.

------------------------------------------------------------------------

# Threat Categories

## 1. Initial Access

Indicators include:

-   suspicious authentication sequences
-   brute force login attempts
-   remote access tool execution
-   anomalous login locations

Signals may include:

-   repeated_auth_failures
-   impossible_travel
-   suspicious_rdp_activity

------------------------------------------------------------------------

## 2. Execution

Attackers commonly execute commands or scripts.

ChronoSIFT detects:

-   encoded PowerShell
-   unusual command interpreter usage
-   suspicious scripting activity

Example signals:

-   encoded_powershell
-   suspicious_command_execution

------------------------------------------------------------------------

## 3. Persistence

Persistence mechanisms may appear as unusual system configuration
changes.

Examples:

-   scheduled task creation
-   registry modification
-   service installation

Signals may include:

-   suspicious_scheduled_task
-   registry_persistence

------------------------------------------------------------------------

## 4. Privilege Escalation

Indicators include:

-   unusual administrative activity
-   unexpected privilege changes

Signals may include:

-   privilege_escalation_pattern

------------------------------------------------------------------------

## 5. Lateral Movement

ChronoSIFT attempts to identify lateral movement behaviours such as:

-   repeated remote authentication
-   internal network traversal
-   credential reuse across hosts

Signals may include:

-   lateral_movement_pattern
-   internal_auth_sequence

------------------------------------------------------------------------

## 6. Data Exfiltration

Indicators include:

-   suspicious network transfers
-   unusual archive creation
-   unexpected outbound connections

Signals may include:

-   suspicious_data_transfer
-   archive_creation

------------------------------------------------------------------------

# Behavioural Signals

Signals are not intended to represent definitive compromise
individually.

Instead they act as **behavioural evidence fragments** that combine into
a weighted event score.

This allows ChronoSIFT to highlight events requiring analyst review.

------------------------------------------------------------------------

# Adversary Evasion Considerations

Attackers may attempt to evade detection by:

-   modifying timestamps (timestomping)
-   manipulating log entries
-   using living-off-the-land binaries
-   spreading activity across long time windows

ChronoSIFT mitigates these by:

-   retaining anomalous timestamps
-   using behavioural sequences rather than single events
-   combining signals across time

------------------------------------------------------------------------

# Relationship to Dendritic Cell Algorithm Research

ChronoSIFT produces deterministic behavioural signals.

These signals are intended to serve as **input antigens** for future
Deterministic Dendritic Cell Algorithm (DDCA) models.

The goal is to combine:

-   explainable rule signals
-   adaptive anomaly detection

for improved cybercrime detection.

------------------------------------------------------------------------

# Future Expansion

Potential threat model extensions:

-   insider threat detection
-   ransomware behavioural patterns
-   cloud infrastructure activity
-   container environment telemetry
