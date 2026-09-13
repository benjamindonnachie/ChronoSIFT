# Investigator-priority behaviour policy

Rules v21 / weights v19 extend v20/v18 in the isolated candidate checkout.
ChronoSIFT remains a stage in a pipeline. A score prioritises human review; it
is not a probability, proof of compromise, attribution verdict or assessment
of downstream pipeline accuracy. The score cap remains 50.

## Evidence, outcome and priority

Suspicious attempts can deserve substantial weight without proof of success.
Outcome and attribution limits belong in the explanation, not an automatic
zero-score gate. These are general parser/behaviour rules: no challenge account,
address, hash, archive name or malware filename selects an event.

| Observation | New contribution | ATT&CK rationale and limits |
|---|---:|---|
| Explicitly denied sudo command targeting root | 8 | [T1548.003](https://attack.mitre.org/techniques/T1548/003/), attempted privilege use; never fed into execution fields. |
| Allowed root command from a configured writable/staging directory | 14, plus existing execution context | T1548.003; typical home-directory command totals 23, temporary-directory command 27. No AV hit required. Allowed command is not proof of successful payload effects. |
| Allowed root command by a recently created account | 12 additive | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) / T1548.003; exact actor and host, fixed seven-day creation window; deletion/modification/recreation resets context. |
| FTP transfer, with archive/direction/completion context | 2 base + 10 archive + 8 outgoing archive + 3 completed archive | Incoming archive 12–15; outgoing archive attempt/completion 20–23. [T1048.003](https://attack.mitre.org/techniques/T1048/003/) is an outgoing-exfiltration candidate, not a label for incoming traffic. |
| System-wide preload-control creation/modification | 24 | [T1574.006](https://attack.mitre.org/techniques/T1574/006/), dynamic-linker hijacking candidate. No AV requirement; contents and actual library use remain unproved. |
| Administrative theme/plugin editor POST | 12 | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) deployment candidate. Failed/rejected attempts count; POST/302 does not prove authentication, saved code or a web shell. |
| Direct AV/YARA web-shell category on a script under an explicit document root | Existing shell artefact/use weights | T1505.003; classification can support the existing shell-use chain without a suggestive filename. Generic malware/YARA hits are not substituted for the web-shell category. |

Weights are additive with independently applicable existing rules. Thus a new
account's allowed writable-root command may score 35 before other context.
Explanations must account for the uncapped contributions; only the final total
is capped. Repeated metadata observations are separate timeline rows, not
separate proved executions.

## Parsing and controls

Sudo parsing accepts complete, ordered TTY/PWD/USER/COMMAND records from scoped
Linux log parsers, distinguishing the caller from the run-as account. Recognised
denial messages never supply an allowed command, even when a generic command
field is present. Unknown rejection formats are not assumed successful. Root
dropping to a normal account does not inherit root execution context.

`posix_path_resolve` is a generic normalisation method with required `from` and
`base_field`. It resolves an explicit absolute path or slash-containing relative
reference against an absolute recorded directory. It preserves case, performs
no filesystem access or shell expansion, does not search PATH, and rejects
`..`, network-root syntax, variables and control characters. It is a lexical
reference, not symlink/file-version proof. Only non-missing scalar candidates
are visited; no defensive dataframe or nested-context copy is added.

FTP parsing uses the full xferlog field layout exposed by `text/vsftpd`, including
direction `i`/`o`, completion `c`/`i`, account, remote host, path and byte count.
The parser name does not prove which FTP daemon was installed. Incoming means
upload **into the analysed server**; outgoing means download **from it**.
Deletion records and malformed/quoted examples are excluded. Ordinary transfers
retain low weight; archives receive greater priority without an invented
malicious-content verdict. [T1105](https://attack.mitre.org/techniques/T1105/)
requires tool/payload context, and
[T1074.001](https://attack.mitre.org/techniques/T1074/001/) staging remains a
candidate, not an automatic conclusion from every archive.

Only creation/content-modification/metadata-modification observations of the
actual `/etc/ld.so.preload` control file qualify. Read/access timestamps,
similarly named files elsewhere and directories do not. Merely finding a
library or a segfault does not establish that the preload file named it; the
control-file change itself is sufficient to flag for investigation.

## Explicit web document roots

Use `configure_web_roots.py` to produce a fresh effective YAML policy, then pass
that policy through the existing runner's `--rules-yaml`. For example, using
the project's uv-managed environment:

```sh
uv run --no-project --python /path/to/project/.venv/bin/python python -B configure_web_roots.py \
  rules/rules_evidence_calibrated_v21.yaml /path/to/working/run/effective-rules.yaml \
  --web-document-root /srv/tenant/deployment
```

The output is exclusively created and never overwrites the input or an old run.
Roots refer to paths **inside the evidence**, not the analysis machine. The
helper updates existing referenced-file, lifecycle and web-shell policy surfaces
consistently. Longer roots take precedence for nested deployments; ambiguity
between full file identities still rejects linkage. Case is preserved for Linux.
There is no basename-only join, mount guessing, cookie inference or implicit CMS
installation-root detection. Record the effective YAML with run provenance.

Requests linked to an observed web-shell-like file can receive the existing
15-point bounded use context. That is evidence of a request, not proof a command
succeeded. Administrative GET/login redirects alone are not newly classified;
the administrative edit POST is independently flagged without requiring them.

## Database-export correction

The lifecycle candidate now requires an existing database/export extension, or
an archive extension together with a dump-like **basename**. A `dump` substring
in an executable, parent directory or arbitrary log text no longer suffices.
Credential-dumping tools retain independent AV/YARA/tool signals under
[T1003](https://attack.mitre.org/techniques/T1003/). SQL/database extensions remain
heuristics, not verified export content.

Generic lifecycle predicates may refer to **previously declared** derived
predicates. Forward references, cycles and base-fact collisions are rejected.
This expresses the archive-and-name condition in YAML, not engine vocabulary.

## Validation boundary

Tests cover renamed actors, addresses and web paths; normal commands, denied
commands, root downshift, incomplete FTP, loader access-only timestamps, benign
editor GETs, ambiguous web mappings and genuine SQL exports. Native compact
versus eager monthly processing checks account-to-sudo expiry and lifecycle
resets with 24-hour raw overlap; the existing maximum history remains 199 hours.

Bounded original-Parquet replay is a separate evaluation using actual YARA/AV
resources and explicit deployment-root configuration. Ground-truth IDs are
evaluation selectors only and never enter shipped detection policy. It does
not replace a fresh full Windows/Ubuntu/challenge corpus run. Historical policies,
main, GitHub and previous sidecars remain unchanged by this candidate work.
