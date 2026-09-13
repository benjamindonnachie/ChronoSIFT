# Native web-file path identity

The native file-hit manifest preserves case for POSIX and unknown filesystem
paths. `/Utility.php` and `/utility.php` are distinct: a qualified file at the
former cannot lend AV/YARA/Luhn evidence to a request for the latter.
Percent decoding and normal URL path canonicalisation still apply; case is
not an encoding difference. Configured document roots match whole path
components with the same case contract, avoiding prefix-root collisions.

Explicit Windows path syntax (drive-qualified paths, NTFS-prefixed paths and
rooted backslash/UNC paths) uses separate case-folded URL and upload-basename
indexes. This retains the previous Windows matching convention without
applying it to POSIX paths or guessing from the analysis computer's OS.
Unknown paths, including POSIX-mounted evidence, remain case-sensitive.
This does not discover per-directory case-sensitive Windows settings or
server-specific URL rewrites; those require explicit source configuration.

Upload filename extraction now preserves case, including multipart metadata,
encoded filenames and nameless PUT targets. Lookup uses the source file's
case contract. Multiple hit-bearing files resolving to one alias/basename,
including a POSIX/Windows collision, are excluded rather than combining
unrelated identities. Distinct POSIX case variants remain distinct. Exact
SHA-256 upload evidence still takes precedence over basename evidence.

## Policy and ATT&CK

This corrects evidence attribution; it introduces no points or new detector
vocabulary. YAML still owns document roots, qualification, methods, emissions
and all weights. Rules v22 and weights v20 are unchanged.

[ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/) concerns
web-shell persistence and use. Linking an HTTP request to a qualified shell
requires the correct artifact identity; an unrelated case variant is not
support for that technique. Filename resemblance alone remains a weak hint.
An AV or YARA detection establishes evidence about a file, not successful
execution or compromise of every similarly named endpoint.

## Cache and integrity contract

Referenced-file hit manifest schema **8** replaces schema 7; source fingerprint
version **5** replaces version 4. Four `web_casefold_*` maps hold Windows-only
tags and identities; existing `web_*` maps hold case-preserved keys.
Serialization preserves both sets and the schema's actual type, so a string
or floating-point version cannot be silently converted into a valid integer.
Native processing rebuilds incompatible caches; direct manifest consumers
reject them. Completed historical sidecars are not rewritten or upgraded.

No defensive DataFrame copy was added. Index namespaces are built once;
lookups reuse the existing immutable identity cache. Persistent integer row
IDs, original timestamps and explanation accounting are unchanged.

`tests/test_v231_native_path_case.py` exercises positive/negative POSIX and
Windows cases, upload/hash routes, ambiguous roots, JSON round trips and
old-schema rejection. A two-month native test checks both compact and
expanded history: the mismatched request loses its unsupported 12.5 points,
while the correctly linked request retains 27.5 under rules22/weights20.
