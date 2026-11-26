# AegisForge architecture

AegisForge v0.1.10 is a local-first static security workbench. It has no external model API, telemetry endpoint, or cloud runtime requirement.

## Data flow

1. The CLI validates a local directory or starts the loopback-only web server.
2. The scanner traverses supported files while skipping symlinks, dependency/build directories, and files outside bounded resource limits.
3. Text analyzers inspect configuration and common source patterns; Python source is parsed with the standard-library AST module. Static rules cover unsafe YAML deserialization as well as common command, TLS, SQL, and payment-signature mistakes.
4. Findings are represented as immutable data objects with stable rule IDs, severity, location, redacted evidence, remediation, and confidence.
5. Report renderers produce text, Markdown, JSON, or SARIF.
6. Local baselines fingerprint findings and classify them as new, known, or resolved.
7. Repair proposals are generated without writes. Applying requires an explicit CLI flag, preserves backups, checks that files have not changed since preview, rescans, and rolls back when a targeted finding remains.
8. The browser workbench accepts a ZIP only from a same-origin loopback request. It validates archive member names, types, compression ratio, count and size limits; extracts only supported source/configuration files to a temporary directory; scans them without executing them; returns the report; and deletes the temporary directory.
9. The controlled engineering trial engine accepts a strict JSON plan containing only relative paths, expected SHA-256 hashes, and replacement text. It rejects duplicate keys, duplicate paths, unsupported files, stale hashes, traversal paths, and oversized plans.
10. The engine takes a bounded byte snapshot of supported source files, builds baseline and candidate copies in a temporary directory, and scans both copies with the same static rules. It compares rule, severity, path, and redacted evidence; line/column shifts alone do not count as new findings.
11. The trial report classifies a candidate as accepted when no new findings are detected, review when new lower-severity findings appear, or rejected when new critical/high findings or candidate scan errors appear. The temporary workspace is removed after the report is produced.

## Trust boundaries

- The directory, ZIP, and engineering plan being scanned are untrusted input.
- The scanner and trial engine never import or execute content from the scanned project.
- Trial plans cannot specify shell commands, interpreters, arbitrary execution steps, or additional fields.
- A trial never changes the original project; accepted changes still require human review and explicit application.
- The trial compares both scans against the same byte snapshot so source changes during a trial cannot silently alter the baseline.
- ZIP entries are not allowed to create symlinks, special files, absolute paths, traversal paths, duplicate paths, or out-of-root writes.
- Reads and extraction are bounded by per-file, aggregate size, file-count, directory-count and archive-entry limits.
- The browser server binds only to a loopback IP literal and accepts only local Host and same-origin request headers.
- The browser UI renders finding content through text nodes; scan output is not interpreted as HTML. Container rules also identify privileged mode, hostPath mounts and privilege-escalation settings.
- Evidence snippets are redacted before they enter reports.
- Rules are conservative and may produce false positives or miss issues; human review is required. A clean static scan is not proof of security or functional correctness.

## Extension points

New analyzers should return Finding objects and use stable rule IDs in the shared catalog. A rule needs positive and negative tests before it is added. New repair rules must remain preview-first, verify exact source state before writing, preserve an original copy, run a post-check, and restore on verification failure. Future engineering planners may propose plans, but the deterministic trial engine remains the gate that checks scope, hashes, static results, and review status.
