# AegisForge architecture

AegisForge v0.2.1 is a local-first static security workbench and deterministic mission runner. It has no external model API, telemetry endpoint, or cloud runtime requirement.

## Data flow

1. The CLI validates a local directory or starts the loopback-only web server.
2. The scanner traverses supported files while skipping symlinks, dependency/build directories, and files outside bounded resource limits.
3. Text analyzers inspect configuration and common source patterns; Python source is parsed with the standard-library AST module. Static rules cover unsafe YAML deserialization as well as common command, TLS, SQL, and payment-signature mistakes.
4. Findings are represented as immutable data objects with stable rule IDs, severity, location, redacted evidence, remediation, and confidence.
5. Report renderers produce text, Markdown, JSON, or SARIF.
6. Local baselines fingerprint findings and classify them as new, known, or resolved.
7. Repair proposals are generated without writes. Applying requires an explicit CLI flag, preserves backups, checks that files have not changed since preview, validates that the proposal exactly matches a built-in deterministic transformation, rescans, and rolls back when a targeted finding remains.
8. The browser workbench accepts a ZIP only from a same-origin loopback request. It validates archive member names, types, compression ratio, count and size limits; extracts only supported source/configuration files to a temporary directory; scans them without executing them; returns the report; and deletes the temporary directory.
9. The mission runner uses an explicit registry of built-in local tools. Each tool declares whether it mutates project data. The runner performs a scan, prepares supported repair proposals, pauses in an approval-required state by default, and only calls the mutating repair tool when the user supplies the explicit approval flag. A fresh scan verifies the outcome.
10. The mission trial command loads either a strict hash-checked change plan or a plan generated from the built-in deterministic repair previews.
11. Trial execution snapshots supported files, creates separate baseline and candidate copies in a temporary directory, applies replacements only to the candidate, and compares static findings. It does not run shell commands or candidate project code.
12. The trial report classifies results as accepted, review, rejected, or no_changes and deletes the temporary workspace after producing the report. The original project remains unchanged.

## Trust boundaries

- The directory or ZIP being scanned is untrusted input.
- The scanner never imports or executes content from the scanned project.
- ZIP entries are not allowed to create symlinks, special files, absolute paths, traversal paths, duplicate paths, or out-of-root writes.
- Reads and extraction are bounded by per-file, aggregate size, file-count, directory-count and archive-entry limits.
- The browser server binds only to a loopback IP literal and accepts only local Host and same-origin request headers.
- The browser UI renders finding content through text nodes; scan output is not interpreted as HTML. Container rules also identify privileged mode, hostPath mounts and privilege-escalation settings.
- The local tool registry does not perform dynamic discovery or import plugins. Its catalog exposes tool names, descriptions, and mutation flags but not callable handlers.
- Mutating tool calls require explicit approval at the registry boundary.
- Evidence snippets are redacted before they enter reports.
- Rules are conservative and may produce false positives or miss issues; human review is required.

## Extension points

New analyzers should return Finding objects and use stable rule IDs in the shared catalog. A rule needs positive and negative tests before it is added. New repair rules must remain preview-first, verify exact source state before writing, preserve an original copy, run a post-check, and restore on verification failure. New mission tools must be explicitly registered, declare their mutation behavior, and have an approval-gate test when they can change data. Trial planning must remain declarative, path-bounded, hash-checked, and unable to execute candidate code.

## Honest capability boundary

The mission runner is a deterministic workflow and permission-gated tool-execution foundation. It is not a trained general-purpose AI model, does not autonomously invent objectives, and cannot control arbitrary software or devices. Those would require separate engineering, model research, and carefully scoped device adapters.
