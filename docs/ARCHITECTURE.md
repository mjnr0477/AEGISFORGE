# AegisForge architecture

AegisForge v0.4.2 is a local-first static security workbench, Python source mapper, conservative source-to-sink analyzer, and deterministic mission runner. It has no external model API, telemetry endpoint, or cloud runtime requirement.

## Data flow

1. The CLI validates a local directory or starts the loopback-only web server.
2. The scanner traverses supported files while skipping symlinks, dependency/build directories, and files outside bounded resource limits.
3. Text analyzers inspect configuration and common source patterns; Python source is parsed with the standard-library AST module. Static rules cover unsafe YAML deserialization as well as common command, TLS, SQL, and payment-signature mistakes.
4. The Python project mapper creates a structural index of modules, imports, class/function definitions, enclosing scopes, and syntactic call sites. It does not resolve dynamic dispatch or claim a complete semantic call graph.
5. The Python data-flow visitor tracks common Flask, ASGI and Django request sources, `input()`, and `sys.argv` through local assignments and supported async iteration. It resolves common import aliases for Flask request objects, subprocess and os modules, and explicitly imported sink functions, while keeping function-local aliases from leaking into sibling scopes. A bounded fixed-point summary pass propagates parameter and return taint through unambiguous synchronous module-level helper functions using positional and keyword arguments. The pass is capped at 12 rounds and does not cover async helpers, methods, nested functions, dynamic dispatch, star-argument binding, or cross-file calls. It records source-line provenance and flags candidate flows into the first code/command/query argument of dynamic evaluation, shell-enabled subprocess commands, and SQL execution. It isolates class/function/lambda state, skips summary resolution when a helper name is shadowed by a local binding, and does not confuse a lambda's deferred return value with an immediately evaluated value. It is a bounded approximation; it does not establish exploitability or track all language/framework constructs.
6. Malformed Python creates an explicit incomplete-analysis warning. A scan that cannot parse one of its Python files is not represented as a clean AST analysis.
7. Findings are represented as immutable data objects with stable rule IDs, severity, location, redacted evidence, remediation, and confidence.
8. Report renderers produce text, Markdown, JSON, or SARIF.
9. Local baselines fingerprint findings and classify them as new, known, or resolved.
10. Repair proposals are generated without writes. Applying requires an explicit CLI flag, preserves backups, checks that files have not changed since preview, validates that the proposal exactly matches a built-in deterministic transformation, rescans, and rolls back when a targeted finding remains or a source-validation error occurs.
11. The browser workbench accepts a ZIP only from a same-origin loopback request. It validates archive member names, types, compression ratio, count and size limits; extracts only supported source/configuration files to a temporary directory; scans them without executing them; and deletes that directory after the response is built. The response includes security findings plus a Python structural map (module/import/class/function/call-site metadata). Paths remain relative to the uploaded archive, and the random temporary extraction directory name is replaced by a neutral label.
12. The mission runner uses an explicit registry of built-in local tools, including read-only project mapping. Each tool declares whether it mutates project data. The runner maps the project, scans it, prepares supported repair proposals, pauses in an approval-required state by default, and only calls the mutating repair tool when the user supplies the explicit approval flag. A fresh scan verifies the outcome. Mission results classify findings not covered by deterministic repairs as manual-review work; failed or incomplete missions expose every remaining finding for human review.

## Trust boundaries

- The directory or ZIP being scanned is untrusted input.
- The scanner, project mapper, and data-flow analyzer never import or execute content from the scanned project.
- Data-flow findings are candidates based on a deliberately limited source/sink list; the analyzer does not prove exploitability or sanitizer correctness.
- ZIP entries are not allowed to create symlinks, special files, absolute paths, traversal paths, duplicate paths, or out-of-root writes.
- Reads and extraction are bounded by per-file, aggregate size, file-count, directory-count and archive-entry limits.
- The browser server binds only to a loopback IP literal and accepts only local Host and same-origin request headers.
- The browser response uses relative file locations and a neutral project label; it does not expose the temporary extraction directory name or absolute host filesystem paths.
- The browser UI renders finding content through text nodes; scan output is not interpreted as HTML. It also renders project-map fields through text nodes.
- Container rules identify privileged mode, hostPath mounts and privilege-escalation settings.
- The local tool registry does not perform dynamic discovery or import plugins. Its catalog exposes tool names, descriptions, and mutation flags but not callable handlers.
- Mutating tool calls require explicit approval at the registry boundary.
- Evidence snippets are redacted before they enter reports.
- Rules are conservative and may produce false positives or miss issues; human review is required.

## Extension points

New analyzers should return Finding objects and use stable rule IDs in the shared catalog. A rule needs positive and negative tests before it is added. New repair rules must remain preview-first, verify exact source state before writing, preserve an original copy, run a post-check, and restore on verification failure. New mission tools must be explicitly registered, declare their mutation behavior, and have an approval-gate test when they can change data. New project-map visitors must remain bounded, AST-only, and side-effect-free. Data-flow extensions must add explicit positive and negative test cases for each new source, propagation rule, and sink. Browser result features must keep user-provided report data as text and must not expose temporary archive paths.

## Honest capability boundary

The mission runner is a deterministic workflow and permission-gated tool-execution foundation. The project map is a syntactic structure index, not a general semantic reasoner. The data-flow analyzer is a limited static approximation, not a complete taint engine. AegisForge is not a trained general-purpose AI model, does not autonomously invent objectives, and cannot control arbitrary software or devices. Those would require separate engineering, model research, and carefully scoped device adapters.
