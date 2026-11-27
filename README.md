# AegisForge

**Offline, local-first software security workbench and deterministic engineering runner.** AegisForge reads source code and configuration, reports evidence-backed findings, builds a structural index of Python projects, checks selected local source-to-sink flows, tracks baselines, prepares repairs, and sequences approved tools. It requires no external AI API, telemetry service, or cloud model.

## Current repository build: 0.4.2

The repository includes static analyzers, a bounded scanner, a read-only Python project map, conservative Python data-flow checks, text/Markdown/JSON/SARIF reports, local finding baselines, preview-first repairs, a loopback-only browser workbench, and a permission-gated local mission runner.

### Included checks

- Python dynamic code evaluation, shell-enabled subprocess calls, disabled TLS verification, unsafe pickle/YAML deserialization, formatted SQL, weak hash functions, and ordinary webhook-signature comparisons.
- Local and bounded interprocedural flows from common request/input sources through local assignments and unambiguous synchronous module-level helper calls into dynamic evaluation, shell-enabled subprocess calls, and SQL query text.
- Credential-like literals and private-key markers, with evidence redaction.
- Debug configuration, wildcard CORS combined with credentials, JavaScript dynamic evaluation and innerHTML assignments.
- Container privileged mode, privilege escalation, hostPath mounts, Docker root user, and public SSH/RDP ingress in AWS security-group Terraform resources.

Rules are conservative signals, not proof of exploitability. They can produce false positives and miss issues.

## Install and use

Python 3.10 or newer is required. Runtime scanning and the local workbench use the Python standard library.

~~~bash
python -m pip install .
aegisforge --version
aegisforge rules
aegisforge scan ./path-to-your-project
aegisforge scan ./path-to-your-project --format json --output report.json
aegisforge scan ./path-to-your-project --format sarif --output report.sarif
~~~

### Understand a Python project

~~~bash
aegisforge map ./my-project
aegisforge map ./my-project --format json
~~~

The project map indexes Python modules, imports, classes, functions, and syntactic call sites. It uses the AST without importing or executing project code. If a Python file cannot be parsed, the map records a warning and returns exit code 2 rather than silently treating that file as fully analyzed. This is a structural index, not a complete semantic call graph.

### Local data-flow checks

The scanner follows common Flask, ASGI and Django request expressions, `input()`, and `sys.argv` through simple local assignments and supported async iteration. It normalizes common Python import aliases for request sources and supported sinks (for example, `import subprocess as sp`, `from subprocess import run`, and `from os import system`). It also summarizes unambiguous synchronous module-level functions and propagates taint through positional or keyword helper arguments and returned values across bounded local call chains. Async helper summaries are intentionally excluded so an un-awaited coroutine call is not treated as an executed function body. It checks whether those values reach the actual code, command, or SQL query-text argument of `eval`/`exec`, shell-enabled subprocess calls, and `execute()`. Findings include source-line provenance and the sink location. The interprocedural pass is bounded to 12 summary rounds; async helpers, methods, nested functions, dynamic dispatch, star-argument binding, and cross-file call resolution are not covered. Lambda definitions are not treated as executed return values, although sinks inside lambda bodies are inspected. It deliberately does not flag tainted values used only as parameterized SQL values. Beyond the bounded module-level helper summaries described above, the analyzer does not resolve methods, nested functions, dynamic dispatch, or cross-file calls; it also does not prove sanitizer correctness or cover every framework and source/sink. Treat results as review candidates, not proof of exploitability.

### Local browser workbench

Run on the same phone or computer that contains the archive:

~~~bash
aegisforge serve
~~~

Open http://127.0.0.1:8765 in that device's browser. Choose a ZIP archive (maximum 25 MB). The server binds only to 127.0.0.1 or ::1, rejects cross-origin requests, validates ZIP paths and symlinks, enforces extraction limits, scans supported source files in a temporary directory, and removes that directory after the scan. Results include security findings plus a Python project-structure panel showing modules, classes, functions, imports and call sites. Temporary directory names and absolute source roots are not included in the browser report. The archive is not sent to a remote host.

### Baselines, repairs and missions

~~~bash
aegisforge baseline create ./my-project
aegisforge baseline compare ./my-project --input ./my-project/.aegisforge/baseline.json
aegisforge repair ./my-project
aegisforge repair ./my-project --apply
aegisforge tools --format json
aegisforge mission audit ./my-project --format json
aegisforge mission audit ./my-project --apply-supported-repairs
~~~

Baseline comparison reports new, known, and resolved findings. Repair mode previews supported changes by default; --apply is explicit, writes backups under .aegisforge/backups, rescans the project, and restores originals if the targeted finding remains.

The mission runner is a deterministic local workflow engine, not a general AI model. It maps the Python structure, scans the project, prepares supported repair proposals, and pauses for approval before any file changes. Its report separates built-in repair proposals from findings that still need manual security review. If a mission fails or becomes incomplete, it returns all remaining findings to the manual-review list. --apply-supported-repairs is the explicit approval switch; the mission then runs a fresh verification scan.

A scan returns exit code 1 when a finding meets the selected --fail-on threshold (high by default), 0 when no threshold is met, and 2 for an operational error or incomplete scan. Mission runs return 2 when the workflow fails or cannot complete its scan.

## Safety model

- Only scan source code and systems you own or are explicitly authorized to assess.
- Source files are read and Python is parsed with the AST; scanned code is never imported or executed.
- Malformed Python files are reported as incomplete AST analysis, not silently reported as clean.
- Symlinks are rejected; individual-file, aggregate-byte, file-count, directory-count and entry-count limits bound scanning.
- Browser uploads are accepted only by the loopback server and are never forwarded to another service.
- The local tool registry exposes only explicit built-in tools; mutating calls require explicit approval.
- Evidence is redacted before it enters reports.
- A clean report is not a security certification. Validate findings in context.

See [SECURITY.md](SECURITY.md), [DESIGN.md](DESIGN.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

~~~bash
python -m unittest discover -s tests -v
python -m pip install -e .
aegisforge --help
~~~

GitHub Actions runs the unit suite on Python 3.10, 3.11, 3.12, and 3.13; it also validates the browser JavaScript and checks that built wheels contain the UI assets.

## Roadmap

Next: extend data-flow analysis across more language constructs and frameworks, then strengthen isolated engineering missions. AegisForge is not a general autonomous intelligence or a universal system controller.

## License

MIT. See [LICENSE](LICENSE).
