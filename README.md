# AegisForge

**Offline, local-first software security workbench and deterministic engineering runner.** AegisForge reads source code and configuration, reports evidence-backed findings, builds a structural index of Python projects, tracks local baselines, prepares repairs, and sequences approved local tools. It requires no external AI API, telemetry service, or cloud model.

## Current repository build: 0.3.1

The repository includes static analyzers, a bounded scanner, a read-only Python project map, text/Markdown/JSON/SARIF reports, local finding baselines, preview-first repairs, a loopback-only browser workbench, and a permission-gated local mission runner.

### Included checks

- Python dynamic code evaluation, shell-enabled subprocess calls, disabled TLS verification, unsafe pickle/YAML deserialization, formatted SQL, weak hash functions, and ordinary webhook-signature comparisons.
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

### Local browser workbench

Run on the same phone or computer that contains the archive:

~~~bash
aegisforge serve
~~~

Open http://127.0.0.1:8765 in that device's browser. Choose a ZIP archive (maximum 25 MB). The server binds only to 127.0.0.1 or ::1, rejects cross-origin requests, validates ZIP paths and symlinks, enforces extraction limits, scans supported source files in a temporary directory, and removes that directory after the scan. The archive is not sent to a remote host.

### Baselines, repairs and missions

~~~bash
aegisforge baseline create ./my-project
aegisforge baseline compare ./my-project --input ./my-project/.aegisforge/baseline.json
aegisforge repair ./my-project
aegisforge repair ./my-project --apply
aegisforge tools --format json
aegisforge mission audit ./my-project --format json
aegisforge mission audit ./my-project --apply-supported-repairs
aegisforge mission trial ./my-project
aegisforge mission trial ./my-project --plan trial.json --format json
~~~

Baseline comparison reports new, known, and resolved findings. Repair mode previews supported changes by default; --apply is explicit, writes backups under .aegisforge/backups, rescans the project, and restores originals if the targeted finding remains.

The mission runner is a deterministic local workflow engine, not a general AI model. It registers a small explicit set of tools, including read-only Python project mapping and security scanning, prepares supported repair proposals, and pauses for approval before any file changes. --apply-supported-repairs is the explicit approval switch; the mission then runs a fresh verification scan.

Mission trials test candidate text replacements in a disposable workspace and never change the original project or execute candidate code. Without --plan, AegisForge generates a plan from its built-in conservative repair rules. With --plan, it validates a strict JSON plan containing only supported relative paths, expected SHA-256 hashes, and replacement text. Results are accepted (no new static findings), review (new lower-severity findings), rejected (new critical/high findings or incomplete candidate scan), or no_changes (no built-in repair available). Accepted changes still need human review and explicit application.

A scan returns exit code 1 when a finding meets the selected --fail-on threshold (high by default), 0 when no threshold is met, and 2 for an operational error or incomplete scan. Mission trial returns 1 for a rejected candidate and 2 for operational errors. Mission runs return 2 when the workflow fails or cannot complete its scan.

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

Next: extend project understanding beyond Python syntax and expand deterministic engineering missions with stronger isolation and repeatable check runners. AegisForge is not a general autonomous intelligence or a universal system controller.

## License

MIT. See [LICENSE](LICENSE).
