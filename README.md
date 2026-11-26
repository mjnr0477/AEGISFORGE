# AegisForge

**Offline, local-first software security analysis.** AegisForge reads source code and configuration, reports evidence-backed findings, and runs without external AI APIs, telemetry, or a cloud model service.

## Current repository build: 0.1.7

The repository contains the Python package, static analyzers, bounded local scanner, command-line interface, report renderers, and unit tests.

### Included checks

- Python dynamic code evaluation, shell-enabled subprocess calls, disabled TLS verification, unsafe pickle loading, formatted SQL, weak hash functions, and ordinary webhook-signature comparisons.
- Credential-like literals and private-key markers, with evidence redaction.
- Debug configuration, wildcard CORS combined with credentials, JavaScript dynamic evaluation and innerHTML assignments.
- Container privileged mode, hostPath mounts, Docker root user, and public SSH/RDP ingress in AWS security-group Terraform resources.

Rules are conservative signals, not proof of exploitability. They can produce false positives and miss issues.

## Install and use

Python 3.10 or newer is required. The package uses only the Python standard library at runtime.

~~~bash
python -m pip install .
aegisforge --version
aegisforge rules
aegisforge scan ./path-to-your-project
aegisforge scan ./path-to-your-project --format json --output report.json
aegisforge scan ./path-to-your-project --format sarif --output report.sarif
~~~

A scan returns exit code 1 when a finding meets the selected --fail-on threshold (high by default), 0 when no threshold is met, and 2 for an operational error.

## Safety model

- Only scan source code and systems you own or are explicitly authorized to assess.
- Source files are read and Python is parsed with the AST; scanned code is never imported or executed.
- Symlinks are rejected; individual file, aggregate byte, file-count, directory-count and entry-count limits bound scanning.
- Evidence is redacted before it enters reports.
- A clean report is not a security certification. Validate findings in context.

See [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

~~~bash
python -m unittest discover -s tests -v
python -m pip install -e .
aegisforge --help
~~~

## Roadmap

The next planned work is to synchronize the verified local repair, baseline, and browser-console modules into this canonical GitHub repository, then develop an isolated engineering loop for previewing changes, running checks, and rolling back failed modifications. No external AI API is required for the current scope.

## License

MIT. See [LICENSE](LICENSE).
