# AegisForge

**Offline, local-first software security workbench.** AegisForge reads source code and configuration, reports evidence-backed findings, tracks local baselines, supports preview-first repairs, and evaluates proposed edits in disposable workspaces. It requires no external AI API, telemetry service, or cloud model.

## Current repository build: 0.1.10

The repository includes the Python package, static analyzers, bounded scanner, CLI, text/Markdown/JSON/SARIF reports, local finding baselines, verified repair previews, a controlled engineering trial engine, and a browser workbench served only on loopback.

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

### Local browser workbench

Run on the same phone or computer that contains the archive:

~~~bash
aegisforge serve
~~~

Open http://127.0.0.1:8765 in that device's browser. Choose a ZIP archive (maximum 25 MB). The server binds only to 127.0.0.1 or ::1, rejects cross-origin requests, validates ZIP paths and symlinks, enforces extraction limits, scans supported source files in a temporary directory, and removes that directory after the scan. The archive is not sent to a remote host.

### Baselines and repairs

~~~bash
aegisforge baseline create ./my-project
aegisforge baseline compare ./my-project --input ./my-project/.aegisforge/baseline.json
aegisforge repair ./my-project
aegisforge repair ./my-project --apply
~~~

Baseline comparison reports new, known, and resolved findings. Repair mode previews supported changes by default; --apply is explicit, writes backups under .aegisforge/backups, rescans the project, and restores originals if the targeted finding remains.

### Controlled engineering trials

The trial engine evaluates proposed file replacements without changing the original project or executing candidate code. A plan contains only existing supported file paths, each file's expected SHA-256, and replacement text.

~~~bash
aegisforge engine trial ./my-project --plan trial.json --output trial-report.json
aegisforge engine repair-trial ./my-project --output repair-trial.json
~~~

Minimal plan shape:

~~~json
{
  "schema_version": 1,
  "changes": [
    {
      "path": "app.py",
      "expected_sha256": "64-lowercase-hex-characters-for-the-original-file",
      "replacement": "result = user_input\n"
    }
  ]
}
~~~

Create the expected hash from the exact original file bytes. For example:

~~~python
from pathlib import Path
import hashlib
import json

source = Path("my-project/app.py")
plan = {
    "schema_version": 1,
    "changes": [{
        "path": "app.py",
        "expected_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "replacement": "result = user_input\n",
    }],
}
Path("trial.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
~~~

The engine snapshots supported files, verifies every expected hash, builds baseline and candidate copies in a temporary directory, then compares static findings. It returns **accepted** when no new findings are detected, **review** when new lower-severity findings appear, and **rejected** when new critical/high findings or candidate scan errors appear. A rejected trial exits with code 1; operational errors exit with code 2. The temporary workspace is deleted after the report is built.

A trial is not a functional test or proof of exploitability. Accepted changes still require human review and explicit application to the original project.

The guided repair trial uses AegisForge's existing conservative repair rules to generate a hash-checked plan, then evaluates it in the disposable workspace. It does not apply the repair. It returns `no_changes` when no built-in repair is available. This is deterministic rule-based planning, not an external AI model.

A scan returns exit code 1 when a finding meets the selected --fail-on threshold (high by default), 0 when no threshold is met, and 2 for an operational error or incomplete scan.

## Safety model

- Only scan source code and systems you own or are explicitly authorized to assess.
- Source files are read and Python is parsed with the AST; scanned code is never imported or executed.
- Trial plans accept only hash-checked text replacements; arbitrary commands and additional plan fields are rejected.
- Trial work happens in disposable copies. The original project is never modified by the trial engine.
- Symlinks are rejected; individual-file, aggregate-byte, file-count, directory-count and entry-count limits bound scanning.
- Browser uploads are accepted only by the loopback server and are never forwarded to another service.
- Evidence is redacted before it enters reports.
- A clean report is not a security certification. Validate findings in context.

See [SECURITY.md](SECURITY.md), [DESIGN.md](DESIGN.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

~~~bash
python -m unittest discover -s tests -v
python -m pip install -e .
aegisforge --help
~~~

GitHub Actions runs the unit suite on Python 3.10, 3.11, 3.12, and 3.13.

## Roadmap

The next research milestone is a reviewable planner that can construct candidate changes from explicit engineering goals, followed by additional deterministic checks and optional user-configured tests. AegisForge is not yet a general autonomous intelligence or a universal system controller.

## License

MIT. See [LICENSE](LICENSE).
