# AegisForge

**Offline, local-first software security workbench and deterministic engineering runner.** AegisForge reads source code and configuration, reports evidence-backed findings, builds a structural index of Python projects, checks selected local source-to-sink flows, tracks baselines, prepares repairs, and sequences approved tools. It requires no external AI API, telemetry service, or cloud model.

## Current repository build: 0.5.0

The repository includes static analyzers, a bounded scanner, a read-only Python project map, conservative Python data-flow checks, text/Markdown/JSON/SARIF reports, local finding baselines, preview-first repairs, a loopback-only browser workbench, a deterministic mission runner, and a default-deny authority kernel.

### Included checks

- Python dynamic code evaluation, shell-enabled subprocess calls, disabled TLS verification, unsafe pickle/YAML deserialization, formatted SQL, weak hash functions, and ordinary webhook-signature comparisons.
- Intra-function flows from common request/input sources through simple local assignments into dynamic evaluation, shell-enabled subprocess calls, and SQL query text.
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

The scanner follows common Flask, ASGI and Django request expressions, `input()`, and `sys.argv` through simple local assignments and supported async iteration. It checks whether those values reach the actual code, command, or SQL query-text argument of `eval`/`exec`, shell-enabled subprocess calls, and `execute()`. Findings include the input source line and sink location. Lambda definitions are not treated as executed return values, although sinks inside lambda bodies are inspected. It deliberately does not flag tainted values used only as parameterized SQL values. The analyzer does not track flows across function boundaries, prove sanitizer correctness, or cover every framework and source/sink. Treat results as review candidates, not proof of exploitability.

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

aegisforge authority check --policy ./authority-policy.json \
  --audit-log ./.aegisforge/authority.jsonl \
  --subject operator --capability project.inspect \
  --resource project:/absolute/path/to/my-project
~~~

Baseline comparison reports new, known, and resolved findings. Repair mode previews supported changes by default; --apply is explicit, writes backups under .aegisforge/backups, rescans the project, and restores originals if the targeted finding remains.

The mission runner is a deterministic local workflow engine, not a general AI model. It maps the Python structure, scans the project, prepares supported repair proposals, and pauses for approval before any file changes. Its report separates built-in repair proposals from findings that still need manual security review. If a mission fails or becomes incomplete, it returns all remaining findings to the manual-review list. --apply-supported-repairs is the explicit approval switch; the mission then runs a fresh verification scan.

A scan returns exit code 1 when a finding meets the selected --fail-on threshold (high by default), 0 when no threshold is met, and 2 for an operational error or incomplete scan. Mission runs return 2 when the workflow fails or cannot complete its scan.

### Scoped authority checks

The authority kernel evaluates a policy; it does not execute the requested operation. Policies use exact subject, capability, and resource matches, with an expiry on every grant. Unknown capabilities, missing grants, and expired grants are denied. Wildcards and implicit inheritance are not supported.

The Python mission API can enforce the policy before every registered operation. The tool registry derives each project resource from the actual target argument, so callers cannot authorize one path and pass another path to the handler:

~~~python
from aegisforge.authority import AuthorityKernel, DEFAULT_CAPABILITIES
from aegisforge.autonomy import run_audit_mission

kernel = AuthorityKernel.from_policy_file(
    DEFAULT_CAPABILITIES,
    "authority-policy.json",
    audit_path=".aegisforge/authority.jsonl",
)
preview = run_audit_mission(
    "./my-project",
    authority=kernel,
    subject="authenticated-user-id",  # supplied by the authenticated host
)
~~~

For a repair, the host must first authenticate the approver and obtain explicit consent. It then issues an approval for the exact target scope and passes the short-lived token to a separate mission call:

~~~python
from pathlib import Path

target = Path("./my-project").expanduser().resolve()
resource = f"project:{target.as_posix()}"
token = kernel.issue_approval(
    subject="authenticated-user-id",
    capability="project.repair",
    resource=resource,
    approver="authenticated-approver-id",
)
result = run_audit_mission(
    target,
    apply_supported_repairs=True,
    authority=kernel,
    subject="authenticated-user-id",
    approval_token=token,
)
~~~

A token is single-use and must be newly issued after a fresh approval. The host remains responsible for authentication, policy-file protection, and presenting the proposed diff to the approver. The legacy CLI mission mode remains available for local workflows; it does not authenticate users and is not a substitute for the host-integrated Authority Kernel path.

Example policy file:

~~~json
{
  "version": 1,
  "grants": [
    {
      "subject": "operator",
      "capability": "project.inspect",
      "resource": "project:/absolute/path/to/my-project",
      "expires_at": "2030-01-01T00:00:00Z"
    }
  ]
}
~~~

The capability vocabulary is `project.inspect`, `project.repair`, `service.inspect`, `service.restart`, `device.inspect`, and `device.control`. This release includes only an in-memory simulator for service inspection/restart and simulated device-mode changes. It does not ship live service/device connectors or arbitrary command execution.

Run the interactive local simulator with `aegisforge-sim-demo` after installation, or `python examples/simulation_demo.py` from a source checkout. It demonstrates the read path and asks for a separate confirmation before each simulated mutation. Its fixed subject/approver labels are demo placeholders, not authentication; a real host must authenticate both identities before issuing an approval token. The demo writes its decision ledger to `.aegisforge/simulation-audit.jsonl`.

Python integrations can route a registered local tool through `ToolRegistry.call_authorized`, which checks the tool's declared capability and mutation classification before invoking its handler. Capabilities marked as mutating need an active grant plus a short-lived, exact-scope, single-use approval token. The host must authenticate the caller identity and the approver, protect the policy file from untrusted writes, and obtain explicit human consent before calling the Python API's `issue_approval` method. The kernel and CLI do not authenticate identities; the CLI's `--subject` value is only an asserted label for policy evaluation. `issue_approval` is not an authentication system and must never be exposed directly to unauthenticated clients. The CLI check intentionally cannot manufacture or pass mutation approvals, so it denies mutating checks with `approval_required`.

When an audit path is configured (and always for the CLI), approvals and authorization decisions append to a local JSONL hash chain. Authorized adapter and local-tool invocations also append an execution_started event before the handler and a linked execution_result event afterward, with outcome, elapsed milliseconds, and exception class only (not raw output or exception text). Python callers that omit an audit path retain events only in process memory; production hosts should configure a persistent path. Detected edits, reordering, truncation after the process has loaded the log, or write failures block authorization or the next execution phase. A handler that raises may have performed partial side effects. A start without a result means the operation's final outcome is unknown; reconcile the target before retrying. If the final result cannot be recorded, the authorized caller receives a reconciliation error rather than a normal success response. The hash chain is tamper-evident, not tamper-proof against a privileged attacker who can rewrite the entire log. Use one process per audit log. The CLI returns exit code 0 for allow, 1 for deny, and 2 for an operational or policy error.


## Safety model

- Only scan source code and systems you own or are explicitly authorized to assess.
- Source files are read and Python is parsed with the AST; scanned code is never imported or executed.
- Malformed Python files are reported as incomplete AST analysis, not silently reported as clean.
- Symlinks are rejected; individual-file, aggregate-byte, file-count, directory-count and entry-count limits bound scanning.
- Browser uploads are accepted only by the loopback server and are never forwarded to another service.
- The local tool registry exposes only explicit built-in tools; mutating calls require explicit approval.
- The authority kernel defaults to deny, matches exact resource scopes, requires expiring grants, and requires a one-time human approval token for mutating capability decisions.
- Evidence is redacted before it enters reports.
- A clean report is not a security certification. Validate findings in context.

See [SECURITY.md](SECURITY.md), [DESIGN.md](DESIGN.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the [adapter engineering contract](docs/ADAPTERS.md).

## Development

~~~bash
python -m unittest discover -s tests -v
python -m pip install -e .
aegisforge --help
~~~

GitHub Actions runs the unit suite on Python 3.10, 3.11, 3.12, and 3.13; it also validates the browser JavaScript and checks that built wheels contain the UI assets.

## Roadmap

The adapter boundary and an in-memory simulator are now included. Adapter calls accept bounded JSON-only arguments (deeply frozen before validation, scope resolution and handler execution); adapter handlers and operation declarations are snapshotted at registration. The simulator offers status inspection, simulated service restart, and simulated mode changes, with separate capabilities and one-time approval for state changes. It has no operating-system, network, live-service, or physical-device access. Next: build one narrowly scoped, real integration behind that boundary only after its authentication, resource identity, failure modes, and rollback behavior are independently reviewed and tested. AegisForge is not a general autonomous intelligence or a universal system controller.

## License

MIT. See [LICENSE](LICENSE).
