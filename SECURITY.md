# Security Policy

AegisForge is a local-first static security analysis tool. Use it only on source code and systems you own or have explicit authorization to assess.

## Reporting a vulnerability in AegisForge

Please do not publish secrets, personal data, or exploitable details in a public issue. Contact the maintainers privately through the repository owner's GitHub profile and include:
- affected version and commit;
- reproducible steps using a local test fixture;
- expected and actual behavior;
- potential impact.

## Scope and limitations

A finding is a signal for human validation, not proof of exploitability. A clean scan is not a security certification. The scanner reads source files; it does not import or execute scanned code. It does not attempt to access accounts, bypass authentication, compromise third-party systems, or perform unauthorized transactions.

The Authority Kernel is default-deny and matches exact subjects, capabilities, resources, and expiries. It does not authenticate users or approvers. Applications must authenticate both identities, protect policy files, show the intended operation, and obtain explicit consent before issuing a one-time mutation token. Tokens expire within 15 minutes; pending token storage is bounded to 4,096 entries per kernel and expired entries are cleaned up during issuance/authorization activity. Never expose the approval-issuance method directly to an unauthenticated client.

Adapters are trusted code explicitly registered by the host application. The registry does not load plugins dynamically, run shell commands, or make network requests. Adapter inputs are bounded plain JSON values, copied and frozen before validation, scope resolution, and handler execution. The bundled adapter is an in-memory simulator only; it does not control a real service, device, or host resource. Do not describe the simulator as a production integration.

The optional JSONL audit chain is tamper-evident, not tamper-proof against an attacker able to rewrite the entire log. Production hosts should restrict write access to the policy and audit paths and use one process per audit log.
