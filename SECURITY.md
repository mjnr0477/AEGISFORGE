# Security Policy

AegisForge is a local-first static security analysis tool. Use it only on source code and systems you own or have explicit authorization to assess.

## Reporting a vulnerability in AegisForge

Please do not publish secrets, personal data, or exploitable details in a public issue. Contact the maintainers privately through the repository owner's GitHub profile and include:
- affected version and commit;
- reproducible steps using a local test fixture;
- expected and actual behavior;
- potential impact.

## Scope and limitations

A finding is a signal for human validation, not proof of exploitability. A clean scan is not a security certification. The scanner and engineering trial engine read source files but do not import or execute scanned code. Trial plans support only bounded, hash-checked replacement text in disposable workspaces; they do not accept shell commands or remote targets. A trial never changes the original project. AegisForge does not attempt to access accounts, bypass authentication, compromise third-party systems, or perform unauthorized transactions.
