# Changelog

## 0.5.0 — scoped authority kernel

- Added a default-deny capability model with exact-resource, subject-specific and expiring grants.
- Required short-lived, exact-scope, single-use approval tokens for capabilities marked as mutating.
- Added a hash-chained JSONL decision ledger that fails closed on detected tampering or write failures.
- Added a policy-file loader and an `authority check` CLI command; checks evaluate permission only and never execute the requested operation.
- Added tests for scope isolation, expiration, approval reuse, policy validation, audit integrity and CLI outcomes.
- Clarified that external service/device adapters and authenticated approval UX are separate future integrations.
- Added resource-scope resolvers so tools bind grants to the actual target argument.
- Integrated mission mapping, scanning, repair previews, approved repair application, and post-repair verification with the Authority Kernel.
- Added tests for exact project binding, missing grants, missing approvals, and successful authorized repairs.
- Added an explicit authority-gated adapter registry with per-operation capability, input validation, mutation classification, and exact resource resolution.
- Added an in-memory simulation adapter and tests for approval gating, denial paths, unknown operations, and metadata-only catalogs; no live service/device access is enabled.
- Restricted adapter payloads to bounded JSON data and froze nested inputs before validation, scope resolution, and handler execution.
- Snapshotted registered operation handlers and added separate simulated service-restart and device-mode operations with distinct capabilities.
- Added CI coverage for the interactive simulator's approved and declined mutation paths, including audit-ledger assertions.
- Packaged the simulator walkthrough as the `aegisforge-sim-demo` console command, with safe EOF/interrupt behavior and wheel-entry-point checks.
- Added a concurrent invocation regression test proving a one-time mutation approval can execute only once when two calls race.
- Packaged the simulator walkthrough as `aegisforge-sim-demo` and made non-interactive EOF/interrupt defaults decline all pending mutations.


## 0.1.7 — repository bootstrap

- Added Python package metadata and module/console entry points.
- Added initial rules for Python, JavaScript, credential exposure, container configuration, and Docker user configuration.
- Added bounded local scanning with symlink rejection and resource limits.
- Added text, Markdown, JSON, and SARIF report formats.
- Added evidence redaction for common credential patterns.
- Added unit tests and GitHub Actions coverage for Python 3.10–3.13.

This repository bootstrap is a focused source baseline. Additional modules from the local development release (repair, baselines, infrastructure-specific checks, and local browser console) are scheduled for synchronization and separate verification before they are declared part of the canonical GitHub release.

- Added detection of direct webhook-signature equality and public SSH/RDP ingress in AWS security-group Terraform.
- Added vulnerable/hardened webhook fixtures and IPv6/comment-boundary regression tests.
- Updated package metadata to a current SPDX license declaration.

## 0.1.8 — local workbench

- Added a responsive local browser workbench with ZIP upload, severity filters, evidence cards and JSON report export.
- Added a loopback-only server restricted to 127.0.0.1 or ::1 with same-origin request validation and security headers.
- Added ZIP validation for traversal, absolute paths, duplicate paths, symlinks, special files, encrypted entries, compression ratio and extraction limits.
- Added local finding baselines with integrity-checked fingerprints and new/known/resolved comparison.
- Added preview-first repairs with backups, stale-file checks, post-scan verification and rollback.
- Added end-to-end tests for CLI, archive handling, upload security and repairs.

## 0.1.9 — additional security rules

- Added detection of unsafe PyYAML load/unsafe_load calls while allowing SafeLoader and safe_load.
- Added detection of container configurations that enable privilege escalation.
- Added positive and negative regression tests for both rules.

## 0.2.0 — deterministic mission engine

- Added an explicit local tool registry with a serializable catalog and clear read-only versus mutating capabilities.
- Required explicit approval before a registered mutating tool can execute.
- Added a local security-audit mission that sequences scanning, repair proposal generation, optional approved application, and post-change verification.
- Added CLI commands for inspecting local tools and running the audit mission.
- Added mission-level tests for permission gating, clean projects, incomplete scans, preview-only behavior, and approved repair verification.

## 0.3.0 — Python project structure map

- Added a read-only AST index of Python modules, imports, classes, functions, and syntactic call sites.
- Added the `aegisforge map` CLI command with text and JSON output.
- Registered project mapping as a read-only local tool.
- Changed malformed Python handling to surface explicit incomplete-analysis warnings instead of silently returning no AST findings.
- Added tests for structural indexing, parse failures, symlink handling, resource-limit warnings, relative-only paths, and non-execution of indexed code.

## 0.4.0 — conservative Python source-to-sink analysis

- Added bounded intra-function taint propagation from common Flask request expressions, `input()`, and `sys.argv` through local variable assignments.
- Added candidate findings when tainted values reach `eval`/`exec`, shell-enabled subprocess calls, or SQL query text passed to `execute()`.
- Added negative tests for parameterized SQL values, unused input, and constant expressions.
- Documented analysis limits: no interprocedural flow, complete sanitizer reasoning, or universal framework coverage.

## 0.4.1 — flow provenance and review clarity

- Added source-line provenance to intra-function data-flow findings.
- Expanded recognized request sources to common Flask, ASGI and Django request objects.
- Added conservative async-iteration propagation and isolated lambda definition state from later expressions.
- Kept sinks argument-specific so untrusted values in unrelated keyword options are not treated as command/query injection.
- Added a manual-review finding list to missions; failed or incomplete missions expose all remaining findings for human review.
- Added regression tests for async loops, lambda boundaries, source-line provenance, framework request sources and failed mission repair review.

## 0.4.2 — browser project map

- Included a read-only Python structural index in local ZIP scan responses.
- Added a browser panel for Python module, class, function, import and call-site counts, with a compact module list.
- Preserved archive-relative source paths and replaced random temporary folder names with a neutral project label in reports.
- Added archive-response, UI-rendering and small-screen layout checks.
