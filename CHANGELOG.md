# Changelog

## Unreleased

- Add a bounded internal Python import dependency map for absolute, package-relative, and namespace-package references.
- Label ambiguous from-import submodule matches as possible and omit unresolved external, invalid-relative, and duplicate-module references.
- Include dependency edges and cross-file call records in JSON and text project maps, audit mission summaries, and the local browser workbench.
- Add conservative cross-file call edges for uniquely resolved module-scope imports; skip function-local imports, shadowed or mutated aliases, duplicate bindings, and wildcard imports, and label package-attribute/submodule collisions as ambiguous.
- Keep project mapping AST-only; scanned project code is never imported or executed.

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
