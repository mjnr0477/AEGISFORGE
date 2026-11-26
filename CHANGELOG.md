# Changelog

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
