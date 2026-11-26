# AegisForge architecture

AegisForge v0.1.7 is a local-first static analyzer with no external model API, telemetry endpoint, or cloud runtime requirement.

## Data flow

1. The CLI validates the requested local directory.
2. The scanner traverses supported files while skipping symlinks, dependency/build directories, and files outside bounded resource limits.
3. Text analyzers inspect configuration and common source patterns.
4. Python source is parsed with the standard-library AST module. Source is never imported or executed.
5. Findings are represented as immutable data objects with rule identifiers, severity, location, redacted evidence, and remediation guidance.
6. Report renderers produce text, Markdown, JSON, or SARIF.

## Trust boundaries

- The directory being scanned is untrusted input.
- The scanner never executes content from the scanned directory.
- Reads are size bounded and symlinks are rejected.
- Evidence snippets are redacted before they enter reports.
- Rules are conservative and may produce false positives or miss issues; human review is required.

## Extension points

New analyzers should return Finding objects and use stable rule IDs in the shared catalog. A rule needs a test for a positive case and a negative case before it is added to the release.
