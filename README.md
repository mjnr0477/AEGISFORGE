# AegisForge

AegisForge is a local-first security analysis and controlled software repair toolkit. It runs without an external AI API or cloud model service.

## Current status

The first repository bootstrap is underway. The verified local release is v0.1.6; this repository will become the canonical source of truth once all release files and tests are committed.

## Safety boundary

AegisForge is intended for source code and systems you own or are explicitly authorized to assess. It does not attempt to access accounts, bypass authentication, steal payment credentials, or modify third-party systems. Its initial release performs static analysis and bounded local repair workflows; uploaded code is never executed by the web console.

## Local use

```bash
python -m pip install .
python -m aegisforge --help
python -m unittest discover -s tests -v
```

## License

See `LICENSE`.
