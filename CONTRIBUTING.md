# Contributing to secret-leak-sentinel

Thank you for your interest in contributing. This document covers how to get set up and what we expect from contributions.

---

## Getting started

1. Fork the repository and clone your fork.
2. Create a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Create a feature branch from `main`:

   ```bash
   git checkout -b feat/your-contribution
   ```

---

## Types of contributions

- **New detector patterns** — add entries to `DETECTOR_PATTERNS` in `detectors/regex_detector.py`
- **New scanner backends** — follow the pattern in `scanners/filesystem_scanner.py`
- **Bug fixes** — check issues labelled `bug`
- **Tests** — more test coverage is always welcome
- **Documentation** — improvements to `docs/` or tutorials

---

## Adding a new detector pattern

1. Add a `DetectorPattern` entry to `DETECTOR_PATTERNS` in `detectors/regex_detector.py`.
2. Choose the appropriate `SecretType` and `Criticality`.
3. Write a clear `description` that explains what the pattern matches and why it is a risk.
4. Add at least two test cases to `tests/test_regex_detector.py`: one that matches and one that does not.
5. Test the pattern against known false positive sources (test files, documentation, minified JS).

**Important:** Never include real credentials in test cases — always use synthetic examples.

---

## Security considerations for contributors

- Never commit real API keys, tokens, or passwords — even in test fixtures.
- Use clearly synthetic values in tests (e.g., `AKIAIOSFODNN7EXAMPLE`, `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`).
- If you accidentally commit a real credential, rotate it immediately and then remove it from git history.

---

## Coding conventions

- Python 3.11+ with modern type hints
- `black` for formatting, `ruff` for linting: `make lint`
- All public functions must have docstrings
- Use `structlog` for logging
- Pydantic models in `schemas/`, dataclasses elsewhere

---

## Pull request checklist

- [ ] Tests pass: `pytest`
- [ ] Linting passes: `make lint`
- [ ] New patterns have test coverage
- [ ] No real credentials in any file
- [ ] PR description explains the motivation

---

## Commit message style

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Slack webhook token detector
fix: prevent entropy detector from flagging base64-encoded images
docs: add remediation guide for private key exposure
```

## Code of Conduct

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
