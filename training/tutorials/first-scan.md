# Tutorial: Your First Secret Scan

This tutorial walks you through scanning a local directory for secrets from scratch.

## Prerequisites

- Python 3.11+
- A directory or git repository to scan

## Step 1: Install

```bash
git clone https://github.com/hiagokinlevi/secret-leak-sentinel.git
cd secret-leak-sentinel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify:

```bash
k1n-sentinel --help
```

## Step 2: Configure

```bash
cp .env.example .env
```

The defaults are sensible for a first scan. Leave them as-is.

## Step 3: See what detectors are active

```bash
k1n-sentinel list-detectors
```

This shows all regex patterns the tool will use during scanning.

## Step 4: Scan a directory

```bash
k1n-sentinel scan-path ./my-project
```

You'll see a colour-coded table of findings (if any) and a line like:

```
Report written to: scan-results/secret_scan_20260401_143022.md
```

## Step 5: Understand the output

A finding table looks like:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Secret Detection Findings                             │
├───┬───────────┬───────────────────────────┬──────┬────────────────┬─────────┤
│ # │ Criticality│ File                     │ Line │ Detector       │Confidence│
├───┼───────────┼───────────────────────────┼──────┼────────────────┼─────────┤
│ 1 │ CRITICAL  │ config/deploy.env         │   12 │ aws_access_key │   87%    │
│ 2 │ HIGH      │ src/db.py                 │   45 │ database_conn  │   65%    │
└───┴───────────┴───────────────────────────┴──────┴────────────────┴─────────┘
```

- **CRITICAL** findings should be rotated immediately.
- **HIGH** findings require review and likely rotation.
- **MEDIUM/LOW** findings are worth investigating but may be false positives.

## Step 6: Review the Markdown report

```bash
open scan-results/secret_scan_20260401_143022.md
```

The report provides masked excerpts, confidence scores, and remediation steps for each finding.

## Step 7: Handle findings

For each genuine finding:
1. Rotate the credential (see `docs/remediation-guides/credential-rotation.md`)
2. Remove the credential from the file
3. If it was committed to git, rewrite the history

For false positives:
1. Add a suppression entry to `.k1n-suppressions.yaml`

## Step 8: Install the pre-commit hook

Prevent future leaks at the source:

```bash
cp hooks/pre-commit/k1n-secret-check .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Now every `git commit` will scan staged files first.

## Next steps

- [Lab 01: Repository scan](../labs/lab_01_repo_scan.md) — hands-on practice with a sample vulnerable repository
- [Detection methodology](../../docs/detection-methodology.md) — understand how findings are derived
- [Credential rotation guide](../../docs/remediation-guides/credential-rotation.md)
