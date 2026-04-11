# secret-leak-sentinel

**Secret detection and prevention for repositories, pipelines, configs, and logs — scan, classify, and prevent credential exposure.**

`secret-leak-sentinel` is a developer-first CLI tool that scans codebases, configuration files, CI pipelines, git patches, and git history for accidentally committed secrets. It combines regex-based pattern matching with Shannon entropy analysis, classifies findings by criticality, and integrates with pre-commit and pre-push hooks to prevent secrets from leaving your repository in the first place.

---

## The problem

Secrets — API keys, tokens, private keys, database passwords, and connection strings — regularly end up in source code. They arrive via copy-paste, environment variable leakage into config files, or poorly reviewed commits. Once committed to a git repository, they are extremely difficult to remove completely.

`secret-leak-sentinel` helps you find secrets before (or after) they are committed, understand their severity, and remediate them systematically.

---

## Features

- **Regex detection** — curated patterns for AWS keys, GitHub tokens, PEM, SSH2, and PuTTY private-key headers, connection strings, password assignments, and more
- **Cloud and SaaS credential coverage** — detects Azure SAS URLs, Azure storage connection strings, GCP service account JSON key indicators, live Stripe secret/restricted keys, Twilio auth tokens, SendGrid API keys, HashiCorp Vault tokens, and weak or unsigned JWT bearer tokens
- **Entropy detection** — flags high-entropy strings that pattern matching alone might miss
- **Git integration** — scan staged files, working tree, or full commit history with commit-level attribution and blob deduplication
- **Pre-commit hook** — drop-in shell script to block secrets at commit time
- **Pre-push hook** — scans outgoing commit patches so `--no-verify` commits still get a last defensive check
- **GitHub Action support** — composite Marketplace-ready action validates CLI inputs, installs the tool, and exposes generated report paths as workflow outputs
- **VS Code extension scaffold** — a local editor integration runs `scan-file --json-output` and turns findings into inline diagnostics
- **Context-aware classification** — explicit context analysis distinguishes live secret stores, CI pipelines, docs, and test fixtures to tune confidence and severity
- **Criticality classification** — multi-signal classifier assigns final severity and confidence scores
- **Rich terminal output** — colour-coded findings table via the `rich` library
- **Structured JSON output for file scans** — stable machine-readable payload for editor and automation integrations
- **Markdown reports** — structured output for code review, compliance, and tracking
- **Suppression file** — silence known-safe findings with a YAML suppression list
- **Policy profiles** — developer, ci, and strict modes with configurable thresholds

---

## Quickstart

### Install

```bash
git clone https://github.com/hiagokinlevi/secret-leak-sentinel.git
cd secret-leak-sentinel
pip install -e ".[dev]"
```

For dependency-restricted workstations that already provide the runtime
dependencies, the repository also supports an offline editable install:

```bash
python -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e . --no-deps --no-build-isolation
.venv/bin/secret-leak-sentinel --help
```

### Scan a directory

```bash
secret-leak-sentinel scan-path ./my-project
```

### Scan staged files (pre-commit integration)

```bash
secret-leak-sentinel scan-staged
```

### Scan git history

```bash
secret-leak-sentinel scan-git-history --repo ./my-project --max-commits 50
```

### Scan a patch file

```bash
secret-leak-sentinel scan-file ./changes.diff --patch-mode
```

### Scan a file and emit JSON

```bash
secret-leak-sentinel scan-file ./app/settings.py --json-output
```

### Install the pre-commit hook

```bash
cp hooks/pre-commit/secret-leak-check .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Install the pre-push hook

```bash
cp hooks/pre-push/secret-leak-check-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

---

## Supported secret types

| Type                        | Example match                          | Criticality |
|-----------------------------|----------------------------------------|-------------|
| AWS Access Key ID           | `AKIA[0-9A-Z]{16}`                     | CRITICAL    |
| GitHub tokens               | `ghp_...`, `gho_...`, `github_pat_...`, `ghs_...` | CRITICAL |
| Stripe live key             | `sk_live_...`, `rk_live_...`          | CRITICAL    |
| Twilio auth token           | `TWILIO_AUTH_TOKEN=...`               | CRITICAL    |
| SendGrid API key            | `SG.<id>.<secret>`                    | CRITICAL    |
| Azure SAS URL               | `https://...blob.core.windows.net/...?...&sig=...` | CRITICAL |
| Azure storage connection string | `DefaultEndpointsProtocol=...;AccountKey=...` | CRITICAL |
| GCP service account key JSON | `"private_key_id": "...", "client_email": "...gserviceaccount.com"` | CRITICAL / HIGH |
| HashiCorp Vault token       | `hvs....`, `hvb....`, or `X-Vault-Token: s....` | CRITICAL |
| Weak or unsigned JWT bearer token | `Bearer eyJ...` with `alg: none` or `HS256/384/512` | HIGH |
| PEM / PKCS#8 Private Key    | `-----BEGIN ... PRIVATE KEY-----`      | CRITICAL    |
| SSH2 Private Key            | `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` | CRITICAL |
| PuTTY PPK Private Key       | `PuTTY-User-Key-File-3: ssh-ed25519`   | CRITICAL    |
| API key in assignment       | `api_key = "abc123..."`               | HIGH        |
| Password in assignment      | `password = "mypassword"`             | HIGH        |
| Database connection string  | `postgresql://user:pass@host/db`      | HIGH        |
| High-entropy string         | Entropy > 4.5 in variable assignment  | MEDIUM      |

---

## Configuration

```bash
cp .env.example .env
# Edit .env to tune scan mode, entropy threshold, fail severity, etc.
```

Key settings:

| Variable              | Default      | Description                                         |
|-----------------------|--------------|-----------------------------------------------------|
| `SCAN_MODE`           | `filesystem` | `filesystem`, `git`, or `staged`                   |
| `ENTROPY_ENABLED`     | `true`       | Enable Shannon entropy detection                    |
| `ENTROPY_THRESHOLD`   | `4.5`        | Minimum entropy to flag a string                   |
| `FAIL_ON_SEVERITY`    | `high`       | Exit non-zero if any finding reaches this level     |
| `MASK_FINDINGS`       | `true`       | Mask secret values in output (recommended: always) |
| `POLICY_PROFILE`      | `default`    | `developer`, `ci`, or `strict`                     |

---

## Suppressing false positives

Create `.secret-leak-suppressions.yaml` in your project root:

```yaml
suppressions:
  - file: "tests/fixtures/sample_keys.py"
    reason: "Test fixture — not a real credential"
  - detector: "password_assignment"
    file: "docs/examples/config_example.md"
    reason: "Documentation example only"
```

---

## CI integration

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Scan repository for leaked secrets
        id: secret_scan
        uses: hiagokinlevi/secret-leak-sentinel@main
        with:
          command: scan-path
          args: .
          fail-on: high
          output-dir: ./scan-results

      - name: Upload Markdown report
        if: ${{ steps.secret_scan.outputs.report-markdown != '' }}
        uses: actions/upload-artifact@v4
        with:
          name: secret-scan-report
          path: ${{ steps.secret_scan.outputs.report-markdown }}
```

The repository now includes a composite GitHub Action in [`action.yml`](action.yml). It installs `secret-leak-sentinel`, validates the requested subcommand and root CLI options without invoking a shell, runs inside the workflow workspace, and publishes the newest Markdown, CSV, and HTML report paths as step outputs for downstream upload or notification steps.

## VS Code integration

The repository now includes a starter extension under
[`integrations/vscode`](integrations/vscode). It shells out to the local
`secret-leak-sentinel` binary, runs `scan-file --json-output` against the
active file, and surfaces the returned findings as diagnostics inline.

Local validation:

```bash
cd integrations/vscode
npm run check
npm test
```

## Cloud credential notes

`secret-leak-sentinel` now treats Azure SAS URLs, Azure storage
connection strings, and GCP service account JSON key indicators as
first-class high-signal detections. The regexes stay intentionally narrow so
they catch production-shaped cloud credentials without broadly flagging
ordinary query strings or unrelated JSON documents.

Vault coverage follows the same bias toward high-signal matches. The detector
flags modern Vault token prefixes such as `hvs.`, `hvb.`, and `hvr.` directly,
and only treats legacy single-letter prefixes such as `s.` as findings when
they appear in explicit Vault contexts like `VAULT_TOKEN=` assignments or
`X-Vault-Token:` headers. That keeps generic short `s.` strings out of the
high-severity path while still surfacing production-shaped Vault tokens.

JWT coverage is also intentionally narrow: the detector only emits a finding
when a JWT-shaped bearer token decodes to `alg: none` or an HMAC signing mode
(`HS256`, `HS384`, or `HS512`). That keeps asymmetric `RS*`, `ES*`, and
similar JWTs out of the high-signal secret list while still catching portable
tokens that are unsigned or commonly backed by shared secrets.

The classifier now applies explicit context analysis before producing the final
severity. Live dotenv-style files such as `.env`, `.env.local`,
`.env.production`, and `config.env` remain high-risk storage locations that
escalate confirmed `HIGH` findings to `CRITICAL`. Placeholder dotenv examples
such as `.env.example` and `.env.sample` stay out of that automatic escalation
path, while documentation-oriented paths, sample fixtures, and CI workflow
files now contribute separate context labels and confidence adjustments that
travel through the JSON output as `context_labels`.

SSH private-key coverage spans traditional PEM headers, encrypted PKCS#8
blocks, SSH.com `SSH2` private-key blocks, and PuTTY `.ppk` headers so
private-key material is still flagged when teams store it outside the
classic OpenSSL PEM layout.

Git history scans now walk commits in chronological order, inspect only the
lines introduced by each commit, and skip rescanning unchanged blobs across
later commits. That keeps large repositories practical to review while making
the first introducing commit, author, and line context visible in the CLI
output.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

CC BY 4.0 — see [LICENSE](LICENSE).
