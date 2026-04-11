# secret-leak-sentinel

**Secret detection and prevention for repositories, pipelines, configs, and logs — scan, classify, and prevent credential exposure.**

`secret-leak-sentinel` is a developer-first CLI tool that scans codebases, configuration files, CI pipelines, and git history for accidentally committed secrets. It combines regex-based pattern matching with Shannon entropy analysis, classifies findings by criticality, and integrates with pre-commit hooks to prevent secrets from entering your repository in the first place.

---

## The problem

Secrets — API keys, tokens, private keys, database passwords, and connection strings — regularly end up in source code. They arrive via copy-paste, environment variable leakage into config files, or poorly reviewed commits. Once committed to a git repository, they are extremely difficult to remove completely.

`secret-leak-sentinel` helps you find secrets before (or after) they are committed, understand their severity, and remediate them systematically.

---

## Features

- **Regex detection** — curated patterns for AWS keys, GitHub tokens, PEM blocks, connection strings, password assignments, and more
- **Cloud and SaaS credential coverage** — detects Azure SAS URLs, Azure storage connection strings, GCP service account JSON key indicators, live Stripe secret/restricted keys, Twilio auth tokens, and SendGrid API keys
- **Entropy detection** — flags high-entropy strings that pattern matching alone might miss
- **Git integration** — scan staged files, working tree, or commit history with gitpython
- **Pre-commit hook** — drop-in shell script to block secrets at commit time
- **Criticality classification** — multi-signal classifier assigns final severity and confidence scores
- **Rich terminal output** — colour-coded findings table via the `rich` library
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
.venv/bin/k1n-sentinel --help
```

### Scan a directory

```bash
k1n-sentinel scan-path ./my-project
```

### Scan staged files (pre-commit integration)

```bash
k1n-sentinel scan-staged
```

### Scan git history

```bash
k1n-sentinel scan-git --repo ./my-project --depth 50
```

### Install the pre-commit hook

```bash
cp hooks/pre-commit/k1n-secret-check .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

## Supported secret types

| Type                        | Example match                          | Criticality |
|-----------------------------|----------------------------------------|-------------|
| AWS Access Key ID           | `AKIA[0-9A-Z]{16}`                     | CRITICAL    |
| GitHub Personal Access Token | `ghp_[A-Za-z0-9]{36}`                | CRITICAL    |
| GitHub OAuth Token          | `gho_[A-Za-z0-9]{36}`                 | CRITICAL    |
| Stripe live key             | `sk_live_...`, `rk_live_...`          | CRITICAL    |
| Twilio auth token           | `TWILIO_AUTH_TOKEN=...`               | CRITICAL    |
| SendGrid API key            | `SG.<id>.<secret>`                    | CRITICAL    |
| Azure SAS URL               | `https://...blob.core.windows.net/...?...&sig=...` | CRITICAL |
| Azure storage connection string | `DefaultEndpointsProtocol=...;AccountKey=...` | CRITICAL |
| GCP service account key JSON | `"private_key_id": "...", "client_email": "...gserviceaccount.com"` | CRITICAL / HIGH |
| PEM Private Key             | `-----BEGIN ... PRIVATE KEY-----`      | CRITICAL    |
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

Create `.k1n-suppressions.yaml` in your project root:

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
- name: Secret scan
  run: k1n-sentinel scan-path . --fail-on high
```

## Cloud credential notes

`secret-leak-sentinel` now treats Azure SAS URLs, Azure storage
connection strings, and GCP service account JSON key indicators as
first-class high-signal detections. The regexes stay intentionally narrow so
they catch production-shaped cloud credentials without broadly flagging
ordinary query strings or unrelated JSON documents.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
