# Detection Methodology

This document describes how `secret-leak-sentinel` detects secrets, how findings are classified, and how to tune the tool for your environment.

## Detection pipeline

```
File content
    |
    ├─── Regex Detector ──────────► regex_findings (high precision)
    |
    └─── Entropy Detector ────────► entropy_findings (high recall)
                                         |
                                         ▼
                                 Criticality Classifier
                                         |
                                         ▼
                                 ClassifiedFinding list
                                         |
                                         ▼
                                 Policy check → pass/fail
                                         |
                                         ▼
                                   Markdown Report
```

## Regex detection

The regex detector (`detectors/regex_detector.py`) applies a list of curated `DetectorPattern` objects to each line of each scanned file.

Each pattern has:
- **Pattern**: a regular expression (uses Python `re` module syntax)
- **SecretType**: what kind of credential this matches
- **Criticality**: how severe a confirmed match would be
- **Description**: human-readable explanation

Patterns are ordered from most specific to most generic to reduce false positives.
Provider-specific SaaS patterns are intentionally narrower than generic token
rules: Stripe detection only flags live `sk_live_` and `rk_live_` keys, Twilio
requires an auth-token or API-secret assignment context around a 32-character hex
token, SendGrid requires the structured `SG.<id>.<secret>` key format, Azure SAS
coverage requires a signed URL shape with `sv` and `sig` parameters, and GCP
service-account coverage keys off the `private_key_id` and
`client_email ... iam.gserviceaccount.com` JSON fields. Vault coverage flags
modern `hvs.`, `hvb.`, and `hvr.` tokens directly while only treating legacy
single-letter prefixes such as `s.` as findings when they appear in explicit
Vault assignment or header contexts. Private-key coverage also spans classic
PEM headers, encrypted PKCS#8 blocks, SSH.com `SSH2`
private-key blocks, and PuTTY `.ppk` headers. JWT coverage uses a two-step
check: a narrow regex first finds JWT-shaped bearer tokens, then the detector
base64url-decodes the header and only emits a finding when the header
advertises `alg: none` or an HMAC signing mode (`HS256`, `HS384`, `HS512`).

## Entropy detection

The entropy detector (`detectors/entropy_detector.py`) calculates the Shannon entropy of strings found in assignment contexts (e.g., `api_key = "..."`, `TOKEN: "..."`).

Genuine secrets tend to have entropy above 4.5 bits/character because they are generated randomly. Human-readable text, variable names, and simple passwords typically score below this threshold.

**Tuning the threshold:**
- Lower threshold (e.g., 4.0): catches more secrets, but generates more false positives
- Higher threshold (e.g., 5.0): fewer false positives, but may miss some secrets

The threshold is configurable via `ENTROPY_THRESHOLD` in `.env` or the `--entropy-threshold` CLI flag.

## Criticality classification

The classifier (`classifiers/criticality_classifier.py`) combines signals from both detectors and applies context-based adjustments:

| Signal | Effect |
|--------|--------|
| Regex pattern matches with high specificity | High base confidence |
| Entropy detector corroborates the same line | Confidence boost |
| File is in a `tests/` or `samples/` directory | Confidence penalty; de-escalate criticality |
| File is in a documentation-oriented path such as `docs/` or `tutorials/` | Confidence penalty |
| File is in a CI workflow path such as `.github/workflows/` or `.gitlab-ci.yml` | Confidence boost |
| File is a live dotenv-style secret store (`.env`, `.env.local`, `config.env`) or a key container (`.pem`, `.key`) | Confidence boost; escalate to CRITICAL |
| File extension is `.md`, `.txt` | Confidence penalty |

Dotenv escalation intentionally excludes placeholder filenames such as
`.env.example`, `.env.sample`, and `.env.template`. Those files often exist to
document configuration rather than store live credentials, so they remain
subject to the normal documentation and sample-context penalties instead of an
automatic severity jump.

The same context engine now emits explicit `context_labels` such as
`live_secret_store`, `ci_pipeline`, `documentation_path`, and
`sample_or_test` in the JSON output. That makes downstream tooling like editor
integrations and automation hooks aware of *why* a finding was promoted or
penalized instead of only receiving the final severity.

## Policy application

After classification, each finding is compared against the configured policy profile. If any finding meets or exceeds `fail_on_severity`, the CLI exits with a non-zero code. In a pre-commit hook context, this blocks the commit.

## False positive management

False positives are inevitable with any static analysis tool. Manage them using the suppression file:

```yaml
# .secret-leak-suppressions.yaml
suppressions:
  - file: "tests/fixtures/aws_test_data.py"
    reason: "Synthetic test credentials — not real AWS keys"
  - detector: "password_assignment"
    file: "docs/configuration-examples.md"
    reason: "Documentation placeholder values"
```

## Confidence scores

Confidence is a heuristic estimate of how likely a finding is to be a real secret (not a false positive). It is NOT a guarantee. Human review is always required before rotating credentials based on a finding.

| Confidence | Interpretation |
|------------|---------------|
| 0.85–0.98 | Highly likely to be a real secret |
| 0.65–0.84 | Probable; review carefully |
| 0.40–0.64 | Uncertain; may be a false positive |
| < 0.40     | Low confidence; likely false positive |
