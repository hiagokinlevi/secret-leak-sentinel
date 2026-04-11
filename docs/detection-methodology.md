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
`client_email ... iam.gserviceaccount.com` JSON fields.

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
| File extension is `.env`, `.pem`, `.key` | Confidence boost; escalate to CRITICAL |
| File extension is `.md`, `.txt` | Confidence penalty |

## Policy application

After classification, each finding is compared against the configured policy profile. If any finding meets or exceeds `fail_on_severity`, the CLI exits with a non-zero code. In a pre-commit hook context, this blocks the commit.

## False positive management

False positives are inevitable with any static analysis tool. Manage them using the suppression file:

```yaml
# .k1n-suppressions.yaml
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
