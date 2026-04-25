# Roadmap

Planned development direction for `secret-leak-sentinel`.

---

## v0.1 — Foundation (current)

- [x] Regex-based secret detector with curated patterns
- [x] Shannon entropy detector for high-entropy string detection
- [x] Filesystem scanner with exclusion support
- [x] Git scanner (working tree and staged files via gitpython)
- [x] Criticality classifier with multi-signal confidence scoring
- [x] Pre-commit hook shell script
- [x] Click CLI: scan-path, scan-staged, scan-git, validate-policy, generate-report, list-detectors
- [x] Markdown report generator
- [x] Default YAML policy profile
- [x] Suppression file support

---

## v0.2 — Pattern coverage expansion

- [x] Stripe API key patterns (`sk_live_`, `rk_live_`)
- [x] Twilio auth tokens
- [x] SendGrid API keys
- [x] Azure SAS tokens and connection strings
- [x] GCP service account JSON key detection
- [x] JWT token detection (unsigned or weak-signature JWTs)
- [x] SSH private key detection (PEM, PKCS#8, SSH2, and PuTTY formats)
- [x] HashiCorp Vault tokens

---

## v0.3 — Git history scanning

- [x] Deep git log scan (all commits in history, not just current tree)
- [x] Blob deduplication to avoid rescanning unchanged file content
- [x] Per-commit finding attribution (which commit introduced the secret)
- [x] Report: git history scan with commit hashes and author info

---

## v0.4 — IDE and editor integration

- [x] VS Code extension (calls CLI and surfaces findings inline)
- [x] Pre-push hook in addition to pre-commit
- [x] GitHub Actions marketplace action

---

## v0.5 — Advanced classification

- [ ] ML-based classifier to reduce false positive rate on entropy findings
- [x] Context-aware analysis (is the file a test fixture? a documentation example?)
- [x] Cross-file correlation (e.g., same high-ent

## Automated Completions
- [x] Add `--min-severity` filter to scan commands (cycle 36)
