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

- [ ] Stripe API key patterns (`sk_live_`, `rk_live_`)
- [ ] Twilio auth tokens
- [ ] SendGrid API keys
- [ ] Azure SAS tokens and connection strings
- [ ] GCP service account JSON key detection
- [ ] JWT token detection (unsigned or weak-signature JWTs)
- [ ] SSH private key detection (all formats)
- [ ] HashiCorp Vault tokens

---

## v0.3 — Git history scanning

- [ ] Deep git log scan (all commits in history, not just current tree)
- [ ] Blob deduplication to avoid rescanning unchanged file content
- [ ] Per-commit finding attribution (which commit introduced the secret)
- [ ] Report: git history scan with commit hashes and author info

---

## v0.4 — IDE and editor integration

- [ ] VS Code extension (calls CLI and surfaces findings inline)
- [ ] Pre-push hook in addition to pre-commit
- [ ] GitHub Actions marketplace action

---

## v0.5 — Advanced classification

- [ ] ML-based classifier to reduce false positive rate on entropy findings
- [ ] Context-aware analysis (is the file a test fixture? a documentation example?)
- [ ] Cross-file correlation (e.g., same high-entropy string appears in multiple files)
- [ ] Severity escalation when a pattern is found inside a `.env` file specifically

---

## Future / Under consideration

- SARIF output for GitHub Advanced Security / Code Scanning integration
- API server mode for integration with other tooling
- Web dashboard for tracking findings over time across multiple repositories
- Plugin interface for custom detector patterns
- Automatic rotation guidance per secret type (links to provider-specific rotation docs)
