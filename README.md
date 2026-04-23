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
- **Cloud and SaaS credential coverage** — detects Azure SAS URLs, Azure storage connection strings, GCP service account JSON key indicators, GCP OAuth access tokens, live Stripe secret/restricted keys, Twilio auth tokens, SendGrid API keys, Slack bearer/app tokens, npm access tokens, HashiCorp Vault tokens, and weak or unsigned JWT bearer tokens
- **Entropy detection** — flags high-entropy strings that pattern matching alone might miss
- **Cross-file entropy correlation** — highlights masked high-entropy tokens reused across multiple files and elevates them as likely propagated secrets
- **Git integration** — scan staged files, working tree, or full commit history with commit-level attribution and blob deduplication
- **Pre-commit hook** — drop-in shell script to block secrets at commit time
- **Pre-push hook** — scans outgoing commit patches so `--no-verify` commits still get a last defensive check
- **GitHub Action support** — composite Marketplace-ready action validates CLI inputs, installs the tool, and exposes generated report paths as workflow outputs
- **VS Code extension scaffold** — a local editor integration runs `scan-file --json-output` and turns findings into inline diagnostics
- **Baseline comparison mode** — pass `--baseline previous.json` to
- **Output safety guardrail** — pass `--fail-on-unmasked` to `scan-path`, `scan-staged`, or `scan-git` to force a non-zero exit if serialized findings/log payload appears to contain raw (unredacted) secret material
