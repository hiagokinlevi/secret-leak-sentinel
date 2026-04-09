# Overview

`secret-leak-sentinel` is a secret detection and prevention CLI tool. It scans source code, configuration files, git history, and CI pipeline artifacts for accidentally exposed credentials and sensitive values.

## The threat

When a developer commits an API key, database password, or private key to a git repository, that secret immediately becomes accessible to:

- Everyone with repository read access (potentially hundreds of people in large organisations)
- Anyone who clones the repository publicly
- All past and future forks of the repository
- Any backup, CI artifact, or log that contains the repository

Removing a secret from git is significantly harder than preventing it from being committed in the first place. Even after rewriting history, the secret may persist in forks, CI caches, backup systems, and anyone who cloned the repository before the removal.

## Detection approach

The tool uses two complementary detection techniques:

### Regex detection

Curated regular expressions match known patterns for specific credential types. These patterns have high precision (low false positive rate) because the formats of AWS access keys, GitHub tokens, PEM headers, and database URLs are well-defined.

### Entropy detection

Shannon entropy measures the randomness of a string. High-entropy strings in assignment context may represent secrets that don't follow a known pattern — custom API keys, internal tokens, or manually generated passwords. This technique has lower precision (more false positives) but catches what regex cannot.

## Prevention pipeline

```
Developer workstation  -->  Pre-commit hook  -->  [commit blocked if secrets found]
                                 |
                                 v
CI pipeline  -->  scan-path / scan-staged  -->  [pipeline fails if secrets found]
                                 |
                                 v
Post-incident  -->  scan-git (full history)  -->  [find and remediate historical leaks]
```

## Next steps

- [Detection methodology](detection-methodology.md) — how detectors work and are tuned
- [Remediation guide: credential rotation](remediation-guides/credential-rotation.md)
- [First scan tutorial](../training/tutorials/first-scan.md)
