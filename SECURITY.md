# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Responsible disclosure

If you discover a security vulnerability in `secret-leak-sentinel`, please **do not** open a public GitHub issue. Report it privately so we can investigate and patch before disclosure.

**Report via:** GitHub's private vulnerability reporting feature (Security > Report a vulnerability).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The affected version(s)
- Any suggested fixes (optional)

We aim to acknowledge reports within **72 hours** and provide an initial assessment within **7 days**.

## Important note: real secrets in bug reports

If your report involves a real credential that was discovered by the tool, do **not** include the actual secret value in your report. Mask it (e.g., `AKIA**************`) or describe the pattern only. If you have reason to believe the credential is actively in use, rotate it immediately and then report the vulnerability.

## Scope

In-scope vulnerabilities:

- Bugs that cause the tool to fail to detect a known secret type
- Bugs that cause the tool to output unmasked secret values
- Code execution vulnerabilities triggered by scanning malicious files
- Dependency vulnerabilities with a realistic exploit path

Out of scope:

- False positives (intended behavior, use suppression files)
- Secrets discovered in your own repositories (tool working as intended)

## Disclosure timeline

1. Patch released
2. GitHub Security Advisory published
3. Reporter credited (unless anonymity requested)
