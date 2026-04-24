# CI secret-type filtering (`--only-type`, `--exclude-type`)

You can now filter findings by detector/rule type before report generation and exit-code evaluation.

Supported on scan commands:
- `scan-path`
- `scan-staged`
- `scan-git`

Both flags are repeatable:
- `--only-type <type>`: keep only matching types
- `--exclude-type <type>`: drop matching types

## Examples

Fail CI only on credential classes:

```bash
secret-leak-sentinel scan-path . \
  --only-type aws_access_key \
  --only-type private_key \
  --only-type jwt \
  --json-output reports/credentials.json \
  --markdown-output reports/credentials.md
```

Ignore known low-risk test token classes while still failing on everything else:

```bash
secret-leak-sentinel scan-git \
  --exclude-type test_token \
  --exclude-type dummy_api_key \
  --json-output reports/filtered.json
```

Combine include + exclude (include set first, then exclude from that set):

```bash
secret-leak-sentinel scan-staged \
  --only-type jwt \
  --only-type bearer_token \
  --exclude-type weak_example_jwt
```

Notes:
- Matching is case-insensitive.
- JSON/Markdown outputs contain only retained findings.
- Exit code is computed from retained findings only.
