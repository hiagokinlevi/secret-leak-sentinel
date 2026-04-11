# Secret Leak Sentinel for VS Code

This extension shells out to the local `secret-leak-sentinel` CLI, runs
`scan-file --json-output` against the active file, and publishes the returned
findings as inline diagnostics.

## Current capabilities

- Command palette action: `Secret Leak Sentinel: Scan Current File`
- Optional automatic scan on save
- Uses the repository CLI directly, so the editor stays aligned with the same
  detectors, policies, and masking rules used in hooks and CI

## Settings

- `secretLeakSentinel.binaryPath`
- `secretLeakSentinel.extraArgs`
- `secretLeakSentinel.runOnSave`

## Local validation

```bash
cd integrations/vscode
npm run check
npm test
```
