# Policy Configuration

## Entropy detector guardrails

To reduce noisy alerts from very short random-looking strings, you can set a minimum token length before entropy evaluation runs:

```yaml
detectors:
  entropy:
    enabled: true
    threshold: 3.5
    entropy_min_length: 8
```

- `entropy_min_length` applies **only** to entropy detection.
- Tokens shorter than this value are skipped by the entropy detector.
- If omitted, the detector uses its built-in default (preserving existing behavior).
