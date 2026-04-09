# Secret Detection Prompts

A reference collection of prompts for use with AI assistants when working with secret detection findings.

---

## Interpreting a scan report

```
I ran secret-leak-sentinel on my repository and got the following findings:
[paste findings here]

Please:
1. Identify which findings are most likely to be real secrets vs. false positives,
   and explain your reasoning.
2. For each probable real secret, tell me the exact steps to rotate it.
3. Tell me how to prevent each type of secret from being committed in the future.
```

---

## Investigating a specific finding

```
The following finding was detected in my repository:

- Detector: [detector name]
- File: [file path]
- Line: [line number]
- Masked excerpt: [masked excerpt]

The file is: [describe the file — test fixture, documentation, production config, etc.]

Is this likely a real secret? What are the risks if it is? What should I do next?
```

---

## Writing a suppression entry

```
I have a false positive finding from secret-leak-sentinel:
- File: [file path]
- Detector: [detector name]
- Reason it's a false positive: [explain]

Please write a valid .k1n-suppressions.yaml entry for this finding.
```

---

## Adding a custom detector pattern

```
I want to add a custom detector for [describe the credential type].
The format of this credential is: [describe the format]
Example value (synthetic, not real): [example]

Please write a DetectorPattern entry for detectors/regex_detector.py, including:
- An appropriate pattern string
- The correct SecretType and Criticality
- A clear description
- Two pytest test cases
```

---

## Rewriting git history to remove a secret

```
My secret was committed to the repository at [describe location, e.g., file path].
The commit hash where it was introduced is: [hash]

Please provide the exact git-filter-repo command to remove this file/string from
all commits, and the steps to safely force-push the rewritten history.

Repository details:
- Team size: [number]
- Main branch name: [branch name]
- Number of open pull requests: [number]
```

---

## Auditing cloud resources after a credential leak

```
My [AWS access key / GitHub token / database password] was exposed.
The exposure window was approximately [start date] to [end date].

Please give me:
1. The specific API calls or log queries to run to audit unauthorized usage.
2. The indicators of compromise I should look for.
3. The remediation steps if unauthorized access did occur.
```
