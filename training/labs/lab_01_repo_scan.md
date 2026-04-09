# Lab 01: Scanning a Repository for Secrets

**Duration:** ~30 minutes
**Objective:** Practice using `secret-leak-sentinel` to find, classify, and remediate intentionally-seeded secrets in a sample repository.

---

## Setup

### Create a sample "vulnerable" repository

```bash
mkdir /tmp/sample-vulnerable-repo && cd /tmp/sample-vulnerable-repo
git init

# Create files with intentionally seeded synthetic credentials
# (These are NOT real credentials — they follow the format but are non-functional)
```

Create `config/app.py`:

```python
# Application configuration
# NOTE: This file intentionally contains synthetic secrets for training purposes

DATABASE_URL = "postgresql://app_user:s3cr3tP@ssw0rd!@db.internal.example.com/appdb"

# API keys (synthetic, non-functional)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz1234567890"
```

Create `docs/setup-guide.md`:

```markdown
## Configuration

Set the following environment variables:

- `DATABASE_URL=postgresql://user:password@host/db`  (example only)
- `AWS_ACCESS_KEY_ID` — your AWS access key
- `GITHUB_TOKEN` — your GitHub personal access token
```

Commit both files:

```bash
git add .
git commit -m "initial commit"
```

---

## Exercise 1: Filesystem scan

Scan the sample repository:

```bash
k1n-sentinel scan-path /tmp/sample-vulnerable-repo
```

**Questions:**

1. How many findings were detected?
2. Which findings are CRITICAL? Which are HIGH?
3. Which file has the most findings?
4. Did the docs/setup-guide.md produce findings? Should it?

---

## Exercise 2: Entropy detection

Run the scan with verbose entropy output:

```bash
k1n-sentinel scan-path /tmp/sample-vulnerable-repo \
  --entropy \
  --entropy-threshold 3.5
```

Lower the threshold to 3.5 and observe:

**Questions:**

1. How many additional findings appear with the lower threshold?
2. Which new findings look like false positives?
3. What threshold seems appropriate for reducing noise while catching real secrets?

---

## Exercise 3: Suppressing false positives

The `docs/setup-guide.md` findings are documentation examples, not real secrets.

Create a suppression file:

```bash
cat > /tmp/sample-vulnerable-repo/.k1n-suppressions.yaml << 'EOF'
suppressions:
  - file: "docs/setup-guide.md"
    reason: "Documentation examples only — no real credentials"
EOF
```

Re-run the scan and confirm the file is excluded:

```bash
k1n-sentinel scan-path /tmp/sample-vulnerable-repo
```

---

## Exercise 4: Pre-commit hook

Install the hook and try to commit a file containing a synthetic secret:

```bash
cp /path/to/secret-leak-sentinel/hooks/pre-commit/k1n-secret-check \
   /tmp/sample-vulnerable-repo/.git/hooks/pre-commit
chmod +x /tmp/sample-vulnerable-repo/.git/hooks/pre-commit

cd /tmp/sample-vulnerable-repo
echo 'NEW_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"' >> config/app.py
git add config/app.py
git commit -m "test commit"  # This should be blocked
```

**Expected result:** The commit is blocked and the finding is displayed.

---

## Exercise 5: Review the report

Open the generated Markdown report from Exercise 1 or 2 and answer:

1. What is the risk score?
2. For the AWS Access Key finding: what remediation steps are recommended?
3. What is the confidence score for the `password_assignment` finding?

---

## Summary

After completing this lab you should be able to:

- Run a filesystem scan and interpret the findings table
- Distinguish between CRITICAL, HIGH, and MEDIUM findings
- Create suppression entries for known false positives
- Install and test the pre-commit hook
- Read and act on the Markdown report
