# Remediation Guide: Credential Rotation

This guide covers how to rotate common credential types after they have been detected by `secret-leak-sentinel`. **Rotation should happen before you remove the secret from git history**, because git history rewriting takes time and the credential may already have been seen.

---

## General steps for any credential

1. **Rotate first.** Invalidate the exposed credential immediately. A rotated-but-still-in-code secret is vastly better than an active-and-in-code one.
2. **Audit usage.** Check provider logs for unauthorized use of the exposed credential during the window of exposure.
3. **Remove from code.** Delete the credential from the source file.
4. **Rewrite git history** (if committed). Use `git-filter-repo` to remove the secret from all commits.
5. **Force-push the rewritten branch** (coordinate with your team — this rewrites shared history).
6. **Notify affected parties** if the credential granted access to sensitive data.

---

## AWS Access Key and Secret Key

### Rotate

```bash
# Deactivate the old key (do this FIRST — before deletion, to allow a rollback window)
aws iam update-access-key \
  --access-key-id AKIA_THE_EXPOSED_KEY \
  --status Inactive \
  --user-name your-iam-user

# Create a new key
aws iam create-access-key --user-name your-iam-user

# Update all services, CI pipelines, and ~/.aws/credentials with the new key

# Once confirmed, delete the old key
aws iam delete-access-key \
  --access-key-id AKIA_THE_EXPOSED_KEY \
  --user-name your-iam-user
```

### Audit

```bash
# Check CloudTrail for API calls using the exposed key in the last 90 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA_THE_EXPOSED_KEY \
  --query 'Events[*].{Time:EventTime,Event:EventName,User:Username,Source:EventSource}' \
  --output table
```

---

## GitHub Personal Access Token

### Rotate

1. Go to **GitHub Settings > Developer settings > Personal access tokens**.
2. Click the token name.
3. Click **Regenerate token** (or delete and create a new one).
4. Update all locations that use the token (CI secrets, local `.env`, config files).

### Audit

1. Check **GitHub Settings > Security log** for events associated with the old token.
2. Review the organizations and repositories the token had access to.

---

## Database Connection String (PostgreSQL, MySQL, etc.)

### Rotate

```bash
# PostgreSQL: change the user's password
psql -U admin_user -d your_database \
  -c "ALTER USER app_user WITH PASSWORD 'new_secure_password_here';"

# Update the connection string in all services
# New format: postgresql://app_user:new_secure_password_here@host/database
```

### Prevent recurrence

Store connection strings in a secrets manager:
- **AWS**: AWS Secrets Manager or SSM Parameter Store (SecureString)
- **Azure**: Azure Key Vault
- **GCP**: Google Cloud Secret Manager
- **Self-hosted**: HashiCorp Vault

Reference them via environment variables at runtime; never hardcode them.

---

## Private Keys (PEM, RSA, EC, OpenSSH)

Private keys typically sign certificates or authenticate SSH connections. Rotation depends on the use case:

| Key type | Rotation process |
|----------|-----------------|
| TLS/SSL certificate | Reissue certificate with a new key pair; install on all servers |
| SSH key | Remove old public key from `authorized_keys`; generate new pair |
| Code signing key | Revoke old certificate with the CA; get a new signing cert |
| JWT signing key | Roll to new key; accept both during transition; remove old |

After rotation, run `git-filter-repo` to remove the key material from all commits:

```bash
pip install git-filter-repo

git filter-repo \
  --path path/to/private.key \
  --invert-paths

# Force-push to all branches (coordinate with your team)
git push --force --all
```

---

## Preventing recurrence

- Install the pre-commit hook: `cp hooks/pre-commit/k1n-secret-check .git/hooks/pre-commit`
- Use a secrets manager for all credentials — never store them in source files
- Set `FAIL_ON_SEVERITY=high` in CI to block pipelines that introduce new secrets
- Review findings weekly via `k1n-sentinel scan-git --repo . --depth 50`
