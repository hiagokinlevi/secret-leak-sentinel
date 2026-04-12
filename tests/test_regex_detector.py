"""
Tests for detectors/regex_detector.py
=======================================
Validates that the regex detector correctly identifies known secret patterns
and does not flag benign content.

All test credentials are SYNTHETIC and non-functional.
They follow the correct format but have never been valid credentials.
"""
import pytest

from detectors.regex_detector import (
    Criticality,
    Finding,
    SecretType,
    scan_content,
)

_FAKE_SLACK_BOT = "xoxb-" + "123456789012-" + "123456789012-" + "abcdefghijklmnopqrstuvwx"
_FAKE_SLACK_APP = "xapp-1-" + "ABCD1234EFGH5678-" + "IJKL9012MNOP3456-" + "qrstuvwxyzabcdef"
_FAKE_NPM = "npm_" + "n" * 36


class TestAWSAccessKeyDetection:
    """Tests for the aws_access_key_id detector pattern."""

    def test_detects_synthetic_aws_access_key(self):
        """A line containing a synthetic AWS Access Key ID should produce a finding."""
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert len(aws_findings) == 1
        assert aws_findings[0].criticality == Criticality.CRITICAL
        assert aws_findings[0].secret_type == SecretType.AWS_ACCESS_KEY

    def test_detects_synthetic_aws_sts_access_key(self):
        """A temporary STS AWS access key ID should produce the same CRITICAL finding."""
        content = 'AWS_ACCESS_KEY_ID = "' + ("AS" + "IAIOSFODNN7EXAMPLE") + '"'
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert len(aws_findings) == 1
        assert aws_findings[0].criticality == Criticality.CRITICAL
        assert aws_findings[0].secret_type == SecretType.AWS_ACCESS_KEY

    def test_aws_key_finding_has_masked_excerpt(self):
        """The finding excerpt must be masked and not contain the full key."""
        content = 'key = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_content(content, "test.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert aws_findings
        # The full 20-character key should not appear unmasked in the excerpt
        assert "AKIAIOSFODNN7EXAMPLE" not in aws_findings[0].masked_excerpt

    def test_does_not_flag_non_akia_string(self):
        """A string that does not start with AKIA should not match the AWS key pattern."""
        content = "BKIAIOSFODNN7EXAMPLE = something"  # Starts with B, not A
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert aws_findings == []

    def test_does_not_flag_short_akia_string(self):
        """AKIA followed by fewer than 16 alphanumeric characters should not match."""
        content = "AKIASHORT = value"  # Only 5 characters after AKIA
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert aws_findings == []

    def test_does_not_flag_short_asia_string(self):
        """ASIA followed by fewer than 16 alphanumeric characters should not match."""
        content = "ASIASHORT = value"
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert aws_findings == []


class TestGitHubTokenDetection:
    """Tests for the GitHub token detector patterns."""

    def test_detects_synthetic_github_pat(self):
        """A synthetic GitHub PAT should produce a CRITICAL finding."""
        content = 'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        findings = scan_content(content, ".env")
        gh_findings = [f for f in findings if f.detector_name == "github_personal_access_token"]
        assert len(gh_findings) == 1
        assert gh_findings[0].criticality == Criticality.CRITICAL

    def test_detects_synthetic_github_oauth(self):
        """A synthetic GitHub OAuth token should produce a CRITICAL finding."""
        content = "token=gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        findings = scan_content(content, "config.yaml")
        gho_findings = [f for f in findings if f.detector_name == "github_oauth_token"]
        assert len(gho_findings) == 1

    def test_detects_synthetic_github_fine_grained_pat(self):
        """A synthetic GitHub fine-grained PAT should produce a CRITICAL finding."""
        content = (
            "token=github_pat_"
            "AAAAAAAAAAAAAAAAAAAAAA_"
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        )
        findings = scan_content(content, "config.yaml")
        pat_findings = [f for f in findings if f.detector_name == "github_fine_grained_pat"]
        assert len(pat_findings) == 1
        assert pat_findings[0].criticality == Criticality.CRITICAL
        assert pat_findings[0].secret_type == SecretType.GITHUB_TOKEN

    @pytest.mark.parametrize(
        ("detector_name", "token"),
        [
            ("github_app_user_token", "ghu_" + ("u" * 36)),
            ("github_app_installation_token", "ghs_" + ("s" * 36)),
            ("github_app_refresh_token", "ghr_" + ("r" * 36)),
        ],
    )
    def test_detects_github_app_tokens(self, detector_name: str, token: str):
        """GitHub App token families should be detected as CRITICAL findings."""
        findings = scan_content(f"TOKEN={token}", ".env")
        token_findings = [f for f in findings if f.detector_name == detector_name]
        assert len(token_findings) == 1
        assert token_findings[0].criticality == Criticality.CRITICAL
        assert token_findings[0].secret_type == SecretType.GITHUB_TOKEN

    def test_does_not_flag_short_github_app_token(self):
        """Short GitHub App tokens should not match the detector."""
        findings = scan_content("TOKEN=ghs_shortexampletoken", ".env.example")
        token_findings = [f for f in findings if f.detector_name == "github_app_installation_token"]
        assert token_findings == []

    def test_does_not_flag_github_url_without_token(self):
        """A GitHub URL without a token should not be flagged."""
        content = "REPO_URL = https://github.com/myorg/myrepo"
        findings = scan_content(content, "config.py")
        gh_findings = [
            f for f in findings
            if f.detector_name.startswith("github_")
        ]
        assert gh_findings == []


class TestSaaSTokenDetection:
    """Tests for provider-specific SaaS API token patterns."""

    def test_detects_stripe_live_secret_key(self):
        content = "STRIPE_SECRET_KEY=sk_live_" + "A" * 24
        findings = scan_content(content, ".env")
        stripe = [f for f in findings if f.detector_name == "stripe_live_secret_key"]
        assert len(stripe) == 1
        assert stripe[0].criticality == Criticality.CRITICAL
        assert stripe[0].secret_type == SecretType.STRIPE_KEY

    def test_detects_stripe_restricted_live_key(self):
        content = "stripe_key = 'rk_live_" + "B" * 28 + "'"
        findings = scan_content(content, "settings.py")
        assert any(f.detector_name == "stripe_live_secret_key" for f in findings)

    def test_ignores_stripe_test_key(self):
        content = "STRIPE_SECRET_KEY=sk_test_" + "C" * 24
        findings = scan_content(content, ".env.example")
        assert not any(f.detector_name == "stripe_live_secret_key" for f in findings)

    def test_detects_twilio_auth_token_assignment(self):
        content = "TWILIO_AUTH_TOKEN=" + "a" * 32
        findings = scan_content(content, ".env")
        twilio = [f for f in findings if f.detector_name == "twilio_auth_token_assignment"]
        assert len(twilio) == 1
        assert twilio[0].secret_type == SecretType.TWILIO_TOKEN

    def test_ignores_bare_32_char_hex_without_context(self):
        content = "checksum = " + "b" * 32
        findings = scan_content(content, "checksums.txt")
        assert not any(f.detector_name == "twilio_auth_token_assignment" for f in findings)

    def test_detects_sendgrid_api_key(self):
        content = "SENDGRID_API_KEY=SG." + "a" * 22 + "." + "b" * 43
        findings = scan_content(content, ".env")
        sendgrid = [f for f in findings if f.detector_name == "sendgrid_api_key"]
        assert len(sendgrid) == 1
        assert sendgrid[0].criticality == Criticality.CRITICAL
        assert sendgrid[0].secret_type == SecretType.SENDGRID_KEY

    @pytest.mark.parametrize(
        ("detector_name", "token"),
        [
            ("slack_bearer_token", _FAKE_SLACK_BOT),
            ("slack_app_token", _FAKE_SLACK_APP),
        ],
    )
    def test_detects_slack_tokens(self, detector_name: str, token: str):
        findings = scan_content(f"SLACK_TOKEN={token}", ".env")
        slack_findings = [f for f in findings if f.detector_name == detector_name]
        assert len(slack_findings) == 1
        assert slack_findings[0].criticality == Criticality.CRITICAL
        assert slack_findings[0].secret_type == SecretType.API_TOKEN

    def test_detects_npm_access_token(self):
        findings = scan_content(f"NPM_TOKEN={_FAKE_NPM}", ".npmrc")
        npm_findings = [f for f in findings if f.detector_name == "npm_access_token"]
        assert len(npm_findings) == 1
        assert npm_findings[0].criticality == Criticality.CRITICAL
        assert npm_findings[0].secret_type == SecretType.API_TOKEN

    def test_does_not_flag_short_slack_token(self):
        findings = scan_content("SLACK_TOKEN=xoxb-short-example", ".env.example")
        slack_findings = [f for f in findings if f.detector_name == "slack_bearer_token"]
        assert slack_findings == []

    def test_does_not_flag_short_npm_token(self):
        findings = scan_content("NPM_TOKEN=npm_short_example_token", ".env.example")
        npm_findings = [f for f in findings if f.detector_name == "npm_access_token"]
        assert npm_findings == []

    def test_saas_tokens_are_masked(self):
        content = "SENDGRID_API_KEY=SG." + "a" * 22 + "." + "b" * 43
        findings = scan_content(content, ".env")
        sendgrid = next(f for f in findings if f.detector_name == "sendgrid_api_key")
        assert "b" * 43 not in sendgrid.masked_excerpt

    def test_slack_token_is_masked(self):
        findings = scan_content(f"SLACK_BOT_TOKEN={_FAKE_SLACK_BOT}", ".env")
        slack = next(f for f in findings if f.detector_name == "slack_bearer_token")
        assert _FAKE_SLACK_BOT not in slack.masked_excerpt

    def test_npm_token_is_masked(self):
        findings = scan_content(f"NPM_TOKEN={_FAKE_NPM}", ".npmrc")
        npm = next(f for f in findings if f.detector_name == "npm_access_token")
        assert _FAKE_NPM not in npm.masked_excerpt


class TestCloudCredentialDetection:
    """Tests for Azure and GCP cloud credential patterns."""

    def test_detects_azure_sas_url(self):
        content = (
            "BLOB_URL=https://storageacct.blob.core.windows.net/backups/app.db"
            "?sv=2024-01-01&sr=b&sp=r&se=2030-01-01T00:00:00Z"
            "&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2F"
        )
        findings = scan_content(content, ".env")
        sas = [f for f in findings if f.detector_name == "azure_sas_url"]
        assert len(sas) == 1
        assert sas[0].criticality == Criticality.CRITICAL
        assert sas[0].secret_type == SecretType.CLOUD_CREDENTIAL

    def test_does_not_flag_azure_url_without_sig(self):
        content = (
            "BLOB_URL=https://storageacct.blob.core.windows.net/backups/app.db"
            "?sv=2024-01-01&sr=b&sp=r&se=2030-01-01T00:00:00Z"
        )
        findings = scan_content(content, ".env.example")
        assert not any(f.detector_name == "azure_sas_url" for f in findings)

    def test_detects_azure_storage_connection_string(self):
        content = (
            "AZURE_STORAGE_CONNECTION_STRING="
            "DefaultEndpointsProtocol=https;AccountName=sampleacct;"
            "AccountKey=" + "A" * 86 + "==;EndpointSuffix=core.windows.net"
        )
        findings = scan_content(content, "settings.env")
        conn = [f for f in findings if f.detector_name == "azure_storage_connection_string"]
        assert len(conn) == 1
        assert conn[0].criticality == Criticality.CRITICAL
        assert conn[0].secret_type == SecretType.CONNECTION_STRING

    def test_detects_gcp_service_account_private_key_id(self):
        content = '{"private_key_id": "' + ("a" * 40) + '"}'
        findings = scan_content(content, "service-account.json")
        key_id = [f for f in findings if f.detector_name == "gcp_service_account_private_key_id"]
        assert len(key_id) == 1
        assert key_id[0].criticality == Criticality.CRITICAL
        assert key_id[0].secret_type == SecretType.CLOUD_CREDENTIAL

    def test_detects_gcp_service_account_client_email(self):
        content = '{"client_email": "sentinel@demo-project.iam.gserviceaccount.com"}'
        findings = scan_content(content, "service-account.json")
        client_email = [f for f in findings if f.detector_name == "gcp_service_account_client_email"]
        assert len(client_email) == 1
        assert client_email[0].criticality == Criticality.HIGH
        assert client_email[0].secret_type == SecretType.CLOUD_CREDENTIAL

    def test_cloud_credentials_are_masked(self):
        content = '{"private_key_id": "' + ("b" * 40) + '"}'
        findings = scan_content(content, "service-account.json")
        key_id = next(
            f for f in findings if f.detector_name == "gcp_service_account_private_key_id"
        )
        assert ("b" * 40) not in key_id.masked_excerpt


class TestPEMPrivateKeyDetection:
    """Tests for the pem_private_key detector pattern."""

    def test_detects_pem_header(self):
        """A PEM private key header should produce a CRITICAL finding."""
        content = "-----BEGIN RSA PRIVATE KEY-----"
        findings = scan_content(content, "server.key")
        pem_findings = [f for f in findings if f.detector_name == "pem_private_key"]
        assert len(pem_findings) == 1
        assert pem_findings[0].criticality == Criticality.CRITICAL

    def test_detects_ec_private_key(self):
        """An EC private key header should also be flagged."""
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = scan_content(content, "ec.key")
        pem_findings = [f for f in findings if f.detector_name == "pem_private_key"]
        assert len(pem_findings) == 1

    def test_detects_encrypted_private_key(self):
        """Encrypted PKCS#8 private key material should be flagged."""
        content = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        findings = scan_content(content, "encrypted.key")
        pem_findings = [f for f in findings if f.detector_name == "pem_private_key"]
        assert len(pem_findings) == 1

    def test_detects_ssh2_private_key_header(self):
        """SSH.com SSH2 private key material should be flagged."""
        content = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
        findings = scan_content(content, "id_ssh2")
        ssh2_findings = [f for f in findings if f.detector_name == "ssh2_private_key"]
        assert len(ssh2_findings) == 1
        assert ssh2_findings[0].criticality == Criticality.CRITICAL

    def test_detects_putty_private_key_header(self):
        """PuTTY PPK private key material should be flagged."""
        content = "PuTTY-User-Key-File-3: ssh-ed25519"
        findings = scan_content(content, "id_ed25519.ppk")
        putty_findings = [f for f in findings if f.detector_name == "putty_private_key"]
        assert len(putty_findings) == 1
        assert putty_findings[0].secret_type == SecretType.PRIVATE_KEY

    def test_does_not_flag_public_key_header(self):
        """A PUBLIC key header is not a private key and should not match pem_private_key."""
        content = "-----BEGIN PUBLIC KEY-----"
        findings = scan_content(content, "pub.pem")
        pem_findings = [f for f in findings if f.detector_name == "pem_private_key"]
        assert pem_findings == []

    def test_does_not_flag_certificate_header(self):
        """A CERTIFICATE header (public cert) should not match pem_private_key."""
        content = "-----BEGIN CERTIFICATE-----"
        findings = scan_content(content, "cert.pem")
        pem_findings = [f for f in findings if f.detector_name == "pem_private_key"]
        assert pem_findings == []

    def test_does_not_flag_putty_public_key_header(self):
        """PuTTY public key exports must not match the private key detector."""
        content = "PuTTY-User-Key-File-3: ssh-public"
        findings = scan_content(content, "id_rsa.pub")
        putty_findings = [f for f in findings if f.detector_name == "putty_private_key"]
        assert putty_findings == []


class TestJWTDetection:
    """Tests for the jwt_weak_or_unsigned detector pattern."""

    def test_detects_unsigned_jwt(self):
        content = (
            "Authorization: Bearer "
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiJ1c2VyLTEyMyIsInNjb3BlIjoiYXBpIn0."
        )
        findings = scan_content(content, "headers.txt")
        jwt_findings = [f for f in findings if f.detector_name == "jwt_weak_or_unsigned"]
        assert len(jwt_findings) == 1
        assert jwt_findings[0].criticality == Criticality.HIGH
        assert jwt_findings[0].secret_type == SecretType.API_TOKEN

    def test_detects_hmac_signed_jwt(self):
        content = (
            "jwt="
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJzZWNyZXQtbGVhay1zZW50aW5lbCIsInJvbGUiOiJhZG1pbiJ9."
            "c2lnbmF0dXJl"
        )
        findings = scan_content(content, ".env")
        jwt_findings = [f for f in findings if f.detector_name == "jwt_weak_or_unsigned"]
        assert len(jwt_findings) == 1

    def test_does_not_flag_rs256_jwt(self):
        content = (
            "token="
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJzZWNyZXQtbGVhay1zZW50aW5lbCIsInN1YiI6ImFwaSJ9."
            "c2lnbmF0dXJl"
        )
        findings = scan_content(content, "config.py")
        jwt_findings = [f for f in findings if f.detector_name == "jwt_weak_or_unsigned"]
        assert jwt_findings == []

    def test_does_not_flag_invalid_jwt_header(self):
        content = "token=eyJub3QtanNvbiI.eyJzdWIiOiJhcHAifQ.signature"
        findings = scan_content(content, "config.py")
        jwt_findings = [f for f in findings if f.detector_name == "jwt_weak_or_unsigned"]
        assert jwt_findings == []

    def test_masks_jwt_value(self):
        token = (
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9."
            "eyJyb2xlIjoic2VjdXJpdHktb3BzIiwiaWF0IjoxNzEwMDAwMDAwfQ."
            "c2lnbmVk"
        )
        findings = scan_content(f"AUTH_TOKEN={token}", ".env")
        jwt_finding = next(f for f in findings if f.detector_name == "jwt_weak_or_unsigned")
        assert token not in jwt_finding.masked_excerpt


class TestVaultTokenDetection:
    """Tests for HashiCorp Vault token detector patterns."""

    def test_detects_modern_service_token(self):
        content = "VAULT_TOKEN=hvs.CAESICg2bhAsyvurkbzEV8JgLaCF2pqanZCVWJHMGNZZXA"
        findings = scan_content(content, ".env")
        vault_findings = [f for f in findings if f.detector_name == "vault_token_modern"]
        assert len(vault_findings) == 1
        assert vault_findings[0].criticality == Criticality.CRITICAL
        assert vault_findings[0].secret_type == SecretType.API_TOKEN

    def test_detects_modern_batch_token(self):
        content = "X-Vault-Token: hvb.CAESIGJhdGNoVG9rZW5Gb3JUZXN0aW5nMTIzNDU2Nzg5"
        findings = scan_content(content, "headers.txt")
        vault_findings = [f for f in findings if f.detector_name == "vault_token_modern"]
        assert len(vault_findings) == 1

    def test_detects_legacy_service_token_in_assignment_context(self):
        content = "vault_token = 's.n4M0dE1lZ2FjeVRva2VuRm9yRGV0ZWN0aW9uMTIzNDU2'"
        findings = scan_content(content, "config.py")
        vault_findings = [
            f for f in findings if f.detector_name == "vault_token_legacy_assignment"
        ]
        assert len(vault_findings) == 1

    def test_does_not_flag_short_modern_vault_token(self):
        content = "VAULT_TOKEN=hvs.short-example"
        findings = scan_content(content, ".env")
        vault_findings = [f for f in findings if f.detector_name == "vault_token_modern"]
        assert vault_findings == []

    def test_does_not_flag_legacy_token_without_vault_context(self):
        content = "note = 's.n4M0dE1lZ2FjeVRva2VuRm9yRGV0ZWN0aW9uMTIzNDU2'"
        findings = scan_content(content, "notes.txt")
        vault_findings = [
            f for f in findings if f.detector_name == "vault_token_legacy_assignment"
        ]
        assert vault_findings == []

    def test_masks_vault_token_value(self):
        token = "hvs.CAESICg2bhAsyvurkbzEV8JgLaCF2pqanZCVWJHMGNZZXA"
        findings = scan_content(f"VAULT_TOKEN={token}", ".env")
        vault_finding = next(f for f in findings if f.detector_name == "vault_token_modern")
        assert token not in vault_finding.masked_excerpt


class TestPasswordAssignmentDetection:
    """Tests for the password_assignment detector pattern."""

    def test_detects_password_in_quotes(self):
        """A password literal in quotes should be detected."""
        content = 'password = "MyS3cur3P@ssw0rd!"'
        findings = scan_content(content, "settings.py")
        pw_findings = [f for f in findings if f.detector_name == "password_assignment"]
        assert len(pw_findings) == 1
        assert pw_findings[0].criticality == Criticality.HIGH

    def test_detects_passwd_variant(self):
        """The 'passwd' variant of the keyword should also be detected."""
        content = "passwd='longpassword1234'"
        findings = scan_content(content, "config.py")
        pw_findings = [f for f in findings if f.detector_name == "password_assignment"]
        assert len(pw_findings) == 1

    def test_does_not_flag_empty_password(self):
        """An empty string assignment should not trigger the password detector."""
        content = 'password = ""'
        findings = scan_content(content, "config.py")
        pw_findings = [f for f in findings if f.detector_name == "password_assignment"]
        assert pw_findings == []

    def test_does_not_flag_short_password(self):
        """A password shorter than 8 characters should not match (likely a placeholder)."""
        content = 'password = "abc"'
        findings = scan_content(content, "config.py")
        pw_findings = [f for f in findings if f.detector_name == "password_assignment"]
        assert pw_findings == []


class TestDatabaseConnectionStringDetection:
    """Tests for the database_connection_string detector."""

    def test_detects_postgres_with_credentials(self):
        """A PostgreSQL connection string with embedded credentials should be detected."""
        content = "DATABASE_URL = postgresql://app_user:secretpassword@db.example.com/mydb"
        findings = scan_content(content, "settings.py")
        db_findings = [f for f in findings if f.detector_name == "database_connection_string"]
        assert len(db_findings) == 1
        assert db_findings[0].criticality == Criticality.HIGH

    def test_detects_mysql_connection_string(self):
        """A MySQL connection string with embedded credentials should be detected."""
        content = "mysql://root:p4ssw0rd@localhost/production_db"
        findings = scan_content(content, "config.yaml")
        db_findings = [f for f in findings if f.detector_name == "database_connection_string"]
        assert len(db_findings) == 1

    def test_does_not_flag_connection_string_without_credentials(self):
        """A connection string without an embedded password should not match."""
        content = "DB_HOST = db.example.com"
        findings = scan_content(content, "config.py")
        db_findings = [f for f in findings if f.detector_name == "database_connection_string"]
        assert db_findings == []


class TestScanContent:
    """Integration tests for the scan_content() function."""

    def test_returns_empty_list_for_clean_content(self):
        """A file with no secrets should produce an empty findings list."""
        content = "def hello():\n    print('Hello, world!')\n"
        findings = scan_content(content, "hello.py")
        assert findings == []

    def test_line_numbers_are_correct(self):
        """Finding line numbers should match the actual line in the file."""
        content = "# normal line\nAWS_KEY = AKIAIOSFODNN7EXAMPLE\n# another normal line"
        findings = scan_content(content, "config.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        assert aws_findings
        assert aws_findings[0].line_number == 2

    def test_multiple_findings_on_different_lines(self):
        """Multiple findings on different lines should each have distinct line numbers."""
        content = (
            'AWS_KEY = AKIAIOSFODNN7EXAMPLE\n'
            '# comment\n'
            'GITHUB = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        )
        findings = scan_content(content, "multi.py")
        aws_findings = [f for f in findings if f.detector_name == "aws_access_key_id"]
        gh_findings = [f for f in findings if f.detector_name == "github_personal_access_token"]
        assert aws_findings[0].line_number == 1
        assert gh_findings[0].line_number == 3

    def test_multiple_cloud_findings_on_one_line(self):
        """Specific cloud patterns should coexist without suppressing each other."""
        content = (
            '{"private_key_id": "' + ("c" * 40) + '", '
            '"client_email": "sentinel@demo-project.iam.gserviceaccount.com"}'
        )
        findings = scan_content(content, "service-account.json")
        detector_names = {f.detector_name for f in findings}
        assert "gcp_service_account_private_key_id" in detector_names
        assert "gcp_service_account_client_email" in detector_names
