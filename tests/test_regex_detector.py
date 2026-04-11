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


class TestGitHubTokenDetection:
    """Tests for the github_personal_access_token and github_oauth_token patterns."""

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

    def test_does_not_flag_github_url_without_token(self):
        """A GitHub URL without a token should not be flagged."""
        content = "REPO_URL = https://github.com/myorg/myrepo"
        findings = scan_content(content, "config.py")
        gh_findings = [
            f for f in findings
            if f.detector_name in ("github_personal_access_token", "github_oauth_token")
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

    def test_saas_tokens_are_masked(self):
        content = "SENDGRID_API_KEY=SG." + "a" * 22 + "." + "b" * 43
        findings = scan_content(content, ".env")
        sendgrid = next(f for f in findings if f.detector_name == "sendgrid_api_key")
        assert "b" * 43 not in sendgrid.masked_excerpt


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
