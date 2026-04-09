# test_cloud_credential_detector.py
# Tests for detectors/cloud_credential_detector.py
#
# CC BY 4.0 License
# © 2026 hiagokinlevi / Cyber Port
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_cloud_credential_detector.py -q

from __future__ import annotations

import sys
import os

# Ensure the package root is on the path when running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.cloud_credential_detector import (
    CCDFinding,
    CCDMatch,
    CCDResult,
    _CHECK_WEIGHTS,
    scan,
    scan_many,
)

# ---------------------------------------------------------------------------
# Shared test fixtures — constructed dynamically to avoid push-protection
# ---------------------------------------------------------------------------

_FAKE_AKIA = "AKIA" + "TESTKEY1234567890"[:16]   # 20 chars total
_FAKE_ASIA = "ASIA" + "TESTKEY1234567890"[:16]   # temporary STS variant
_FAKE_AROA = "AROA" + "TESTKEY1234567890"[:16]   # assumed-role variant
_FAKE_AIDA = "AIDA" + "TESTKEY1234567890"[:16]   # IAM user-ID variant
_FAKE_SECRET = "A" * 40                           # 40-char fake secret
_FAKE_AZURE_KEY = "B" * 86 + "=="                 # 88-char Azure storage key
_FAKE_GCP_KEY_ID = "a" * 40                       # 40-char hex GCP private_key_id
_FAKE_SA_EMAIL = "my-sa@my-project.iam.gserviceaccount.com"
_FAKE_UUID = "12345678-1234-1234-1234-123456789012"  # 36-char UUID
_FAKE_SESSION = "X" * 120                         # >100 char session token
_FAKE_GCP_OAUTH = "ya29." + "G" * 55              # GCP OAuth token prefix + body
_FAKE_RDS_URL = (
    "postgresql://user:password@mydb.cluster-abc123.us-east-1.rds.amazonaws.com/mydb"
)
_FAKE_AZURE_SQL = (
    "Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;"
    "Password=SuperSecret123!"
)
_FAKE_CLOUD_SQL = "postgresql://user:password@127.0.0.1:3307/mydb?cloudsql=my-project:us-east1:myinstance"
_FAKE_ARN_SECRET = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password"
_FAKE_ARN_SSM = "arn:aws:ssm:us-east-1:123456789012:parameter/prod/app/api-key"
_FAKE_ARN_KMS = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"


# ===========================================================================
# Utility / datamodel tests
# ===========================================================================


def test_empty_text_returns_clean_result():
    r = scan("")
    assert r.findings == []
    assert r.risk_score == 0
    assert r.provider_summary == {}


def test_clean_text_returns_no_findings():
    r = scan("Hello, world!  Nothing secret here.")
    assert r.findings == []
    assert r.risk_score == 0


def test_source_name_propagated():
    r = scan("nothing", source_name="myfile.py")
    assert r.source_name == "myfile.py"


def test_default_source_name():
    r = scan("nothing")
    assert r.source_name == "input"


def test_ccd_result_to_dict_structure():
    r = scan(_FAKE_AKIA, source_name="test.py")
    d = r.to_dict()
    assert "source_name" in d
    assert "risk_score" in d
    assert "provider_summary" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)


def test_ccd_result_to_dict_finding_keys():
    r = scan(_FAKE_AKIA, source_name="test.py")
    d = r.to_dict()
    f = d["findings"][0]
    for key in ("check_id", "severity", "title", "detail", "weight", "matches"):
        assert key in f


def test_ccd_result_to_dict_match_keys():
    r = scan(_FAKE_AKIA, source_name="test.py")
    d = r.to_dict()
    m = d["findings"][0]["matches"][0]
    for key in ("provider", "pattern_name", "line_number", "redacted_value"):
        assert key in m


def test_summary_contains_source_name():
    r = scan("nothing", source_name="sentinel.py")
    s = r.summary()
    assert "sentinel.py" in s


def test_summary_contains_risk_score():
    r = scan("nothing")
    s = r.summary()
    assert "risk=0" in s


def test_summary_contains_findings_count():
    r = scan("nothing")
    s = r.summary()
    assert "findings=0" in s


def test_by_severity_groups_correctly():
    text = "\n".join([
        _FAKE_AKIA,
        _FAKE_ARN_SECRET,
    ])
    r = scan(text)
    sev = r.by_severity()
    assert "CRITICAL" in sev
    assert "MEDIUM" in sev
    assert all(isinstance(v, list) for v in sev.values())


def test_by_severity_empty_when_no_findings():
    r = scan("nothing")
    assert r.by_severity() == {}


def test_check_weights_dict_has_all_ids():
    for cid in ("CCD-001", "CCD-002", "CCD-003", "CCD-004",
                "CCD-005", "CCD-006", "CCD-007"):
        assert cid in _CHECK_WEIGHTS


def test_check_weights_values():
    assert _CHECK_WEIGHTS["CCD-001"] == 45
    assert _CHECK_WEIGHTS["CCD-002"] == 45
    assert _CHECK_WEIGHTS["CCD-003"] == 45
    assert _CHECK_WEIGHTS["CCD-004"] == 45
    assert _CHECK_WEIGHTS["CCD-005"] == 30
    assert _CHECK_WEIGHTS["CCD-006"] == 30
    assert _CHECK_WEIGHTS["CCD-007"] == 15


# ===========================================================================
# CCD-001: AWS Access Key ID
# ===========================================================================


def test_ccd001_detects_akia():
    r = scan(_FAKE_AKIA)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_ccd001_detects_asia():
    r = scan(_FAKE_ASIA)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_ccd001_detects_aroa():
    r = scan(_FAKE_AROA)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_ccd001_detects_aida():
    r = scan(_FAKE_AIDA)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_ccd001_severity_is_critical():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert f.severity == "CRITICAL"


def test_ccd001_weight_is_45():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert f.weight == 45


def test_ccd001_provider_is_aws():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert all(m.provider == "aws" for m in f.matches)


def test_ccd001_line_number_correct():
    text = "first line\n" + _FAKE_AKIA + "\nthird line"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert f.matches[0].line_number == 2


def test_ccd001_line_number_first_line():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert f.matches[0].line_number == 1


def test_ccd001_redacted_value_format():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")
    assert rv.startswith(_FAKE_AKIA[:4])


def test_ccd001_redacted_length():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    rv = f.matches[0].redacted_value
    assert len(rv) == 8  # 4 chars + 4 asterisks


def test_ccd001_multiple_keys_same_line():
    line = _FAKE_AKIA + " " + _FAKE_ASIA
    r = scan(line)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert len(f.matches) == 2


def test_ccd001_multiple_lines():
    text = _FAKE_AKIA + "\n" + _FAKE_ASIA
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    assert len(f.matches) == 2
    assert f.matches[0].line_number == 1
    assert f.matches[1].line_number == 2


def test_ccd001_short_key_not_detected():
    # Only 15 chars after prefix — must not match
    short = "AKIA" + "TESTKEY123456"[:15]
    r = scan(short)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" not in ids


def test_ccd001_risk_score_equals_weight():
    r = scan(_FAKE_AKIA)
    assert r.risk_score == 45


def test_ccd001_provider_summary_contains_aws():
    r = scan(_FAKE_AKIA)
    assert "aws" in r.provider_summary
    assert r.provider_summary["aws"] >= 1


# ===========================================================================
# CCD-002: AWS Secret Access Key
# ===========================================================================


def test_ccd002_detects_aws_secret_access_key():
    text = f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" in ids


def test_ccd002_detects_secret_access_key():
    text = f"secret_access_key={_FAKE_SECRET}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" in ids


def test_ccd002_detects_aws_secret():
    text = f"aws_secret: {_FAKE_SECRET}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" in ids


def test_ccd002_severity_is_critical():
    text = f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-002")
    assert f.severity == "CRITICAL"


def test_ccd002_weight_is_45():
    text = f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-002")
    assert f.weight == 45


def test_ccd002_provider_is_aws():
    text = f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-002")
    assert all(m.provider == "aws" for m in f.matches)


def test_ccd002_line_number():
    text = "line one\naws_secret_access_key = " + _FAKE_SECRET
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-002")
    assert f.matches[0].line_number == 2


def test_ccd002_redaction_shows_first_four():
    text = f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-002")
    rv = f.matches[0].redacted_value
    assert rv == "AAAA****"


def test_ccd002_39_char_secret_not_detected():
    # 39 chars is one short — must not match
    short = "B" * 39
    text = f"aws_secret_access_key = {short}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" not in ids


def test_ccd002_with_quotes():
    text = f'aws_secret_access_key = "{_FAKE_SECRET}"'
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" in ids


def test_ccd002_case_insensitive_keyword():
    text = f"AWS_SECRET_ACCESS_KEY={_FAKE_SECRET}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-002" in ids


# ===========================================================================
# CCD-003: Azure storage credential
# ===========================================================================


def test_ccd003_detects_account_key():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-003" in ids


def test_ccd003_detects_connection_string():
    text = (
        "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;"
        "AccountKey=abc123def456ghi789"
    )
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-003" in ids


def test_ccd003_severity_is_critical():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-003")
    assert f.severity == "CRITICAL"


def test_ccd003_weight_is_45():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-003")
    assert f.weight == 45


def test_ccd003_provider_is_azure():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-003")
    assert all(m.provider == "azure" for m in f.matches)


def test_ccd003_line_number():
    text = "# config\nAccountKey=" + _FAKE_AZURE_KEY
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-003")
    assert f.matches[0].line_number == 2


def test_ccd003_redaction():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-003")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")
    assert len(rv) == 8


def test_ccd003_provider_summary_contains_azure():
    text = f"AccountKey={_FAKE_AZURE_KEY}"
    r = scan(text)
    assert "azure" in r.provider_summary


def test_ccd003_case_insensitive():
    text = f"accountkey={_FAKE_AZURE_KEY}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-003" in ids


def test_ccd003_short_key_not_detected():
    # Azure storage keys are exactly 86+== chars; shorter should not match
    short_key = "B" * 40 + "=="
    text = f"AccountKey={short_key}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-003" not in ids


# ===========================================================================
# CCD-004: GCP service account JSON key
# ===========================================================================


def test_ccd004_detects_private_key_id():
    text = f'"private_key_id": "{_FAKE_GCP_KEY_ID}"'
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-004" in ids


def test_ccd004_detects_client_email():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-004" in ids


def test_ccd004_detects_both_fields():
    text = (
        f'"private_key_id": "{_FAKE_GCP_KEY_ID}",\n'
        f'"client_email": "{_FAKE_SA_EMAIL}"'
    )
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert len(f.matches) == 2


def test_ccd004_severity_is_critical():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert f.severity == "CRITICAL"


def test_ccd004_weight_is_45():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert f.weight == 45


def test_ccd004_provider_is_gcp():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert all(m.provider == "gcp" for m in f.matches)


def test_ccd004_line_number_private_key_id():
    text = "{\n" + f'"private_key_id": "{_FAKE_GCP_KEY_ID}"' + "\n}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert f.matches[0].line_number == 2


def test_ccd004_line_number_client_email():
    text = "{\n" + f'"client_email": "{_FAKE_SA_EMAIL}"' + "\n}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    assert f.matches[0].line_number == 2


def test_ccd004_provider_summary_gcp():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    assert "gcp" in r.provider_summary


def test_ccd004_invalid_email_not_detected():
    text = '"client_email": "user@example.com"'
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-004" not in ids


def test_ccd004_redaction_client_email():
    text = f'"client_email": "{_FAKE_SA_EMAIL}"'
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-004")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")


# ===========================================================================
# CCD-005: Generic cloud API tokens
# ===========================================================================


def test_ccd005_detects_client_secret():
    text = f"client_secret = {_FAKE_UUID}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-005" in ids


def test_ccd005_detects_tenant_id():
    text = f"tenant_id={_FAKE_UUID}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-005" in ids


def test_ccd005_detects_client_id():
    text = f"client_id: {_FAKE_UUID}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-005" in ids


def test_ccd005_detects_aws_session_token():
    text = f"aws_session_token = {_FAKE_SESSION}"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-005" in ids


def test_ccd005_detects_gcp_oauth_token():
    r = scan(_FAKE_GCP_OAUTH)
    ids = [f.check_id for f in r.findings]
    assert "CCD-005" in ids


def test_ccd005_severity_is_high():
    text = f"client_secret = {_FAKE_UUID}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    assert f.severity == "HIGH"


def test_ccd005_weight_is_30():
    text = f"client_secret = {_FAKE_UUID}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    assert f.weight == 30


def test_ccd005_azure_provider():
    text = f"client_secret = {_FAKE_UUID}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    azure_matches = [m for m in f.matches if m.provider == "azure"]
    assert len(azure_matches) >= 1


def test_ccd005_gcp_provider_for_oauth():
    r = scan(_FAKE_GCP_OAUTH)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    gcp_matches = [m for m in f.matches if m.provider == "gcp"]
    assert len(gcp_matches) >= 1


def test_ccd005_aws_provider_for_session():
    text = f"aws_session_token = {_FAKE_SESSION}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    aws_matches = [m for m in f.matches if m.provider == "aws"]
    assert len(aws_matches) >= 1


def test_ccd005_session_token_short_not_detected():
    # Under 100 chars — must not match
    short = "X" * 50
    text = f"aws_session_token = {short}"
    r = scan(text)
    # CCD-005 might still fire for azure UUID; we specifically want no session match
    if "CCD-005" in [f.check_id for f in r.findings]:
        f = next(x for x in r.findings if x.check_id == "CCD-005")
        aws_session = [m for m in f.matches
                       if m.pattern_name == "AWS session token"]
        assert len(aws_session) == 0


def test_ccd005_gcp_oauth_short_not_detected():
    # Under 50 chars after ya29. — must not match
    short_token = "ya29." + "G" * 40
    r = scan(short_token)
    # If detected, it would only match if >= 50 chars; 40 is not enough
    if "CCD-005" in [f.check_id for f in r.findings]:
        f = next(x for x in r.findings if x.check_id == "CCD-005")
        gcp_matches = [m for m in f.matches
                       if m.pattern_name == "GCP OAuth access token"]
        assert len(gcp_matches) == 0


def test_ccd005_line_number():
    text = "# env\nclient_secret = " + _FAKE_UUID
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    assert f.matches[0].line_number == 2


def test_ccd005_redaction():
    text = f"client_secret = {_FAKE_UUID}"
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-005")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")
    assert len(rv) == 8


# ===========================================================================
# CCD-006: Cloud database connection strings
# ===========================================================================


def test_ccd006_detects_rds_postgresql():
    r = scan(_FAKE_RDS_URL)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" in ids


def test_ccd006_detects_rds_mysql():
    url = "mysql://user:secret@mydb.cluster-xyz.us-west-2.rds.amazonaws.com/mydb"
    r = scan(url)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" in ids


def test_ccd006_detects_azure_sql():
    r = scan(_FAKE_AZURE_SQL)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" in ids


def test_ccd006_detects_cloudsql():
    r = scan(_FAKE_CLOUD_SQL)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" in ids


def test_ccd006_severity_is_high():
    r = scan(_FAKE_RDS_URL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    assert f.severity == "HIGH"


def test_ccd006_weight_is_30():
    r = scan(_FAKE_RDS_URL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    assert f.weight == 30


def test_ccd006_rds_provider_is_aws():
    r = scan(_FAKE_RDS_URL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    aws_matches = [m for m in f.matches if m.provider == "aws"]
    assert len(aws_matches) >= 1


def test_ccd006_azure_sql_provider_is_azure():
    r = scan(_FAKE_AZURE_SQL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    azure_matches = [m for m in f.matches if m.provider == "azure"]
    assert len(azure_matches) >= 1


def test_ccd006_cloudsql_provider_is_gcp():
    r = scan(_FAKE_CLOUD_SQL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    gcp_matches = [m for m in f.matches if m.provider == "gcp"]
    assert len(gcp_matches) >= 1


def test_ccd006_line_number():
    text = "# db config\n" + _FAKE_RDS_URL
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    assert f.matches[0].line_number == 2


def test_ccd006_redaction():
    r = scan(_FAKE_RDS_URL)
    f = next(x for x in r.findings if x.check_id == "CCD-006")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")


def test_ccd006_no_rds_domain_not_detected():
    url = "postgresql://user:password@mydb.example.com/mydb"
    r = scan(url)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" not in ids


def test_ccd006_jdbc_mysql_rds():
    url = "jdbc:mysql://user:secret@mydb.abcde12345.us-east-1.rds.amazonaws.com:3306/appdb"
    r = scan(url)
    ids = [f.check_id for f in r.findings]
    assert "CCD-006" in ids


# ===========================================================================
# CCD-007: AWS ARN — sensitive resource path
# ===========================================================================


def test_ccd007_detects_secrets_manager_arn():
    r = scan(_FAKE_ARN_SECRET)
    ids = [f.check_id for f in r.findings]
    assert "CCD-007" in ids


def test_ccd007_detects_ssm_arn():
    r = scan(_FAKE_ARN_SSM)
    ids = [f.check_id for f in r.findings]
    assert "CCD-007" in ids


def test_ccd007_detects_kms_arn():
    r = scan(_FAKE_ARN_KMS)
    ids = [f.check_id for f in r.findings]
    assert "CCD-007" in ids


def test_ccd007_severity_is_medium():
    r = scan(_FAKE_ARN_SECRET)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    assert f.severity == "MEDIUM"


def test_ccd007_weight_is_15():
    r = scan(_FAKE_ARN_SECRET)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    assert f.weight == 15


def test_ccd007_provider_is_aws():
    r = scan(_FAKE_ARN_SECRET)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    assert all(m.provider == "aws" for m in f.matches)


def test_ccd007_line_number():
    text = "# ARN reference\n" + _FAKE_ARN_SSM
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    assert f.matches[0].line_number == 2


def test_ccd007_redaction():
    r = scan(_FAKE_ARN_SECRET)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    rv = f.matches[0].redacted_value
    assert rv.endswith("****")
    assert rv.startswith("arn:")


def test_ccd007_plain_arn_not_detected():
    # ARN that does not point to secretsmanager, ssm, or kms
    plain_arn = "arn:aws:s3:::my-bucket"
    r = scan(plain_arn)
    ids = [f.check_id for f in r.findings]
    assert "CCD-007" not in ids


def test_ccd007_all_three_arns_in_one_scan():
    text = "\n".join([_FAKE_ARN_SECRET, _FAKE_ARN_SSM, _FAKE_ARN_KMS])
    r = scan(text)
    f = next(x for x in r.findings if x.check_id == "CCD-007")
    assert len(f.matches) == 3


def test_ccd007_risk_score_is_15_alone():
    r = scan(_FAKE_ARN_SECRET)
    assert r.risk_score == 15


# ===========================================================================
# Risk score and provider_summary calculations
# ===========================================================================


def test_risk_score_single_check_equals_weight():
    r = scan(_FAKE_ARN_SECRET)
    assert r.risk_score == 15


def test_risk_score_two_critical_checks_sums():
    text = _FAKE_AKIA + "\n" + f"aws_secret_access_key = {_FAKE_SECRET}"
    r = scan(text)
    assert r.risk_score == 90  # 45 + 45


def test_risk_score_capped_at_100():
    # Trigger as many checks as possible to overflow 100
    text = "\n".join([
        _FAKE_AKIA,
        f"aws_secret_access_key = {_FAKE_SECRET}",
        f"AccountKey={_FAKE_AZURE_KEY}",
        f'"client_email": "{_FAKE_SA_EMAIL}"',
        f"client_secret = {_FAKE_UUID}",
        _FAKE_RDS_URL,
        _FAKE_ARN_SECRET,
    ])
    r = scan(text)
    assert r.risk_score == 100


def test_risk_score_deduplication():
    # Two AKIA keys must not double-count CCD-001's weight
    text = _FAKE_AKIA + "\n" + _FAKE_ASIA
    r = scan(text)
    assert r.risk_score == 45  # still just one check ID fired


def test_provider_summary_multiple_providers():
    text = "\n".join([
        _FAKE_AKIA,
        f"AccountKey={_FAKE_AZURE_KEY}",
        f'"client_email": "{_FAKE_SA_EMAIL}"',
    ])
    r = scan(text)
    assert "aws" in r.provider_summary
    assert "azure" in r.provider_summary
    assert "gcp" in r.provider_summary


def test_provider_summary_counts_are_positive():
    text = "\n".join([_FAKE_AKIA, f"AccountKey={_FAKE_AZURE_KEY}"])
    r = scan(text)
    for provider, count in r.provider_summary.items():
        assert count > 0


def test_provider_summary_aws_count():
    # Two AKIA keys -> 2 matches under CCD-001 -> aws count == 2
    text = _FAKE_AKIA + " " + _FAKE_ASIA
    r = scan(text)
    assert r.provider_summary.get("aws", 0) == 2


# ===========================================================================
# scan_many function
# ===========================================================================


def test_scan_many_returns_list():
    results = scan_many(["nothing", "nothing"])
    assert isinstance(results, list)
    assert len(results) == 2


def test_scan_many_source_names_propagated():
    results = scan_many(["a", "b"], source_names=["file_a.py", "file_b.py"])
    assert results[0].source_name == "file_a.py"
    assert results[1].source_name == "file_b.py"


def test_scan_many_default_source_names():
    results = scan_many(["a", "b"])
    assert results[0].source_name == "input_0"
    assert results[1].source_name == "input_1"


def test_scan_many_partial_source_names():
    results = scan_many(["a", "b", "c"], source_names=["only_one"])
    assert results[0].source_name == "only_one"
    assert results[1].source_name == "input_1"
    assert results[2].source_name == "input_2"


def test_scan_many_empty_list():
    results = scan_many([])
    assert results == []


def test_scan_many_detects_in_second_entry():
    results = scan_many(["nothing", _FAKE_AKIA])
    assert results[0].findings == []
    assert any(f.check_id == "CCD-001" for f in results[1].findings)


def test_scan_many_independent_results():
    results = scan_many([_FAKE_AKIA, f"AccountKey={_FAKE_AZURE_KEY}"])
    assert results[0].provider_summary.get("aws", 0) >= 1
    assert results[1].provider_summary.get("azure", 0) >= 1
    assert results[0].provider_summary.get("azure", 0) == 0


# ===========================================================================
# Edge cases and integration tests
# ===========================================================================


def test_multiline_text_all_checks():
    text = "\n".join([
        "# configuration dump",
        _FAKE_AKIA,
        f"aws_secret_access_key = {_FAKE_SECRET}",
        f"AccountKey={_FAKE_AZURE_KEY}",
        f'"private_key_id": "{_FAKE_GCP_KEY_ID}"',
        f"client_secret = {_FAKE_UUID}",
        _FAKE_RDS_URL,
        _FAKE_ARN_SECRET,
    ])
    r = scan(text, source_name="config_dump.txt")
    fired = {f.check_id for f in r.findings}
    for cid in ("CCD-001", "CCD-002", "CCD-003", "CCD-004",
                "CCD-005", "CCD-006", "CCD-007"):
        assert cid in fired, f"{cid} not found in {fired}"


def test_no_false_positive_on_random_text():
    text = (
        "The quick brown fox jumps over the lazy dog.\n"
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
        "Version: 1.2.3 | Status: OK | Code: 200"
    )
    r = scan(text)
    assert r.findings == []
    assert r.risk_score == 0


def test_to_dict_round_trip_source_name():
    r = scan("nothing", source_name="roundtrip.py")
    d = r.to_dict()
    assert d["source_name"] == "roundtrip.py"


def test_to_dict_risk_score_type():
    r = scan(_FAKE_AKIA)
    d = r.to_dict()
    assert isinstance(d["risk_score"], int)


def test_finding_has_non_empty_detail():
    r = scan(_FAKE_AKIA)
    for f in r.findings:
        assert len(f.detail) > 0


def test_finding_has_non_empty_title():
    r = scan(_FAKE_AKIA)
    for f in r.findings:
        assert len(f.title) > 0


def test_ccd_match_pattern_name_is_string():
    r = scan(_FAKE_AKIA)
    f = next(x for x in r.findings if x.check_id == "CCD-001")
    for m in f.matches:
        assert isinstance(m.pattern_name, str)
        assert len(m.pattern_name) > 0


def test_scan_windows_line_endings():
    text = _FAKE_AKIA + "\r\n" + "next line"
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_scan_single_long_line():
    # Key embedded deep inside a long line
    padding = "x" * 200
    text = padding + " " + _FAKE_AKIA + " " + padding
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_scan_unicode_before_key():
    text = "# config — production 🔑\n" + _FAKE_AKIA
    r = scan(text)
    ids = [f.check_id for f in r.findings]
    assert "CCD-001" in ids


def test_by_severity_returns_dict():
    r = scan(_FAKE_AKIA)
    sev = r.by_severity()
    assert isinstance(sev, dict)


def test_risk_score_not_negative():
    r = scan("")
    assert r.risk_score >= 0


def test_risk_score_is_int():
    r = scan(_FAKE_AKIA)
    assert isinstance(r.risk_score, int)
