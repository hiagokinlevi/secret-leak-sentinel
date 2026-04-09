"""Unit tests for the CI artifact scanner."""
import textwrap
from pathlib import Path

import pytest

from detectors.regex_detector import Criticality, SecretType
from scanners.ci_artifact_scanner import (
    CiSecretFinding,
    _mask_match,
    scan_log_directory,
    scan_log_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_log(tmp_path: Path, content: str, filename: str = "build.log") -> Path:
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_aws_access_key_in_log(tmp_path):
    p = _write_log(tmp_path, "Configuring AWS: AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_log_file(p)
    assert findings
    aws_findings = [f for f in findings if f.secret_type == SecretType.AWS_ACCESS_KEY]
    assert aws_findings
    assert aws_findings[0].criticality == Criticality.CRITICAL


def test_github_pat_in_log(tmp_path):
    p = _write_log(tmp_path, "Using token: ghp_abcdefghijklmnopqrstuvwxyz123456789012\n")
    findings = scan_log_file(p)
    gh = [f for f in findings if f.secret_type == SecretType.GITHUB_TOKEN]
    assert gh


def test_private_key_in_log(tmp_path):
    p = _write_log(tmp_path, "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n")
    findings = scan_log_file(p)
    key_findings = [f for f in findings if f.secret_type == SecretType.PRIVATE_KEY]
    assert key_findings
    assert key_findings[0].criticality == Criticality.CRITICAL


# ---------------------------------------------------------------------------
# CI-specific patterns
# ---------------------------------------------------------------------------


def test_env_var_dump_detected(tmp_path):
    p = _write_log(tmp_path, "export DB_PASSWORD=SuperSecret123\n")
    findings = scan_log_file(p, include_ci_patterns=True)
    env_findings = [f for f in findings if "env_var" in f.detector_name]
    assert env_findings


def test_curl_auth_header_detected(tmp_path):
    p = _write_log(tmp_path, "curl -X GET https://api.example.com -H 'Authorization: Bearer eyJtoken12345678'\n")
    findings = scan_log_file(p, include_ci_patterns=True)
    assert findings


def test_docker_build_arg_secret(tmp_path):
    p = _write_log(tmp_path, "docker build --build-arg API_SECRET=mysecretvalue123 .\n")
    findings = scan_log_file(p, include_ci_patterns=True)
    assert findings


def test_url_with_credentials(tmp_path):
    p = _write_log(tmp_path, "Installing from https://user:p4ssw0rd123@registry.example.com/pypi\n")
    findings = scan_log_file(p, include_ci_patterns=True)
    cred_findings = [f for f in findings if f.secret_type == SecretType.CONNECTION_STRING]
    assert cred_findings


# ---------------------------------------------------------------------------
# Clean log — no findings
# ---------------------------------------------------------------------------


def test_clean_log_no_findings(tmp_path):
    p = _write_log(tmp_path, textwrap.dedent("""
        [INFO] Running build step 1/5...
        [INFO] Installing dependencies...
        [INFO] Running tests...
        [INFO] All 42 tests passed.
        [INFO] Build complete.
    """))
    findings = scan_log_file(p)
    assert findings == []


def test_github_actions_group_annotation_skipped(tmp_path):
    # Structural log annotations should not produce findings
    p = _write_log(tmp_path, textwrap.dedent("""
        ##[group]Run tests
        ##[endgroup]
        ::notice::Build succeeded
        ::set-output name=version::1.2.3
    """))
    findings = scan_log_file(p)
    assert findings == []


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


def test_masked_line_does_not_contain_secret(tmp_path):
    secret = "AKIAIOSFODNN7EXAMPLE"
    p = _write_log(tmp_path, f"AWS key: {secret}\n")
    findings = scan_log_file(p)
    for finding in findings:
        assert secret not in finding.masked_line


def test_mask_match_helper():
    assert "AKIA" in _mask_match("AKIAIOSFODNN7EXAMPLE")
    assert "IOSFODNN7EXAMPLE" not in _mask_match("AKIAIOSFODNN7EXAMPLE")


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------


def test_scan_log_directory_finds_in_subdir(tmp_path):
    subdir = tmp_path / "logs" / "job1"
    subdir.mkdir(parents=True)
    log_file = subdir / "output.log"
    log_file.write_text("AWS key: AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_log_directory(tmp_path)
    assert findings


def test_scan_log_directory_empty_when_clean(tmp_path):
    log_file = tmp_path / "clean.log"
    log_file.write_text("No secrets here. Build passed.\n")
    findings = scan_log_directory(tmp_path)
    assert findings == []


def test_scan_log_directory_skips_wrong_extension(tmp_path):
    p = tmp_path / "secret.py"
    p.write_text("token = 'AKIAIOSFODNN7EXAMPLE'\n")
    # .py is not in default extensions (.log, .txt, .out)
    findings = scan_log_directory(tmp_path)
    assert findings == []


def test_scan_log_directory_sorted_critical_first(tmp_path):
    log1 = tmp_path / "a.log"
    log1.write_text("key: AKIAIOSFODNN7EXAMPLE\n")
    log2 = tmp_path / "b.log"
    log2.write_text("export DB_PASSWORD=secret123\n")
    findings = scan_log_directory(tmp_path)
    if len(findings) >= 2:
        # Critical findings must come before lower-severity ones
        priorities = [f.criticality for f in findings]
        crit_indices = [i for i, p in enumerate(priorities) if p == Criticality.CRITICAL]
        high_indices = [i for i, p in enumerate(priorities) if p == Criticality.HIGH]
        if crit_indices and high_indices:
            assert min(crit_indices) < min(high_indices)


# ---------------------------------------------------------------------------
# is_high_priority property
# ---------------------------------------------------------------------------


def test_is_high_priority_for_critical():
    f = CiSecretFinding(
        file_path="test.log",
        line_number=1,
        secret_type=SecretType.AWS_ACCESS_KEY,
        criticality=Criticality.CRITICAL,
        detector_name="aws_access_key_id",
        masked_line="AKIA****",
    )
    assert f.is_high_priority is True


def test_is_not_high_priority_for_low():
    f = CiSecretFinding(
        file_path="test.log",
        line_number=1,
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.LOW,
        detector_name="generic",
        masked_line="key=****",
    )
    assert f.is_high_priority is False
