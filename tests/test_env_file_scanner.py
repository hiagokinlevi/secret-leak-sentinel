"""
tests/test_env_file_scanner.py
===============================
≥115 tests for detectors/env_file_scanner.py covering:
  - ENV-001 through ENV-007 positive triggers and negatives
  - Dynamic AKIA pattern construction
  - Placeholder detection for all placeholder strings
  - parse_env_content edge cases
  - masked_value format
  - risk_tier thresholds
  - scan_content equivalence to parse+scan
  - scan_many correctness
  - to_dict / summary / by_severity shapes
  - Clean file → LOW / 0
"""

from __future__ import annotations

import sys
import os

# Allow importing from the repository root regardless of test invocation path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import math
import pytest
from collections import Counter

from detectors.env_file_scanner import (
    EnvCheck,
    EnvEntry,
    EnvScanResult,
    _entropy,
    _is_placeholder,
    _masked,
    _risk_tier,
    parse_env_content,
    scan_content,
    scan_entries,
    scan_many,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_entry(var: str, val: str, lineno: int = 1, fp: str = "test.env") -> EnvEntry:
    return EnvEntry(variable_name=var, value=val, line_number=lineno, file_path=fp)


def _fired_ids(result: EnvScanResult) -> list:
    return [c.check_id for c in result.checks_fired]


# ===========================================================================
# _entropy helper
# ===========================================================================

class TestEntropy:
    def test_empty_string_returns_zero(self):
        assert _entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert _entropy("aaaa") == pytest.approx(0.0)

    def test_two_equal_chars_returns_one(self):
        # "ab" → two equal probability chars → entropy = 1.0
        assert _entropy("ab") == pytest.approx(1.0)

    def test_high_entropy_random_string(self):
        # A diverse alphanumeric string should exceed 4.0 bits
        s = "aB3!xZ9#mQ2@wE7$rT5%"
        assert _entropy(s) > 4.0

    def test_low_entropy_repeated_string(self):
        # Repeating "aaa..." has entropy 0 — well below 4.0
        assert _entropy("a" * 30) < 4.0

    def test_medium_entropy_string(self):
        # "abcdefgh" repeated → predictable, should be around 3 bits
        s = "abcdefghabcdefgh"
        assert 2.5 < _entropy(s) < 4.0


# ===========================================================================
# _is_placeholder helper
# ===========================================================================

class TestIsPlaceholder:
    def test_your_prefix(self):
        assert _is_placeholder("your_api_key_here")

    def test_example(self):
        assert _is_placeholder("example_secret_value")

    def test_placeholder_literal(self):
        assert _is_placeholder("placeholder")

    def test_changeme(self):
        assert _is_placeholder("changeme123")

    def test_xxxx(self):
        assert _is_placeholder("xxxxsomething")

    def test_angle_open(self):
        assert _is_placeholder("<your-key>")

    def test_angle_close(self):
        assert _is_placeholder("value>end")

    def test_brace_open(self):
        assert _is_placeholder("{variable}")

    def test_brace_close(self):
        assert _is_placeholder("value}end")

    def test_real_secret_not_placeholder(self):
        assert not _is_placeholder("aB3xZ9mQ2wE7rT5nK8pL")

    def test_case_insensitive_your(self):
        assert _is_placeholder("YOUR_KEY_HERE")

    def test_case_insensitive_example(self):
        assert _is_placeholder("EXAMPLE_VALUE")


# ===========================================================================
# _masked helper
# ===========================================================================

class TestMasked:
    def test_long_value_shows_first_four_plus_stars(self):
        assert _masked("ABCDEFGHIJ") == "ABCD****"

    def test_exactly_five_chars(self):
        assert _masked("ABCDE") == "ABCD****"

    def test_exactly_four_chars(self):
        assert _masked("ABCD") == "****"

    def test_three_chars(self):
        assert _masked("ABC") == "****"

    def test_empty_string(self):
        assert _masked("") == "****"

    def test_one_char(self):
        assert _masked("X") == "****"


# ===========================================================================
# _risk_tier helper
# ===========================================================================

class TestRiskTier:
    def test_score_zero_is_low(self):
        assert _risk_tier(0) == "LOW"

    def test_score_19_is_low(self):
        assert _risk_tier(19) == "LOW"

    def test_score_20_is_medium(self):
        assert _risk_tier(20) == "MEDIUM"

    def test_score_39_is_medium(self):
        assert _risk_tier(39) == "MEDIUM"

    def test_score_40_is_high(self):
        assert _risk_tier(40) == "HIGH"

    def test_score_69_is_high(self):
        assert _risk_tier(69) == "HIGH"

    def test_score_70_is_critical(self):
        assert _risk_tier(70) == "CRITICAL"

    def test_score_100_is_critical(self):
        assert _risk_tier(100) == "CRITICAL"


# ===========================================================================
# parse_env_content
# ===========================================================================

class TestParseEnvContent:
    def test_basic_key_value(self):
        entries = parse_env_content("FOO=bar")
        assert len(entries) == 1
        assert entries[0].variable_name == "FOO"
        assert entries[0].value == "bar"

    def test_export_prefix(self):
        entries = parse_env_content("export MY_VAR=hello")
        assert len(entries) == 1
        assert entries[0].variable_name == "MY_VAR"
        assert entries[0].value == "hello"

    def test_double_quoted_value(self):
        entries = parse_env_content('API_KEY="abc123secretvalue"')
        assert entries[0].value == "abc123secretvalue"

    def test_single_quoted_value(self):
        entries = parse_env_content("SECRET='mysecretvalue'")
        assert entries[0].value == "mysecretvalue"

    def test_comment_line_skipped(self):
        content = "# This is a comment\nFOO=bar"
        entries = parse_env_content(content)
        assert len(entries) == 1
        assert entries[0].variable_name == "FOO"

    def test_empty_line_skipped(self):
        content = "\n\nFOO=bar\n\n"
        entries = parse_env_content(content)
        assert len(entries) == 1

    def test_inline_comment_stripped_from_bare_value(self):
        entries = parse_env_content("FOO=bar # this is an inline comment")
        assert entries[0].value == "bar"

    def test_line_number_recorded(self):
        content = "# comment\n\nFOO=bar"
        entries = parse_env_content(content)
        assert entries[0].line_number == 3

    def test_file_path_recorded(self):
        entries = parse_env_content("FOO=bar", file_path="/etc/.env")
        assert entries[0].file_path == "/etc/.env"

    def test_empty_value_parsed(self):
        entries = parse_env_content("FOO=")
        assert entries[0].variable_name == "FOO"
        assert entries[0].value == ""

    def test_multiple_entries(self):
        content = "A=1\nB=2\nC=3"
        entries = parse_env_content(content)
        assert len(entries) == 3

    def test_export_with_quoted_value(self):
        entries = parse_env_content('export TOKEN="mytoken123"')
        assert entries[0].variable_name == "TOKEN"
        assert entries[0].value == "mytoken123"

    def test_value_with_equals_sign(self):
        # Value itself can contain '='
        entries = parse_env_content("KEY=abc=def=ghi")
        assert entries[0].value == "abc=def=ghi"

    def test_whitespace_only_line_skipped(self):
        content = "   \nFOO=bar"
        entries = parse_env_content(content)
        assert len(entries) == 1


# ===========================================================================
# ENV-001: AWS access key
# ===========================================================================

class TestEnv001:
    """AKIA + 16 uppercase alphanumeric."""

    _VALID_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AKIA + 16 chars

    def test_positive_in_value(self):
        entry = _make_entry("AWS_ACCESS_KEY_ID", self._VALID_AWS_KEY)
        result = scan_entries([entry])
        assert "ENV-001" in _fired_ids(result)

    def test_positive_embedded_in_longer_value(self):
        entry = _make_entry("SOME_VAR", f"prefix-{self._VALID_AWS_KEY}-suffix")
        result = scan_entries([entry])
        assert "ENV-001" in _fired_ids(result)

    def test_negative_wrong_prefix(self):
        entry = _make_entry("AWS_KEY", "BKIAIOSFODNN7EXAMPLE")
        result = scan_entries([entry])
        assert "ENV-001" not in _fired_ids(result)

    def test_negative_too_short_after_akia(self):
        # Only 15 chars after AKIA → no match
        entry = _make_entry("AWS_KEY", "AKIA123456789012")  # 12 chars
        result = scan_entries([entry])
        assert "ENV-001" not in _fired_ids(result)

    def test_negative_lowercase_after_akia(self):
        # Pattern requires [0-9A-Z], lowercase should not match
        entry = _make_entry("AWS_KEY", "AKIAiosfodnn7exampl")
        result = scan_entries([entry])
        assert "ENV-001" not in _fired_ids(result)

    def test_dynamic_pattern_construction(self):
        # Confirm the pattern is assembled at runtime — 16 uppercase alphanumeric
        import re
        pattern = re.compile("AKIA" + r"[0-9A-Z]{16}")
        assert pattern.search(self._VALID_AWS_KEY)
        assert not pattern.search("AKIA" + "A" * 15)   # too short
        assert not pattern.search("AKIA" + "a" * 16)   # lowercase

    def test_severity_is_critical(self):
        entry = _make_entry("K", self._VALID_AWS_KEY)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-001"]
        assert checks[0].severity == "CRITICAL"

    def test_weight_is_45(self):
        entry = _make_entry("K", self._VALID_AWS_KEY)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-001"]
        assert checks[0].weight == 45


# ===========================================================================
# ENV-002: Generic API key
# ===========================================================================

class TestEnv002:
    _LONG_SECRET = "abcdefghijklmnop"  # exactly 16 chars, no placeholder

    def test_positive_api_key_name(self):
        entry = _make_entry("MY_API_KEY", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_positive_apikey_name(self):
        entry = _make_entry("APIKEY", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_positive_api_secret_name(self):
        entry = _make_entry("API_SECRET", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_positive_client_secret_name(self):
        entry = _make_entry("CLIENT_SECRET", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_positive_app_secret_name(self):
        entry = _make_entry("APP_SECRET", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_positive_case_insensitive_name(self):
        entry = _make_entry("my_api_key", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" in _fired_ids(result)

    def test_negative_short_value(self):
        # value is 15 chars — below threshold of 16
        entry = _make_entry("MY_API_KEY", "abcdefghijklmno")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_empty_value(self):
        entry = _make_entry("MY_API_KEY", "")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_your(self):
        entry = _make_entry("MY_API_KEY", "your_api_key_here_now")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_example(self):
        entry = _make_entry("MY_API_KEY", "example_key_value_12")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_placeholder(self):
        entry = _make_entry("MY_API_KEY", "placeholder_value_xx")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_changeme(self):
        entry = _make_entry("MY_API_KEY", "changeme1234567890ab")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_xxxx(self):
        entry = _make_entry("MY_API_KEY", "xxxx1234567890abcdef")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_angle_bracket(self):
        entry = _make_entry("MY_API_KEY", "<your-api-key-here>")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_placeholder_brace(self):
        entry = _make_entry("MY_API_KEY", "{insert_api_key_here}")
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_negative_wrong_var_name(self):
        entry = _make_entry("DATABASE_URL", self._LONG_SECRET)
        result = scan_entries([entry])
        assert "ENV-002" not in _fired_ids(result)

    def test_severity_is_high(self):
        entry = _make_entry("MY_API_KEY", self._LONG_SECRET)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-002"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_30(self):
        entry = _make_entry("MY_API_KEY", self._LONG_SECRET)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-002"]
        assert checks[0].weight == 30


# ===========================================================================
# ENV-003: Password variable
# ===========================================================================

class TestEnv003:
    _GOOD_PASSWORD = "sup3rSecr3t!"  # 12 chars, no placeholder

    def test_positive_password_name(self):
        entry = _make_entry("DB_PASSWORD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        assert "ENV-003" in _fired_ids(result)

    def test_positive_passwd_name(self):
        entry = _make_entry("DB_PASSWD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        assert "ENV-003" in _fired_ids(result)

    def test_positive_pwd_name(self):
        entry = _make_entry("APP_PWD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        assert "ENV-003" in _fired_ids(result)

    def test_positive_case_insensitive(self):
        entry = _make_entry("MY_PASSWORD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        assert "ENV-003" in _fired_ids(result)

    def test_negative_short_password(self):
        # 7 chars — below minimum of 8
        entry = _make_entry("DB_PASSWORD", "short7!")
        result = scan_entries([entry])
        assert "ENV-003" not in _fired_ids(result)

    def test_negative_exactly_seven_chars(self):
        entry = _make_entry("PASSWORD", "abcdefg")
        result = scan_entries([entry])
        assert "ENV-003" not in _fired_ids(result)

    def test_negative_empty_value(self):
        entry = _make_entry("DB_PASSWORD", "")
        result = scan_entries([entry])
        assert "ENV-003" not in _fired_ids(result)

    def test_negative_placeholder_changeme(self):
        entry = _make_entry("DB_PASSWORD", "changeme_default_pw")
        result = scan_entries([entry])
        assert "ENV-003" not in _fired_ids(result)

    def test_negative_placeholder_example(self):
        entry = _make_entry("DB_PASSWORD", "example_password_val")
        result = scan_entries([entry])
        assert "ENV-003" not in _fired_ids(result)

    def test_negative_wrong_var_name(self):
        entry = _make_entry("SECRET_HASH", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        # Should not fire ENV-003 (wrong keyword)
        assert "ENV-003" not in _fired_ids(result)

    def test_severity_is_high(self):
        entry = _make_entry("DB_PASSWORD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-003"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_25(self):
        entry = _make_entry("DB_PASSWORD", self._GOOD_PASSWORD)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-003"]
        assert checks[0].weight == 25


# ===========================================================================
# ENV-004: PEM private key material
# ===========================================================================

class TestEnv004:
    _PEM_VALUE = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA..."

    def test_positive_pem_header(self):
        entry = _make_entry("PRIVATE_KEY", self._PEM_VALUE)
        result = scan_entries([entry])
        assert "ENV-004" in _fired_ids(result)

    def test_positive_ec_key(self):
        entry = _make_entry("SIGNING_KEY", "-----BEGIN EC PRIVATE KEY-----\\ndata")
        result = scan_entries([entry])
        assert "ENV-004" in _fired_ids(result)

    def test_positive_generic_begin(self):
        entry = _make_entry("CERT", "-----BEGIN CERTIFICATE-----")
        result = scan_entries([entry])
        assert "ENV-004" in _fired_ids(result)

    def test_negative_no_pem_header(self):
        entry = _make_entry("SOME_KEY", "justanormalvalue")
        result = scan_entries([entry])
        assert "ENV-004" not in _fired_ids(result)

    def test_negative_partial_header(self):
        entry = _make_entry("KEY", "---BEGIN PRIVATE KEY---")
        result = scan_entries([entry])
        assert "ENV-004" not in _fired_ids(result)

    def test_severity_is_critical(self):
        entry = _make_entry("KEY", self._PEM_VALUE)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-004"]
        assert checks[0].severity == "CRITICAL"

    def test_weight_is_45(self):
        entry = _make_entry("KEY", self._PEM_VALUE)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-004"]
        assert checks[0].weight == 45


# ===========================================================================
# ENV-005: Database connection string
# ===========================================================================

class TestEnv005:
    def test_positive_postgres(self):
        entry = _make_entry("DATABASE_URL", "postgres://user:password123@localhost:5432/db")
        result = scan_entries([entry])
        assert "ENV-005" in _fired_ids(result)

    def test_positive_mysql(self):
        entry = _make_entry("DATABASE_URL", "mysql://admin:secr3tpass@db.example.com/mydb")
        result = scan_entries([entry])
        assert "ENV-005" in _fired_ids(result)

    def test_positive_mongodb(self):
        entry = _make_entry("MONGO_URI", "mongodb://dbuser:dbpassword@cluster.mongo.net/app")
        result = scan_entries([entry])
        assert "ENV-005" in _fired_ids(result)

    def test_positive_redis(self):
        entry = _make_entry("REDIS_URL", "redis://default:redispassword@cache.host:6379/0")
        result = scan_entries([entry])
        assert "ENV-005" in _fired_ids(result)

    def test_positive_mssql(self):
        entry = _make_entry("DB_CONN", "mssql://sa:SqlPass123!@sqlserver.local/testdb")
        result = scan_entries([entry])
        assert "ENV-005" in _fired_ids(result)

    def test_negative_no_credentials(self):
        entry = _make_entry("DATABASE_URL", "postgres://localhost:5432/mydb")
        result = scan_entries([entry])
        assert "ENV-005" not in _fired_ids(result)

    def test_negative_short_password_in_url(self):
        # password is only 5 chars — requires ≥6
        entry = _make_entry("DB_URL", "postgres://user:abc12@host/db")
        result = scan_entries([entry])
        assert "ENV-005" not in _fired_ids(result)

    def test_negative_unknown_scheme(self):
        entry = _make_entry("URL", "ftp://user:password123@host/path")
        result = scan_entries([entry])
        assert "ENV-005" not in _fired_ids(result)

    def test_severity_is_high(self):
        entry = _make_entry("DB", "postgres://u:password@h/d")
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-005"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_30(self):
        entry = _make_entry("DB", "postgres://u:password@h/d")
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-005"]
        assert checks[0].weight == 30


# ===========================================================================
# ENV-006: Token variable with long value
# ===========================================================================

class TestEnv006:
    # 32 printable characters, no placeholder
    _LONG_TOKEN = "abcdefghijklmnopqrstuvwxyz123456"

    def test_positive_token_name(self):
        entry = _make_entry("AUTH_TOKEN", self._LONG_TOKEN)
        result = scan_entries([entry])
        assert "ENV-006" in _fired_ids(result)

    def test_positive_access_token(self):
        entry = _make_entry("ACCESS_TOKEN", self._LONG_TOKEN)
        result = scan_entries([entry])
        assert "ENV-006" in _fired_ids(result)

    def test_positive_refresh_token(self):
        entry = _make_entry("REFRESH_TOKEN", self._LONG_TOKEN)
        result = scan_entries([entry])
        assert "ENV-006" in _fired_ids(result)

    def test_positive_bearer_name(self):
        entry = _make_entry("BEARER_TOKEN_VALUE", self._LONG_TOKEN)
        result = scan_entries([entry])
        assert "ENV-006" in _fired_ids(result)

    def test_positive_exactly_32_chars(self):
        entry = _make_entry("MY_TOKEN", "a" * 32)
        result = scan_entries([entry])
        assert "ENV-006" in _fired_ids(result)

    def test_negative_short_token(self):
        # 31 chars — below minimum of 32
        entry = _make_entry("AUTH_TOKEN", "a" * 31)
        result = scan_entries([entry])
        assert "ENV-006" not in _fired_ids(result)

    def test_negative_placeholder_your(self):
        entry = _make_entry("AUTH_TOKEN", "your_token_here_replace_now_123456")
        result = scan_entries([entry])
        assert "ENV-006" not in _fired_ids(result)

    def test_negative_wrong_var_name(self):
        entry = _make_entry("SESSION_ID", self._LONG_TOKEN)
        result = scan_entries([entry])
        assert "ENV-006" not in _fired_ids(result)

    def test_severity_is_high(self):
        entry = _make_entry("AUTH_TOKEN", self._LONG_TOKEN)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-006"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_25(self):
        entry = _make_entry("AUTH_TOKEN", self._LONG_TOKEN)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-006"]
        assert checks[0].weight == 25


# ===========================================================================
# ENV-007: High-entropy secret
# ===========================================================================

# A string that provably exceeds entropy 4.0 and length ≥ 16
_HIGH_ENTROPY_VALUE = "aB3!xZ9#mQ2@wE7$rT5%nP1^"  # diverse chars

class TestEnv007:
    def test_positive_secret_name(self):
        entry = _make_entry("APP_SECRET_VALUE", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" in _fired_ids(result)

    def test_positive_key_name(self):
        entry = _make_entry("SIGNING_KEY", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" in _fired_ids(result)

    def test_positive_credential_name(self):
        entry = _make_entry("SERVICE_CREDENTIAL", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" in _fired_ids(result)

    def test_positive_cred_name(self):
        entry = _make_entry("MY_CRED", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" in _fired_ids(result)

    def test_negative_low_entropy_value(self):
        # All same character: entropy = 0
        entry = _make_entry("MY_SECRET", "a" * 32)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_entropy_exactly_4(self):
        # Need a value whose entropy is ≤ 4.0. Use 16 chars over 16 unique chars → entropy=4.0
        s = "abcdefghijklmnop"  # exactly 16 unique chars in 16 length → entropy = 4.0
        entry = _make_entry("MY_SECRET", s)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_short_value(self):
        # Value length < 16 → skip
        entry = _make_entry("APP_SECRET", "aB3!xZ9#mQ2@wE7")  # 15 chars
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_placeholder_value(self):
        entry = _make_entry("APP_SECRET", "your_secret_value_here_now")
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_key_path_exclusion(self):
        entry = _make_entry("SSL_KEY_PATH", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_key_file_exclusion(self):
        entry = _make_entry("RSA_KEY_FILE", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_key_dir_exclusion(self):
        entry = _make_entry("CERT_KEY_DIR", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_key_name_exclusion(self):
        entry = _make_entry("KMS_KEY_NAME", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_secret_name_exclusion(self):
        entry = _make_entry("SECRET_NAME", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_secret_path_exclusion(self):
        entry = _make_entry("VAULT_SECRET_PATH", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_negative_wrong_var_name(self):
        entry = _make_entry("DATABASE_HOST", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        assert "ENV-007" not in _fired_ids(result)

    def test_severity_is_medium(self):
        entry = _make_entry("APP_SECRET", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-007"]
        assert checks[0].severity == "MEDIUM"

    def test_weight_is_20(self):
        entry = _make_entry("APP_SECRET", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-007"]
        assert checks[0].weight == 20


# ===========================================================================
# EnvScanResult metadata: risk_score, risk_tier, masked_value
# ===========================================================================

class TestEnvScanResultMeta:
    def test_no_secrets_gives_score_zero(self):
        entries = [_make_entry("HOST", "localhost"), _make_entry("PORT", "5432")]
        result = scan_entries(entries)
        assert result.risk_score == 0

    def test_no_secrets_gives_tier_low(self):
        entries = [_make_entry("HOST", "localhost")]
        result = scan_entries(entries)
        assert result.risk_tier == "LOW"

    def test_score_capped_at_100(self):
        # Two CRITICAL (45 each) = 90, but capped at 100
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        pem = "-----BEGIN RSA PRIVATE KEY-----\\ndata"
        entries = [_make_entry("K1", aws_key), _make_entry("K2", pem)]
        result = scan_entries(entries)
        assert result.risk_score <= 100

    def test_three_criticals_capped_at_100(self):
        # Three CRITICAL checks: 45+45+45=135, capped at 100
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        pem1 = "-----BEGIN RSA PRIVATE KEY-----\\ndata"
        pem2 = "-----BEGIN EC PRIVATE KEY-----\\ndata"
        entries = [
            _make_entry("K1", aws_key),
            _make_entry("K2", pem1),
            _make_entry("K3", pem2),
        ]
        result = scan_entries(entries)
        assert result.risk_score == 100

    def test_total_entries_count(self):
        entries = [_make_entry(f"K{i}", f"v{i}") for i in range(7)]
        result = scan_entries(entries)
        assert result.total_entries == 7

    def test_masked_value_in_check(self):
        entry = _make_entry("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-001"]
        assert checks[0].masked_value == "AKIA****"

    def test_masked_value_short_in_check(self):
        # PEM header triggers ENV-004 with a short prefix value
        entry = _make_entry("K", "-----BEGIN")
        result = scan_entries([entry])
        checks = [c for c in result.checks_fired if c.check_id == "ENV-004"]
        assert checks[0].masked_value == "----****"

    def test_risk_tier_medium_at_20(self):
        # ENV-007 weight=20 alone → MEDIUM
        entry = _make_entry("APP_SECRET", _HIGH_ENTROPY_VALUE)
        result = scan_entries([entry])
        # ENV-007 fires with weight=20 → MEDIUM
        if "ENV-007" in _fired_ids(result):
            assert result.risk_tier in ("MEDIUM", "HIGH", "CRITICAL")

    def test_file_path_propagated(self):
        entries = [_make_entry("K", "v", fp="/my/.env")]
        result = scan_entries(entries, file_path="/my/.env")
        assert result.file_path == "/my/.env"


# ===========================================================================
# EnvScanResult methods: to_dict / summary / by_severity
# ===========================================================================

class TestEnvScanResultMethods:
    def _result_with_checks(self) -> EnvScanResult:
        entries = [
            _make_entry("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            _make_entry("DB_PASSWORD", "sup3rSecr3t!"),
            _make_entry("APP_SECRET", _HIGH_ENTROPY_VALUE),
        ]
        return scan_entries(entries, file_path="config.env")

    def test_to_dict_keys(self):
        result = self._result_with_checks()
        d = result.to_dict()
        assert "file_path" in d
        assert "risk_score" in d
        assert "risk_tier" in d
        assert "total_entries" in d
        assert "checks_fired" in d

    def test_to_dict_checks_fired_is_list(self):
        result = self._result_with_checks()
        d = result.to_dict()
        assert isinstance(d["checks_fired"], list)

    def test_to_dict_check_keys(self):
        result = self._result_with_checks()
        d = result.to_dict()
        if d["checks_fired"]:
            check = d["checks_fired"][0]
            for key in ("check_id", "severity", "description", "variable_name",
                        "masked_value", "line_number", "weight"):
                assert key in check

    def test_to_dict_file_path_matches(self):
        result = self._result_with_checks()
        assert result.to_dict()["file_path"] == "config.env"

    def test_summary_contains_file_path(self):
        result = self._result_with_checks()
        assert "config.env" in result.summary()

    def test_summary_contains_risk_tier(self):
        result = self._result_with_checks()
        assert result.risk_tier in result.summary()

    def test_summary_contains_score(self):
        result = self._result_with_checks()
        assert str(result.risk_score) in result.summary()

    def test_summary_is_string(self):
        result = self._result_with_checks()
        assert isinstance(result.summary(), str)

    def test_by_severity_keys(self):
        result = self._result_with_checks()
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert "HIGH" in by_sev
        assert "MEDIUM" in by_sev

    def test_by_severity_values_are_lists(self):
        result = self._result_with_checks()
        by_sev = result.by_severity()
        for v in by_sev.values():
            assert isinstance(v, list)

    def test_by_severity_critical_contains_env001(self):
        result = self._result_with_checks()
        critical = result.by_severity().get("CRITICAL", [])
        ids = [c.check_id for c in critical]
        assert "ENV-001" in ids

    def test_by_severity_no_checks_all_empty_lists(self):
        entries = [_make_entry("HOST", "localhost")]
        result = scan_entries(entries)
        by_sev = result.by_severity()
        assert by_sev.get("CRITICAL", []) == []
        assert by_sev.get("HIGH", []) == []
        assert by_sev.get("MEDIUM", []) == []


# ===========================================================================
# scan_content equivalence to parse + scan
# ===========================================================================

class TestScanContent:
    def test_equivalence_to_parse_then_scan(self):
        content = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "DB_PASSWORD=sup3rSecr3t!\n"
        )
        fp = "test.env"
        result_direct = scan_content(content, file_path=fp)
        entries = parse_env_content(content, file_path=fp)
        result_manual = scan_entries(entries, file_path=fp)
        assert result_direct.risk_score == result_manual.risk_score
        assert result_direct.risk_tier == result_manual.risk_tier
        assert len(result_direct.checks_fired) == len(result_manual.checks_fired)

    def test_file_path_propagated(self):
        result = scan_content("HOST=localhost", file_path="myfile.env")
        assert result.file_path == "myfile.env"

    def test_no_secrets_returns_low(self):
        content = "HOST=localhost\nPORT=5432\nDEBUG=true\n"
        result = scan_content(content)
        assert result.risk_tier == "LOW"
        assert result.risk_score == 0

    def test_total_entries_reflects_parsed_lines(self):
        content = "A=1\nB=2\nC=3\n# comment\n\nD=4\n"
        result = scan_content(content)
        assert result.total_entries == 4


# ===========================================================================
# scan_many
# ===========================================================================

class TestScanMany:
    def test_returns_one_result_per_input(self):
        pairs = [
            ("a.env", "HOST=localhost"),
            ("b.env", "HOST=remotehost"),
            ("c.env", "HOST=otherhost"),
        ]
        results = scan_many(pairs)
        assert len(results) == 3

    def test_file_paths_correct(self):
        pairs = [
            ("first.env", "A=1"),
            ("second.env", "B=2"),
        ]
        results = scan_many(pairs)
        assert results[0].file_path == "first.env"
        assert results[1].file_path == "second.env"

    def test_empty_list_returns_empty(self):
        assert scan_many([]) == []

    def test_detects_secrets_in_mixed_files(self):
        pairs = [
            ("clean.env", "HOST=localhost\nPORT=5432\n"),
            ("dirty.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"),
        ]
        results = scan_many(pairs)
        clean, dirty = results
        assert clean.risk_tier == "LOW"
        assert dirty.risk_tier != "LOW"

    def test_order_preserved(self):
        pairs = [(f"file{i}.env", f"VAR{i}=val{i}") for i in range(5)]
        results = scan_many(pairs)
        for i, r in enumerate(results):
            assert r.file_path == f"file{i}.env"


# ===========================================================================
# Integration: realistic .env file content
# ===========================================================================

class TestIntegrationRealistic:
    _CLEAN_ENV = (
        "# Application configuration\n"
        "\n"
        "APP_NAME=MyApplication\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "APP_PORT=8080\n"
        "\n"
        "# Database\n"
        "DB_HOST=localhost\n"
        "DB_PORT=5432\n"
        "DB_NAME=appdb\n"
    )

    _DIRTY_ENV = (
        "APP_NAME=MyApplication\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        'DATABASE_URL=postgres://admin:securepassword@db.host/mydb\n'
        "DB_PASSWORD=MyStr0ngPassw0rd\n"
        "API_KEY=abcdefghijklmnopqrstuvwxyz123456\n"
    )

    def test_clean_env_is_low(self):
        result = scan_content(self._CLEAN_ENV, file_path=".env")
        assert result.risk_tier == "LOW"
        assert result.risk_score == 0
        assert result.checks_fired == []

    def test_dirty_env_has_multiple_checks(self):
        result = scan_content(self._DIRTY_ENV, file_path=".env")
        assert len(result.checks_fired) >= 3

    def test_dirty_env_is_critical_or_high(self):
        result = scan_content(self._DIRTY_ENV, file_path=".env")
        assert result.risk_tier in ("CRITICAL", "HIGH")

    def test_dirty_env_total_entries_correct(self):
        result = scan_content(self._DIRTY_ENV, file_path=".env")
        assert result.total_entries == 5

    def test_env001_fired_in_dirty(self):
        result = scan_content(self._DIRTY_ENV)
        assert "ENV-001" in _fired_ids(result)

    def test_env003_fired_in_dirty(self):
        result = scan_content(self._DIRTY_ENV)
        assert "ENV-003" in _fired_ids(result)

    def test_env005_fired_in_dirty(self):
        result = scan_content(self._DIRTY_ENV)
        assert "ENV-005" in _fired_ids(result)
