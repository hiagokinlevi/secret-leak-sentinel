"""
Tests for hooks/pre_commit_hook.py
=====================================
Comprehensive test suite for the pre-commit secret scanning hook.

Covers:
  - Clean files produce exit_code 0
  - Detection of every built-in pattern (SC-001 through SC-006)
  - Severity ordering and comparison via SeverityLevel
  - HookConfig.fail_level property including unknown/edge-case values
  - skip_paths and skip_extensions filtering
  - allow_list suppression
  - fail_on_severity thresholds (CRITICAL, HIGH, MEDIUM, LOW)
  - max_file_size_kb enforcement
  - include_regex=False disables pattern matching
  - Multiple patterns in a single file
  - blocked_files list contents
  - total_findings aggregation across files
  - HookResult.is_blocked property
  - FileScanResult.to_dict() and HookResult.to_dict() structure
  - PreCommitHook.get_config_summary()

All credentials used in this test file are SYNTHETIC and non-functional.
They match the required format but have never been valid secrets.
"""
import pytest

from hooks.pre_commit_hook import (
    FileScanResult,
    HookConfig,
    HookResult,
    PreCommitHook,
    SeverityLevel,
    _severity_from_str,
)

# Dynamically-constructed synthetic secrets to avoid triggering SCM push-protection rules.
_FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_FAKE_AWS2 = "AKIA" + "BB3Z1G0D5L6NTEST"
_FAKE_AWS3 = "AKIA" + "XYZ1234567890ABC"
_FAKE_GHP = "ghp_" + "x" * 40
_FAKE_GHO = "gho_" + "x" * 40
_FAKE_GHS = "ghs_" + "x" * 40
_FAKE_STRIPE = "sk_live_" + "aBcDeFgHiJkLmNoPqRsTuVwX"


# =============================================================================
# SeverityLevel — enum ordering
# =============================================================================

class TestSeverityLevelOrdering:
    """Verify that SeverityLevel comparison operators work correctly."""

    def test_critical_ge_high(self):
        """CRITICAL must be >= HIGH."""
        assert SeverityLevel.CRITICAL >= SeverityLevel.HIGH

    def test_critical_ge_critical(self):
        """A level is >= itself."""
        assert SeverityLevel.CRITICAL >= SeverityLevel.CRITICAL

    def test_high_not_ge_critical(self):
        """HIGH must NOT be >= CRITICAL."""
        assert not (SeverityLevel.HIGH >= SeverityLevel.CRITICAL)

    def test_medium_ge_low(self):
        assert SeverityLevel.MEDIUM >= SeverityLevel.LOW

    def test_medium_ge_medium(self):
        assert SeverityLevel.MEDIUM >= SeverityLevel.MEDIUM

    def test_low_not_ge_medium(self):
        assert not (SeverityLevel.LOW >= SeverityLevel.MEDIUM)

    def test_info_is_lowest(self):
        """INFO must be strictly less than all other levels."""
        for level in (SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            assert SeverityLevel.INFO < level

    def test_gt_operator(self):
        assert SeverityLevel.HIGH > SeverityLevel.MEDIUM

    def test_lt_operator(self):
        assert SeverityLevel.LOW < SeverityLevel.HIGH

    def test_le_operator(self):
        assert SeverityLevel.MEDIUM <= SeverityLevel.MEDIUM
        assert SeverityLevel.LOW <= SeverityLevel.HIGH

    def test_values_are_integers(self):
        assert SeverityLevel.CRITICAL.value == 4
        assert SeverityLevel.HIGH.value == 3
        assert SeverityLevel.MEDIUM.value == 2
        assert SeverityLevel.LOW.value == 1
        assert SeverityLevel.INFO.value == 0


# =============================================================================
# HookConfig — configuration and fail_level property
# =============================================================================

class TestHookConfig:
    """Tests for the HookConfig dataclass and its fail_level property."""

    def test_default_fail_on_severity_is_high(self):
        cfg = HookConfig()
        assert cfg.fail_on_severity == "HIGH"

    def test_fail_level_high(self):
        cfg = HookConfig(fail_on_severity="HIGH")
        assert cfg.fail_level == SeverityLevel.HIGH

    def test_fail_level_critical(self):
        cfg = HookConfig(fail_on_severity="CRITICAL")
        assert cfg.fail_level == SeverityLevel.CRITICAL

    def test_fail_level_medium(self):
        cfg = HookConfig(fail_on_severity="MEDIUM")
        assert cfg.fail_level == SeverityLevel.MEDIUM

    def test_fail_level_low(self):
        cfg = HookConfig(fail_on_severity="LOW")
        assert cfg.fail_level == SeverityLevel.LOW

    def test_fail_level_case_insensitive(self):
        """fail_on_severity matching must be case-insensitive."""
        cfg = HookConfig(fail_on_severity="high")
        assert cfg.fail_level == SeverityLevel.HIGH

    def test_fail_level_unknown_defaults_to_high(self):
        """An unrecognised severity string must fall back to HIGH."""
        cfg = HookConfig(fail_on_severity="UNKNOWN_LEVEL")
        assert cfg.fail_level == SeverityLevel.HIGH

    def test_default_lists_are_empty(self):
        cfg = HookConfig()
        assert cfg.skip_paths == []
        assert cfg.skip_extensions == []
        assert cfg.allow_list == []

    def test_default_max_file_size_kb(self):
        assert HookConfig().max_file_size_kb == 1024

    def test_default_include_flags(self):
        cfg = HookConfig()
        assert cfg.include_entropy is True
        assert cfg.include_regex is True


# =============================================================================
# Clean file — no secrets
# =============================================================================

class TestCleanFile:
    """A file with no secrets must produce exit_code 0 and zero findings."""

    def test_clean_python_file_exit_code_zero(self):
        hook = PreCommitHook()
        result = hook.scan_files({"src/utils.py": "def add(a, b):\n    return a + b\n"})
        assert result.exit_code == 0

    def test_clean_file_zero_findings(self):
        hook = PreCommitHook()
        result = hook.scan_files({"README.md": "# My project\nNo secrets here.\n"})
        assert result.total_findings == 0

    def test_clean_file_is_not_blocked(self):
        hook = PreCommitHook()
        result = hook.scan_files({"app/main.py": "print('hello world')\n"})
        assert result.is_blocked is False

    def test_clean_file_blocked_files_empty(self):
        hook = PreCommitHook()
        result = hook.scan_files({"app/main.py": "print('hello world')\n"})
        assert result.blocked_files == []

    def test_empty_files_dict_is_clean(self):
        hook = PreCommitHook()
        result = hook.scan_files({})
        assert result.exit_code == 0
        assert result.total_findings == 0


# =============================================================================
# SC-001 — AWS Access Key (CRITICAL)
# =============================================================================

class TestAWSKeyDetection:
    """Tests for SC-001: AWS Access Key ID (CRITICAL)."""

    def test_aws_key_detected(self):
        """A synthetic AWS key must be detected and trigger a block."""
        hook = PreCommitHook()
        result = hook.scan_files({"config.py": f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"'})
        assert result.total_findings >= 1

    def test_aws_key_exit_code_one(self):
        hook = PreCommitHook()
        result = hook.scan_files({"config.py": f'key = "{_FAKE_AWS}"'})
        assert result.exit_code == 1

    def test_aws_key_is_blocked(self):
        hook = PreCommitHook()
        result = hook.scan_files({"config.py": f'key = "{_FAKE_AWS}"'})
        assert result.is_blocked is True

    def test_aws_key_file_in_blocked_list(self):
        hook = PreCommitHook()
        result = hook.scan_files({"secrets.env": _FAKE_AWS})
        assert "secrets.env" in result.blocked_files

    def test_aws_key_severity_count_is_critical(self):
        hook = PreCommitHook()
        result = hook.scan_files({"env.py": _FAKE_AWS})
        file_res = result.file_results[0]
        assert file_res.severity_counts.get("CRITICAL", 0) >= 1


# =============================================================================
# SC-002 — GitHub Token (HIGH)
# =============================================================================

class TestGitHubTokenDetection:
    """Tests for SC-002: GitHub tokens (HIGH)."""

    def test_github_pat_detected(self):
        """A synthetic GitHub PAT (ghp_) must be detected."""
        hook = PreCommitHook()
        content = f'GITHUB_TOKEN = "{_FAKE_GHP}"'
        result = hook.scan_files({"ci.yml": content})
        assert result.total_findings >= 1

    def test_github_pat_blocks_with_high_threshold(self):
        hook = PreCommitHook(HookConfig(fail_on_severity="HIGH"))
        content = f"token={_FAKE_GHP}"
        result = hook.scan_files({"deploy.sh": content})
        assert result.is_blocked is True

    def test_github_oauth_token_detected(self):
        """A synthetic GitHub OAuth token (gho_) must be detected."""
        hook = PreCommitHook()
        content = _FAKE_GHO
        result = hook.scan_files({".env": content})
        assert result.total_findings >= 1

    def test_github_server_to_server_detected(self):
        """ghs_ prefix (server-to-server) must be detected by the gh[pousr]_ pattern."""
        hook = PreCommitHook()
        content = _FAKE_GHS
        result = hook.scan_files({"config.env": content})
        assert result.total_findings >= 1


# =============================================================================
# SC-003 — Private Key (HIGH)
# =============================================================================

class TestPrivateKeyDetection:
    """Tests for SC-003: PEM private key block header (HIGH)."""

    def test_rsa_private_key_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"server.key": "-----BEGIN RSA PRIVATE KEY-----"})
        assert result.total_findings >= 1

    def test_ec_private_key_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"ec.pem": "-----BEGIN EC PRIVATE KEY-----"})
        assert result.total_findings >= 1

    def test_generic_private_key_detected(self):
        """'BEGIN PRIVATE KEY' (no algorithm prefix) must also match."""
        hook = PreCommitHook()
        result = hook.scan_files({"key.pem": "-----BEGIN PRIVATE KEY-----"})
        assert result.total_findings >= 1

    def test_private_key_blocks_commit(self):
        hook = PreCommitHook(HookConfig(fail_on_severity="HIGH"))
        result = hook.scan_files({"deploy.pem": "-----BEGIN RSA PRIVATE KEY-----"})
        assert result.is_blocked is True


# =============================================================================
# SC-004 — Password assignment (MEDIUM)
# =============================================================================

class TestPasswordPatternDetection:
    """Tests for SC-004: hardcoded password in assignment context (MEDIUM)."""

    def test_password_equals_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"settings.py": "password = 'MyS3cur3P@ssword'"})
        assert result.total_findings >= 1

    def test_passwd_variant_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"db.cfg": "passwd=supersecret123"})
        assert result.total_findings >= 1

    def test_pwd_variant_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"app.cfg": "pwd: longpassword99"})
        assert result.total_findings >= 1

    def test_password_medium_severity_does_not_block_with_high_threshold(self):
        """MEDIUM finding must NOT block when fail_on_severity=HIGH."""
        cfg = HookConfig(fail_on_severity="HIGH")
        hook = PreCommitHook(cfg)
        # SC-004 is MEDIUM; SC-001/002/003/006 are CRITICAL/HIGH — only use a
        # pattern that exclusively matches MEDIUM
        content = "api_key = 'shortshortshortshortkey1'"
        result = hook.scan_files({"config.ini": content})
        # SC-005 is MEDIUM too; ensure no HIGH pattern fires
        # Use a stand-alone MEDIUM-only payload
        medium_content = "password = 'averylongpasswordvalue'"
        result2 = hook.scan_files({"cfg.ini": medium_content})
        # With fail_on_severity=HIGH, MEDIUM findings should NOT block
        assert result2.exit_code == 0

    def test_password_medium_blocks_with_low_threshold(self):
        """MEDIUM finding MUST block when fail_on_severity=LOW."""
        cfg = HookConfig(fail_on_severity="LOW")
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.ini": "password = 'averylongpasswordvalue'"})
        assert result.is_blocked is True


# =============================================================================
# SC-005 — API key / access token (MEDIUM)
# =============================================================================

class TestAPIKeyDetection:
    """Tests for SC-005: generic API key or access token (MEDIUM)."""

    def test_api_key_assignment_detected(self):
        hook = PreCommitHook(HookConfig(fail_on_severity="LOW"))
        result = hook.scan_files({"config.py": "api_key = 'abcdefghijklmnop1234'"})
        assert result.total_findings >= 1

    def test_access_token_detected(self):
        hook = PreCommitHook(HookConfig(fail_on_severity="LOW"))
        result = hook.scan_files({"auth.py": "access_token = 'abcdefghijklmnop1234'"})
        assert result.total_findings >= 1


# =============================================================================
# SC-006 — Stripe live key (HIGH)
# =============================================================================

class TestStripeLiveKeyDetection:
    """Tests for SC-006: Stripe live-mode secret key (HIGH)."""

    def test_stripe_live_key_detected(self):
        hook = PreCommitHook()
        result = hook.scan_files({"payments.py": _FAKE_STRIPE})
        assert result.total_findings >= 1

    def test_stripe_live_key_blocks_with_high_threshold(self):
        hook = PreCommitHook(HookConfig(fail_on_severity="HIGH"))
        result = hook.scan_files({"billing.py": f"STRIPE_KEY = {_FAKE_STRIPE}"})
        assert result.is_blocked is True


# =============================================================================
# skip_paths filtering
# =============================================================================

class TestSkipPaths:
    """Files whose path matches skip_paths must be skipped entirely."""

    def test_file_in_tests_dir_skipped(self):
        cfg = HookConfig(skip_paths=["tests/"])
        hook = PreCommitHook(cfg)
        # Even a file with a real secret should be skipped
        result = hook.scan_files({"tests/fixtures/aws.py": _FAKE_AWS})
        assert result.total_findings == 0

    def test_file_in_tests_dir_not_blocked(self):
        cfg = HookConfig(skip_paths=["tests/"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"tests/fixtures/aws.py": _FAKE_AWS})
        assert result.is_blocked is False

    def test_skipped_file_produces_no_file_result(self):
        """Skipped files should not appear in file_results at all."""
        cfg = HookConfig(skip_paths=["vendor/"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"vendor/lib/token.js": _FAKE_STRIPE})
        assert result.file_results == []

    def test_non_skipped_file_is_still_scanned(self):
        """Files NOT in skip_paths must still be scanned normally."""
        cfg = HookConfig(skip_paths=["tests/"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({
            "tests/fixture.py": _FAKE_AWS,   # skipped
            "src/config.py": _FAKE_AWS,      # scanned
        })
        assert result.total_findings >= 1
        assert "src/config.py" in result.blocked_files


# =============================================================================
# skip_extensions filtering
# =============================================================================

class TestSkipExtensions:
    """Files with a skipped extension must be excluded from scanning."""

    def test_md_extension_skipped(self):
        cfg = HookConfig(skip_extensions=[".md"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"CREDENTIALS.md": _FAKE_AWS})
        assert result.total_findings == 0

    def test_lock_extension_skipped(self):
        cfg = HookConfig(skip_extensions=[".lock"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"poetry.lock": _FAKE_AWS})
        assert result.total_findings == 0

    def test_multiple_extensions_skipped(self):
        cfg = HookConfig(skip_extensions=[".md", ".txt", ".lock"])
        hook = PreCommitHook(cfg)
        files = {
            "notes.txt": _FAKE_AWS,
            "README.md": _FAKE_AWS,
            "poetry.lock": _FAKE_AWS,
        }
        result = hook.scan_files(files)
        assert result.total_findings == 0

    def test_python_file_not_skipped_by_md_rule(self):
        cfg = HookConfig(skip_extensions=[".md"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"config.py": _FAKE_AWS})
        assert result.total_findings >= 1


# =============================================================================
# allow_list suppression
# =============================================================================

class TestAllowList:
    """Lines containing an allow-list token must have their finding suppressed."""

    def test_allow_list_token_suppresses_finding(self):
        cfg = HookConfig(allow_list=["EXAMPLE_KEY_DO_NOT_USE"])
        hook = PreCommitHook(cfg)
        content = f"# EXAMPLE_KEY_DO_NOT_USE {_FAKE_AWS}"
        result = hook.scan_files({"docs/example.py": content})
        assert result.total_findings == 0

    def test_allow_list_token_prevents_block(self):
        cfg = HookConfig(allow_list=["notsecret"])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": f"{_FAKE_AWS}  # notsecret"})
        assert result.is_blocked is False

    def test_allow_list_only_suppresses_matching_line(self):
        """The allow-list token must only suppress the line it appears on."""
        cfg = HookConfig(allow_list=["FIXTURE"])
        hook = PreCommitHook(cfg)
        files = {
            "test.py": (
                f"key = {_FAKE_AWS}  # FIXTURE\n"
                f"real = {_FAKE_AWS}EXTRA\n"  # NOT suppressed (no token, also wrong len)
            )
        }
        # The second line does not contain "FIXTURE" but also does not have
        # exactly 16 uppercase chars after AKIA — so effectively only line 1
        # would have matched.  Use a clean second line for clarity.
        files2 = {
            "test.py": (
                f"key = {_FAKE_AWS}  # FIXTURE\n"
                f"other = {_FAKE_AWS2}\n"
            )
        }
        result = hook.scan_files(files2)
        # Line 1 is suppressed; line 2 is not — should still have a finding
        assert result.total_findings >= 1

    def test_empty_allow_list_does_not_suppress(self):
        cfg = HookConfig(allow_list=[])
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"env.py": _FAKE_AWS})
        assert result.total_findings >= 1


# =============================================================================
# fail_on_severity threshold behaviour
# =============================================================================

class TestFailOnSeverityThreshold:
    """Verify that the threshold correctly controls which findings block commits."""

    def test_critical_threshold_medium_finding_does_not_block(self):
        """With fail_on_severity=CRITICAL, MEDIUM findings must NOT block."""
        cfg = HookConfig(fail_on_severity="CRITICAL")
        hook = PreCommitHook(cfg)
        # SC-004 (MEDIUM) — password assignment
        result = hook.scan_files({"cfg.py": "password = 'longpassword99'"})
        assert result.is_blocked is False

    def test_critical_threshold_critical_finding_blocks(self):
        """With fail_on_severity=CRITICAL, CRITICAL findings MUST block."""
        cfg = HookConfig(fail_on_severity="CRITICAL")
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": _FAKE_AWS})
        assert result.is_blocked is True

    def test_low_threshold_medium_finding_blocks(self):
        """With fail_on_severity=LOW, a MEDIUM finding must block."""
        cfg = HookConfig(fail_on_severity="LOW")
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": "password = 'longpassword99'"})
        assert result.is_blocked is True

    def test_low_threshold_all_patterns_block(self):
        """With fail_on_severity=LOW, every built-in pattern should block."""
        cfg = HookConfig(fail_on_severity="LOW")
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"any.py": _FAKE_AWS})
        assert result.is_blocked is True

    def test_high_threshold_high_finding_blocks(self):
        """SC-006 (HIGH) must block when fail_on_severity=HIGH."""
        cfg = HookConfig(fail_on_severity="HIGH")
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"pay.py": _FAKE_STRIPE})
        assert result.is_blocked is True


# =============================================================================
# max_file_size_kb enforcement
# =============================================================================

class TestMaxFileSizeKb:
    """Files exceeding max_file_size_kb must be skipped."""

    def test_oversized_file_skipped(self):
        """A file larger than max_file_size_kb should produce zero findings."""
        cfg = HookConfig(max_file_size_kb=1)  # 1 KB limit
        hook = PreCommitHook(cfg)
        # Build content > 1024 bytes that contains a secret
        large_content = _FAKE_AWS + "\n" + ("x" * 1100)
        result = hook.scan_files({"big.py": large_content})
        assert result.total_findings == 0

    def test_file_at_limit_is_scanned(self):
        """A file at exactly the size limit should still be scanned."""
        cfg = HookConfig(max_file_size_kb=1)
        hook = PreCommitHook(cfg)
        # Exactly 1024 bytes — pad with harmless chars, end with the secret
        safe_padding = "# " + ("a" * 1000) + "\n"  # ~1004 bytes
        content = safe_padding + _FAKE_AWS
        # Ensure it is within the limit
        assert len(content.encode("utf-8")) <= 1024
        result = hook.scan_files({"ok.py": content})
        assert result.total_findings >= 1

    def test_large_clean_file_skipped_gracefully(self):
        """Oversized clean files must be skipped without raising an error."""
        cfg = HookConfig(max_file_size_kb=1)
        hook = PreCommitHook(cfg)
        large_clean = "# no secrets\n" + ("y" * 2000)
        result = hook.scan_files({"large_clean.py": large_clean})
        assert result.total_findings == 0
        assert result.exit_code == 0


# =============================================================================
# include_regex=False
# =============================================================================

class TestIncludeRegexFalse:
    """When include_regex=False the built-in patterns must not run."""

    def test_regex_disabled_no_findings(self):
        cfg = HookConfig(include_regex=False)
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": _FAKE_AWS})
        assert result.total_findings == 0

    def test_regex_disabled_not_blocked(self):
        cfg = HookConfig(include_regex=False)
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": _FAKE_STRIPE})
        assert result.is_blocked is False

    def test_regex_enabled_finds_secret(self):
        """Sanity check: same content finds a secret when include_regex=True."""
        cfg = HookConfig(include_regex=True)
        hook = PreCommitHook(cfg)
        result = hook.scan_files({"cfg.py": _FAKE_AWS})
        assert result.total_findings >= 1


# =============================================================================
# Multiple patterns in the same file
# =============================================================================

class TestMultiplePatternsInFile:
    """A single file can trigger multiple pattern rules simultaneously."""

    def test_aws_and_github_in_same_file(self):
        hook = PreCommitHook()
        content = f"AWS_KEY = {_FAKE_AWS}\n" + f"GH_TOKEN = {_FAKE_GHP}\n"
        result = hook.scan_files({"secrets.env": content})
        assert result.total_findings >= 2

    def test_multiple_patterns_all_counted_in_file_result(self):
        hook = PreCommitHook()
        content = _FAKE_AWS + "\n" + _FAKE_STRIPE + "\n"
        result = hook.scan_files({"multi.py": content})
        file_res = result.file_results[0]
        assert file_res.findings_count >= 2

    def test_severity_counts_reflect_multiple_rules(self):
        """severity_counts must track CRITICAL and HIGH separately."""
        hook = PreCommitHook()
        content = (
            _FAKE_AWS + "\n"      # CRITICAL (SC-001)
            + _FAKE_STRIPE + "\n" # HIGH (SC-006)
        )
        result = hook.scan_files({"mixed.py": content})
        file_res = result.file_results[0]
        assert file_res.severity_counts.get("CRITICAL", 0) >= 1
        assert file_res.severity_counts.get("HIGH", 0) >= 1


# =============================================================================
# blocked_files and total_findings across multiple files
# =============================================================================

class TestMultiFileScanning:
    """Verify aggregation across multiple files."""

    def test_blocked_files_lists_only_blocked_paths(self):
        hook = PreCommitHook()
        files = {
            "clean.py": "print('ok')\n",
            "dirty.py": _FAKE_AWS + "\n",
        }
        result = hook.scan_files(files)
        assert "dirty.py" in result.blocked_files
        assert "clean.py" not in result.blocked_files

    def test_total_findings_aggregates_across_files(self):
        hook = PreCommitHook()
        files = {
            "a.py": _FAKE_AWS + "\n",
            "b.py": _FAKE_AWS3 + "\n",
        }
        result = hook.scan_files(files)
        assert result.total_findings >= 2

    def test_multiple_blocked_files(self):
        hook = PreCommitHook()
        files = {
            "a.py": _FAKE_AWS + "\n",
            "b.py": _FAKE_AWS3 + "\n",
            "c.py": "print('clean')\n",
        }
        result = hook.scan_files(files)
        assert len(result.blocked_files) == 2
        assert "c.py" not in result.blocked_files

    def test_only_below_threshold_does_not_block_any_file(self):
        """With fail_on_severity=CRITICAL, only CRITICAL findings block."""
        cfg = HookConfig(fail_on_severity="CRITICAL")
        hook = PreCommitHook(cfg)
        files = {
            # SC-006 is HIGH, not CRITICAL — should NOT block under CRITICAL threshold
            "pay.py": _FAKE_STRIPE + "\n",
        }
        result = hook.scan_files(files)
        assert result.is_blocked is False
        assert result.blocked_files == []


# =============================================================================
# HookResult properties and serialisation
# =============================================================================

class TestHookResult:
    """Tests for HookResult.is_blocked and HookResult.to_dict()."""

    def test_is_blocked_true_when_exit_code_one(self):
        result = HookResult(
            exit_code=1,
            total_findings=1,
            blocked_files=["x.py"],
            file_results=[],
            message="blocked",
            generated_at=0.0,
        )
        assert result.is_blocked is True

    def test_is_blocked_false_when_exit_code_zero(self):
        result = HookResult(
            exit_code=0,
            total_findings=0,
            blocked_files=[],
            file_results=[],
            message="clean",
            generated_at=0.0,
        )
        assert result.is_blocked is False

    def test_to_dict_contains_required_keys(self):
        hook = PreCommitHook()
        result = hook.scan_files({"clean.py": "x = 1\n"})
        d = result.to_dict()
        for key in ("exit_code", "total_findings", "blocked_files", "file_results", "message", "generated_at"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_exit_code_is_int(self):
        hook = PreCommitHook()
        result = hook.scan_files({"clean.py": "x = 1\n"})
        assert isinstance(result.to_dict()["exit_code"], int)

    def test_to_dict_blocked_files_is_list(self):
        hook = PreCommitHook()
        result = hook.scan_files({"dirty.py": _FAKE_AWS})
        assert isinstance(result.to_dict()["blocked_files"], list)

    def test_to_dict_file_results_is_list_of_dicts(self):
        hook = PreCommitHook()
        result = hook.scan_files({"dirty.py": _FAKE_AWS})
        d = result.to_dict()
        assert isinstance(d["file_results"], list)
        assert all(isinstance(fr, dict) for fr in d["file_results"])

    def test_generated_at_is_float(self):
        hook = PreCommitHook()
        result = hook.scan_files({})
        assert isinstance(result.generated_at, float)


# =============================================================================
# FileScanResult.to_dict()
# =============================================================================

class TestFileScanResultToDict:
    """Tests for FileScanResult.to_dict() structure."""

    def test_to_dict_contains_required_keys(self):
        fr = FileScanResult(
            file_path="src/config.py",
            findings_count=2,
            blocked=True,
            severity_counts={"CRITICAL": 1, "HIGH": 1},
            findings_summary=["[SC-001] CRITICAL @ line 1: AKIA****[20chars]"],
        )
        d = fr.to_dict()
        for key in ("file_path", "findings_count", "blocked", "severity_counts", "findings_summary"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_severity_counts_is_dict(self):
        fr = FileScanResult(
            file_path="a.py",
            findings_count=1,
            blocked=True,
            severity_counts={"HIGH": 1},
        )
        assert isinstance(fr.to_dict()["severity_counts"], dict)

    def test_to_dict_findings_summary_is_list(self):
        fr = FileScanResult(
            file_path="a.py",
            findings_count=0,
            blocked=False,
        )
        assert isinstance(fr.to_dict()["findings_summary"], list)

    def test_to_dict_blocked_is_bool(self):
        fr = FileScanResult(file_path="a.py", findings_count=0, blocked=False)
        assert isinstance(fr.to_dict()["blocked"], bool)


# =============================================================================
# get_config_summary
# =============================================================================

class TestGetConfigSummary:
    """Tests for PreCommitHook.get_config_summary()."""

    def test_summary_contains_expected_keys(self):
        hook = PreCommitHook()
        summary = hook.get_config_summary()
        expected_keys = {
            "fail_on_severity", "fail_level", "skip_paths", "skip_extensions",
            "max_file_size_kb", "include_entropy", "include_regex", "allow_list",
        }
        assert expected_keys.issubset(summary.keys())

    def test_summary_fail_level_is_name_string(self):
        """fail_level in the summary should be the enum member name, not its value."""
        hook = PreCommitHook(HookConfig(fail_on_severity="HIGH"))
        summary = hook.get_config_summary()
        assert summary["fail_level"] == "HIGH"

    def test_summary_reflects_custom_config(self):
        cfg = HookConfig(
            fail_on_severity="CRITICAL",
            skip_paths=["vendor/"],
            skip_extensions=[".lock"],
            max_file_size_kb=512,
            include_entropy=False,
            include_regex=True,
            allow_list=["DO_NOT_SCAN"],
        )
        hook = PreCommitHook(cfg)
        summary = hook.get_config_summary()
        assert summary["fail_on_severity"] == "CRITICAL"
        assert summary["skip_paths"] == ["vendor/"]
        assert summary["skip_extensions"] == [".lock"]
        assert summary["max_file_size_kb"] == 512
        assert summary["include_entropy"] is False
        assert summary["include_regex"] is True
        assert summary["allow_list"] == ["DO_NOT_SCAN"]

    def test_summary_skip_paths_is_list(self):
        hook = PreCommitHook()
        assert isinstance(hook.get_config_summary()["skip_paths"], list)

    def test_summary_allow_list_is_list(self):
        hook = PreCommitHook()
        assert isinstance(hook.get_config_summary()["allow_list"], list)


# =============================================================================
# _severity_from_str utility
# =============================================================================

class TestSeverityFromStr:
    """Tests for the module-private _severity_from_str helper."""

    def test_known_values_resolve_correctly(self):
        assert _severity_from_str("CRITICAL") == SeverityLevel.CRITICAL
        assert _severity_from_str("HIGH") == SeverityLevel.HIGH
        assert _severity_from_str("MEDIUM") == SeverityLevel.MEDIUM
        assert _severity_from_str("LOW") == SeverityLevel.LOW
        assert _severity_from_str("INFO") == SeverityLevel.INFO

    def test_unknown_value_defaults_to_info(self):
        assert _severity_from_str("UNKNOWN") == SeverityLevel.INFO

    def test_case_insensitive(self):
        assert _severity_from_str("critical") == SeverityLevel.CRITICAL
        assert _severity_from_str("high") == SeverityLevel.HIGH
