"""
Tests for scanners/git_history_scanner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners.git_history_scanner import (
    CommitSnapshot,
    FileDiff,
    GitHistoryScanner,
    HistoryFinding,
    HistoryScanReport,
    _fingerprint,
    _is_binary_path,
    _redact,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _scanner(**kwargs) -> GitHistoryScanner:
    return GitHistoryScanner(**kwargs)


def _commit(sha="abc123", author="alice@example.com", ts=1700000000.0,
            diffs=None) -> CommitSnapshot:
    return CommitSnapshot(sha=sha, author=author, timestamp=ts,
                          diffs=diffs or [])


def _diff(path="main.py", content="") -> FileDiff:
    return FileDiff(path=path, content=content)


def _rule_ids(report: HistoryScanReport) -> set[str]:
    return {f.rule_id for f in report.findings}


# ===========================================================================
# Helper functions
# ===========================================================================

class TestHelpers:
    def test_is_binary_path_png(self):
        assert _is_binary_path("image.png")

    def test_is_binary_path_pyc(self):
        assert _is_binary_path("cache/__pycache__/foo.pyc")

    def test_is_binary_path_lock(self):
        assert _is_binary_path("package-lock.json") is False  # .json not binary
        assert _is_binary_path("yarn.lock")  # .lock is binary

    def test_is_binary_path_py_not_binary(self):
        assert not _is_binary_path("config.py")

    def test_is_binary_path_txt_not_binary(self):
        assert not _is_binary_path("secrets.txt")

    def test_fingerprint_deterministic(self):
        f1 = _fingerprint("path.py", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        f2 = _fingerprint("path.py", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        assert f1 == f2

    def test_fingerprint_different_for_different_input(self):
        f1 = _fingerprint("a.py", "RULE", "val1")
        f2 = _fingerprint("a.py", "RULE", "val2")
        assert f1 != f2

    def test_fingerprint_length_16(self):
        assert len(_fingerprint("f", "r", "v")) == 16

    def test_redact_short_string_unchanged(self):
        s = "short"
        assert _redact(s) == s

    def test_redact_long_string_contains_redacted(self):
        s = "x" * 200
        r = _redact(s)
        assert "redacted" in r
        assert len(r) < 200


# ===========================================================================
# HistoryFinding
# ===========================================================================

class TestHistoryFinding:
    def _f(self) -> HistoryFinding:
        return HistoryFinding(
            commit_sha="abc123def456",
            commit_author="alice@example.com",
            commit_ts=1700000000.0,
            file_path="config.py",
            line_number=42,
            rule_id="AWS_ACCESS_KEY",
            description="AWS access key ID",
            evidence="AKIA…[redacted]",
            fingerprint="abcdef1234567890",
        )

    def test_to_dict_has_required_keys(self):
        d = self._f().to_dict()
        for k in ("commit_sha", "commit_author", "commit_ts", "file_path",
                  "line_number", "rule_id", "description", "evidence", "fingerprint"):
            assert k in d

    def test_commit_sha_truncated_to_12(self):
        d = self._f().to_dict()
        assert len(d["commit_sha"]) == 12

    def test_line_number_present(self):
        assert self._f().to_dict()["line_number"] == 42


# ===========================================================================
# HistoryScanReport
# ===========================================================================

class TestHistoryScanReport:
    def _report(self) -> HistoryScanReport:
        f1 = HistoryFinding("sha1", rule_id="AWS_ACCESS_KEY", fingerprint="fp1")
        f2 = HistoryFinding("sha2", rule_id="GITHUB_TOKEN", fingerprint="fp2")
        return HistoryScanReport(findings=[f1, f2], commits_scanned=5, files_scanned=20)

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_unique_fingerprints(self):
        r = self._report()
        assert len(r.unique_fingerprints) == 2

    def test_findings_by_rule(self):
        r = self._report()
        assert len(r.findings_by_rule("AWS_ACCESS_KEY")) == 1

    def test_findings_for_commit(self):
        r = self._report()
        assert len(r.findings_for_commit("sha1")) == 1

    def test_findings_for_file(self):
        r = HistoryScanReport(findings=[
            HistoryFinding("sha", file_path="a.py", rule_id="R", fingerprint="fp"),
        ])
        assert len(r.findings_for_file("a.py")) == 1

    def test_summary_contains_finding_count(self):
        assert "2" in self._report().summary()

    def test_summary_contains_commit_count(self):
        assert "5" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for k in ("total_findings", "unique_fingerprints", "commits_scanned",
                  "files_scanned", "generated_at", "findings"):
            assert k in d

    def test_empty_report(self):
        r = HistoryScanReport()
        assert r.total_findings == 0
        assert len(r.unique_fingerprints) == 0


# ===========================================================================
# AWS_ACCESS_KEY detection
# ===========================================================================

class TestAWSAccessKey:
    def test_detects_aws_access_key(self):
        snap = _commit(diffs=[_diff(content="key = 'AKIAIOSFODNN7EXAMPLE1234'")])
        r = _scanner().scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" in _rule_ids(r)

    def test_not_fired_for_short_string(self):
        snap = _commit(diffs=[_diff(content="key = 'AKIA'")])
        r = _scanner().scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" not in _rule_ids(r)

    def test_finding_has_correct_commit_sha(self):
        snap = _commit(sha="deadbeef", diffs=[_diff(content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = _scanner().scan_snapshots([snap])
        f = next(f for f in r.findings if f.rule_id == "AWS_ACCESS_KEY")
        assert f.commit_sha.startswith("deadbeef")

    def test_finding_line_number_set(self):
        content = "import os\nkey = 'AKIAIOSFODNN7EXAMPLEKEY'\n"
        snap = _commit(diffs=[_diff(content=content)])
        r = _scanner().scan_snapshots([snap])
        f = next(f for f in r.findings if f.rule_id == "AWS_ACCESS_KEY")
        assert f.line_number == 2


# ===========================================================================
# GITHUB_TOKEN detection
# ===========================================================================

class TestGitHubToken:
    def test_detects_ghp_token(self):
        content = "token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'"
        snap = _commit(diffs=[_diff(content=content)])
        r = _scanner().scan_snapshots([snap])
        assert "GITHUB_TOKEN" in _rule_ids(r)

    def test_detects_gho_token(self):
        content = "oauth_token = gho_abcdefghijklmnopqrstuvwxyz1234567890abcdef"
        snap = _commit(diffs=[_diff(content=content)])
        r = _scanner().scan_snapshots([snap])
        assert "GITHUB_TOKEN" in _rule_ids(r)

    def test_not_fired_for_random_string(self):
        snap = _commit(diffs=[_diff(content="no token here at all")])
        r = _scanner().scan_snapshots([snap])
        assert "GITHUB_TOKEN" not in _rule_ids(r)


# ===========================================================================
# PRIVATE_KEY_HEADER detection
# ===========================================================================

class TestPrivateKeyHeader:
    def test_detects_rsa_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----"
        snap = _commit(diffs=[_diff(path="id_rsa", content=content)])
        r = _scanner().scan_snapshots([snap])
        assert "PRIVATE_KEY_HEADER" in _rule_ids(r)

    def test_detects_generic_private_key(self):
        content = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----"
        snap = _commit(diffs=[_diff(content=content)])
        r = _scanner().scan_snapshots([snap])
        assert "PRIVATE_KEY_HEADER" in _rule_ids(r)


# ===========================================================================
# PASSWORD_ASSIGNMENT detection
# ===========================================================================

class TestPasswordAssignment:
    def test_detects_password_equals(self):
        snap = _commit(diffs=[_diff(content='DB_PASSWORD = "supersecret123"')])
        r = _scanner().scan_snapshots([snap])
        assert "PASSWORD_ASSIGNMENT" in _rule_ids(r)

    def test_not_fired_for_short_value(self):
        snap = _commit(diffs=[_diff(content='password = "abc"')])
        r = _scanner().scan_snapshots([snap])
        assert "PASSWORD_ASSIGNMENT" not in _rule_ids(r)


# ===========================================================================
# Binary file skipping
# ===========================================================================

class TestBinarySkipping:
    def test_skips_png_file(self):
        snap = _commit(diffs=[_diff(path="logo.png", content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = _scanner().scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" not in _rule_ids(r)

    def test_skips_pyc_file(self):
        snap = _commit(diffs=[_diff(path="__pycache__/foo.pyc", content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = _scanner().scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" not in _rule_ids(r)

    def test_does_not_skip_py_file(self):
        snap = _commit(diffs=[_diff(path="config.py", content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = _scanner().scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" in _rule_ids(r)


# ===========================================================================
# skip_paths
# ===========================================================================

class TestSkipPaths:
    def test_skips_matching_path(self):
        scanner = GitHistoryScanner(skip_paths=["vendor/"])
        snap = _commit(diffs=[_diff(path="vendor/aws.py", content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = scanner.scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" not in _rule_ids(r)

    def test_does_not_skip_non_matching_path(self):
        scanner = GitHistoryScanner(skip_paths=["vendor/"])
        snap = _commit(diffs=[_diff(path="src/config.py", content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = scanner.scan_snapshots([snap])
        assert "AWS_ACCESS_KEY" in _rule_ids(r)


# ===========================================================================
# Deduplication
# ===========================================================================

class TestDeduplication:
    def test_same_secret_in_two_commits_deduped(self):
        content = "AKIAIOSFODNN7EXAMPLEKEY"
        path = "config.py"
        snap1 = _commit(sha="sha1", diffs=[_diff(path=path, content=content)])
        snap2 = _commit(sha="sha2", diffs=[_diff(path=path, content=content)])
        r = _scanner().scan_snapshots([snap1, snap2])
        # Same file + rule + evidence → same fingerprint → deduplicated
        aws_findings = r.findings_by_rule("AWS_ACCESS_KEY")
        assert len(aws_findings) == 1

    def test_different_files_not_deduped(self):
        content = "AKIAIOSFODNN7EXAMPLEKEY"
        snap = _commit(sha="sha1", diffs=[
            _diff(path="config.py", content=content),
            _diff(path="settings.py", content=content),
        ])
        r = _scanner().scan_snapshots([snap])
        aws_findings = r.findings_by_rule("AWS_ACCESS_KEY")
        assert len(aws_findings) == 2


# ===========================================================================
# Report metadata
# ===========================================================================

class TestReportMetadata:
    def test_commits_scanned_count(self):
        snaps = [_commit(sha=f"sha{i}") for i in range(5)]
        r = _scanner().scan_snapshots(snaps)
        assert r.commits_scanned == 5

    def test_files_scanned_count(self):
        snap = _commit(diffs=[
            _diff(path="a.py", content=""),
            _diff(path="b.py", content=""),
        ])
        r = _scanner().scan_snapshots([snap])
        assert r.files_scanned == 2

    def test_author_in_finding(self):
        snap = _commit(author="bob@example.com",
                       diffs=[_diff(content="AKIAIOSFODNN7EXAMPLEKEY")])
        r = _scanner().scan_snapshots([snap])
        f = next(f for f in r.findings if f.rule_id == "AWS_ACCESS_KEY")
        assert f.commit_author == "bob@example.com"

    def test_empty_snapshots_empty_report(self):
        r = _scanner().scan_snapshots([])
        assert r.total_findings == 0
        assert r.commits_scanned == 0
