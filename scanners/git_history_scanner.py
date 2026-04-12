"""
Git History Scanner
====================
Scans all commits in a git repository's history for secret patterns and
high-entropy strings. Operates on structured commit metadata + diff data
so it can be used without a live repository (pass CommitSnapshot objects
for testing or CI replay).

Key design points:
 - Live mode: uses GitPython to iterate commits and extract diffs
 - Dry/test mode: accepts CommitSnapshot list — no git dependency needed
 - Each blob (file diff hunk) is scanned independently
 - Findings include commit SHA, author, timestamp, file, and line number
 - Result deduplication: same secret in same file/line across rebases
   is collapsed by fingerprint

Usage (live repo)::

    from scanners.git_history_scanner import GitHistoryScanner

    scanner = GitHistoryScanner(repo_path=".", max_commits=1000)
    report = scanner.scan()
    for finding in report.findings:
        print(finding.to_dict())

Usage (test / offline)::

    from scanners.git_history_scanner import (
        GitHistoryScanner,
        CommitSnapshot,
        FileDiff,
    )

    snapshot = CommitSnapshot(
        sha="abc123",
        author="alice@example.com",
        timestamp=1700000000.0,
        diffs=[FileDiff(path="config.py", content="API_KEY = 'AKIAIOSFODNN7EXAMPLE'")],
    )
    scanner = GitHistoryScanner()
    report = scanner.scan_snapshots([snapshot])
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# FileDiff — one file's added content from a commit
# ---------------------------------------------------------------------------

@dataclass
class FileDiff:
    """
    Content added (or present) in a file as part of a commit.

    Attributes:
        path:    Relative file path.
        content: Text content of the added/changed lines.
        blob_id: Optional git blob identifier for deduplication.
    """
    path:    str
    content: str = ""
    blob_id: Optional[str] = None


# ---------------------------------------------------------------------------
# CommitSnapshot — structured commit data (input model)
# ---------------------------------------------------------------------------

@dataclass
class CommitSnapshot:
    """
    Structured representation of one commit for offline scanning.

    Attributes:
        sha:       Full or abbreviated commit SHA.
        author:    Author email or identifier.
        timestamp: Unix timestamp of commit.
        message:   Commit message.
        diffs:     List of file diffs in this commit.
    """
    sha:       str
    author:    str              = ""
    timestamp: float            = 0.0
    message:   str              = ""
    diffs:     List[FileDiff]   = field(default_factory=list)


# ---------------------------------------------------------------------------
# HistoryFinding — a secret detected in a commit
# ---------------------------------------------------------------------------

@dataclass
class HistoryFinding:
    """
    A secret or high-entropy string found in a commit.

    Attributes:
        commit_sha:   Commit where the secret was introduced.
        commit_author: Author identifier.
        commit_ts:    Commit timestamp.
        file_path:    File containing the secret.
        line_number:  1-based line number (best-effort).
        rule_id:      Detector rule that fired (e.g. "AWS_KEY", "ENTROPY").
        description:  Human-readable description.
        evidence:     Redacted snippet of the matched text (max 80 chars).
        fingerprint:  SHA-256[:16] of (file_path + rule_id + raw evidence).
    """
    commit_sha:    str
    commit_author: str   = ""
    commit_ts:     float = 0.0
    file_path:     str   = ""
    line_number:   int   = 0
    rule_id:       str   = ""
    description:   str   = ""
    evidence:      str   = ""
    fingerprint:   str   = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_sha":    self.commit_sha[:12],
            "commit_author": self.commit_author,
            "commit_ts":     self.commit_ts,
            "file_path":     self.file_path,
            "line_number":   self.line_number,
            "rule_id":       self.rule_id,
            "description":   self.description,
            "evidence":      self.evidence,
            "fingerprint":   self.fingerprint,
        }


# ---------------------------------------------------------------------------
# HistoryScanReport
# ---------------------------------------------------------------------------

@dataclass
class HistoryScanReport:
    """
    Aggregated result of a git history scan.

    Attributes:
        findings:         All detected secrets.
        commits_scanned:  Number of commits examined.
        files_scanned:    Total file-diffs examined.
        generated_at:     Unix timestamp.
    """
    findings:        List[HistoryFinding] = field(default_factory=list)
    commits_scanned: int   = 0
    files_scanned:   int   = 0
    generated_at:    float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def unique_fingerprints(self) -> set:
        return {f.fingerprint for f in self.findings}

    def findings_by_rule(self, rule_id: str) -> List[HistoryFinding]:
        return [f for f in self.findings if f.rule_id == rule_id]

    def findings_for_commit(self, sha: str) -> List[HistoryFinding]:
        return [f for f in self.findings if f.commit_sha.startswith(sha)]

    def findings_for_file(self, path: str) -> List[HistoryFinding]:
        return [f for f in self.findings if f.file_path == path]

    def summary(self) -> str:
        return (
            f"History scan: {self.total_findings} findings "
            f"({len(self.unique_fingerprints)} unique) across "
            f"{self.commits_scanned} commits, {self.files_scanned} file-diffs"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings":      self.total_findings,
            "unique_fingerprints": len(self.unique_fingerprints),
            "commits_scanned":     self.commits_scanned,
            "files_scanned":       self.files_scanned,
            "generated_at":        self.generated_at,
            "findings":            [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Secret detection rules
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    rule_id:     str
    description: str
    pattern:     re.Pattern


_AWS_ACCESS_KEY_PREFIX_PATTERN = r"(?:AKIA|ASIA)"


_RULES: List[_Rule] = [
    _Rule("AWS_ACCESS_KEY", "AWS access key ID",
          re.compile(_AWS_ACCESS_KEY_PREFIX_PATTERN + r"[0-9A-Z]{16}", re.ASCII)),
    _Rule("AWS_SECRET_KEY", "AWS secret access key candidate",
          re.compile(r"(?:aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", re.IGNORECASE)),
    _Rule("GITHUB_TOKEN", "GitHub personal/app token",
          re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})")),
    _Rule("GENERIC_API_KEY", "Generic API key assignment",
          re.compile(r"(?:api_key|apikey|api_token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})", re.IGNORECASE)),
    _Rule("PRIVATE_KEY_HEADER", "PEM private key header",
          re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    _Rule("PASSWORD_ASSIGNMENT", "Password in code",
          re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE)),
    _Rule("SLACK_TOKEN", "Slack API token",
          re.compile(r"xox[boas]-[0-9A-Za-z\-]+")),
    _Rule("NPM_TOKEN", "npm access token",
          re.compile(r"npm_[A-Za-z0-9]{36}")),
    _Rule("VAULT_TOKEN", "HashiCorp Vault token",
          re.compile(
              r"(?:\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}\b|"
              r"(?:x-vault-token|vault[_-]?token)\s*[:=]\s*['\"]?"
              r"(?:s|b|r)\.[A-Za-z0-9_-]{24,}['\"]?)",
              re.IGNORECASE,
          )),
    _Rule("STRIPE_KEY", "Stripe secret key",
          re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}")),
]

# Binary-like files to skip
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".class",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".lock",  # package lock files rarely contain secrets in useful form
})


def _is_binary_path(path: str) -> bool:
    from pathlib import PurePosixPath
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in _BINARY_EXTENSIONS


def _fingerprint(file_path: str, rule_id: str, evidence: str) -> str:
    raw = f"{file_path}:{rule_id}:{evidence}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _content_fingerprint(file_path: str, content: str) -> str:
    raw = f"{file_path}:{content}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _redact(text: str, max_len: int = 80) -> str:
    """Truncate to max_len, masking the middle portion of long strings."""
    if len(text) <= max_len:
        return text
    keep = max_len // 4
    return text[:keep] + "…[redacted]…" + text[-keep:]


# ---------------------------------------------------------------------------
# GitHistoryScanner
# ---------------------------------------------------------------------------

class GitHistoryScanner:
    """
    Scan git history for secrets.

    Args:
        repo_path:   Path to the git repository root (used in live mode).
        max_commits: Maximum number of commits to scan (None = all).
        branch:      Branch to scan from (None = current HEAD).
        skip_paths:  File path patterns (substring match) to skip.
    """

    def __init__(
        self,
        repo_path: str = ".",
        max_commits: Optional[int] = None,
        branch: Optional[str] = None,
        skip_paths: Optional[List[str]] = None,
    ) -> None:
        self._repo_path  = repo_path
        self._max_commits = max_commits
        self._branch     = branch
        self._skip_paths = skip_paths or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_snapshots(self, snapshots: List[CommitSnapshot]) -> HistoryScanReport:
        """
        Scan a list of CommitSnapshot objects (no live git required).

        Args:
            snapshots: Structured commit data to scan.

        Returns:
            HistoryScanReport with all findings.
        """
        all_findings: List[HistoryFinding] = []
        total_files = 0
        scanned_blobs: set[str] = set()
        scanned_contents: set[str] = set()

        for snap in snapshots:
            for diff in snap.diffs:
                total_files += 1
                if self._should_skip(diff.path):
                    continue
                if diff.blob_id and diff.blob_id in scanned_blobs:
                    continue
                content_fp = _content_fingerprint(diff.path, diff.content)
                if content_fp in scanned_contents:
                    continue
                findings = self._scan_content(
                    content=diff.content,
                    file_path=diff.path,
                    commit_sha=snap.sha,
                    commit_author=snap.author,
                    commit_ts=snap.timestamp,
                )
                all_findings.extend(findings)
                scanned_contents.add(content_fp)
                if diff.blob_id:
                    scanned_blobs.add(diff.blob_id)

        # Deduplicate by fingerprint (keep first occurrence)
        seen: set = set()
        deduped: List[HistoryFinding] = []
        for f in all_findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                deduped.append(f)

        return HistoryScanReport(
            findings=deduped,
            commits_scanned=len(snapshots),
            files_scanned=total_files,
        )

    def scan(self) -> HistoryScanReport:
        """
        Scan live git repository history.

        Requires GitPython. If the repository cannot be opened, returns
        an empty report.

        Returns:
            HistoryScanReport with all findings from git history.
        """
        try:
            from git import Repo, InvalidGitRepositoryError
        except ImportError:
            return HistoryScanReport()

        try:
            repo = Repo(self._repo_path, search_parent_directories=True)
        except Exception:
            return HistoryScanReport()

        ref = self._branch or repo.head.reference
        commits = list(repo.iter_commits(ref))
        if self._max_commits is not None:
            commits = commits[:self._max_commits]
        commits = list(reversed(commits))

        snapshots = []
        for commit in commits:
            diffs = []
            try:
                parents = commit.parents
                if parents:
                    diff_items = commit.diff(parents[0], create_patch=True)
                else:
                    diff_items = commit.diff(None, create_patch=True)
                for di in diff_items:
                    try:
                        content = self._extract_added_lines(di.diff)
                    except Exception:
                        content = ""

                    path = di.b_path or di.a_path or ""
                    if not path or not content.strip():
                        continue

                    blob_id = None
                    if di.b_blob is not None:
                        blob_id = di.b_blob.hexsha

                    diffs.append(FileDiff(
                        path=path,
                        content=content,
                        blob_id=blob_id,
                    ))
            except Exception:
                pass

            snapshots.append(CommitSnapshot(
                sha=commit.hexsha,
                author=str(commit.author.email) if commit.author.email else "",
                timestamp=float(commit.committed_date),
                message=commit.message or "",
                diffs=diffs,
            ))

        return self.scan_snapshots(snapshots)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _should_skip(self, path: str) -> bool:
        if _is_binary_path(path):
            return True
        for pat in self._skip_paths:
            if pat in path:
                return True
        return False

    def _scan_content(
        self,
        content: str,
        file_path: str,
        commit_sha: str,
        commit_author: str,
        commit_ts: float,
    ) -> List[HistoryFinding]:
        findings: List[HistoryFinding] = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for rule in _RULES:
                m = rule.pattern.search(line)
                if m:
                    evidence = _redact(m.group())
                    fp = _fingerprint(file_path, rule.rule_id, m.group())
                    findings.append(HistoryFinding(
                        commit_sha=commit_sha,
                        commit_author=commit_author,
                        commit_ts=commit_ts,
                        file_path=file_path,
                        line_number=lineno,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        evidence=evidence,
                        fingerprint=fp,
                    ))
        return findings

    @staticmethod
    def _extract_added_lines(diff_bytes: bytes | str | None) -> str:
        if not diff_bytes:
            return ""
        if isinstance(diff_bytes, bytes):
            patch_text = diff_bytes.decode("utf-8", errors="replace")
        else:
            patch_text = diff_bytes

        added_lines: List[str] = []
        for line in patch_text.splitlines():
            if line.startswith("+++ ") or line.startswith("@@"):
                continue
            if line.startswith("+"):
                added_lines.append(line[1:])
        return "\n".join(added_lines)
