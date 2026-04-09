"""
Git Scanner
============
Scans git working tree and staged files for secrets using gitpython.

Two scan modes:
  - staged:  Scans only files in the git index (staged for the next commit).
             This is the mode used by the pre-commit hook.
  - working: Scans all tracked and untracked (non-ignored) files in the working tree.

Why scan staged files separately?
----------------------------------
The pre-commit hook must intercept secrets before they are committed.
Scanning staged content (via git diff --cached) is faster and more targeted
than a full working-tree scan, and it catches secrets that were staged but
not yet written to disk in their final form.

Usage
-----
    from scanners.git_scanner import scan_staged_files, scan_working_tree

    # In a pre-commit hook context:
    findings, entropy_findings = scan_staged_files(repo_path=".")

    # Full working-tree scan:
    findings, entropy_findings = scan_working_tree(repo_path="./my-project", depth=None)
"""
from pathlib import Path
from typing import Optional

import structlog
from git import InvalidGitRepositoryError, Repo
from git.exc import GitCommandError

from detectors.regex_detector import Finding, scan_content
from detectors.entropy_detector import EntropyFinding, scan_content_for_entropy

logger = structlog.get_logger(__name__)


def _get_repo(repo_path: str | Path) -> Repo:
    """
    Open a git repository at the given path.

    Raises:
        InvalidGitRepositoryError: If the path is not a git repository.
    """
    try:
        return Repo(str(repo_path), search_parent_directories=True)
    except InvalidGitRepositoryError as exc:
        logger.error("Not a git repository", path=str(repo_path))
        raise


def scan_staged_files(
    repo_path: str | Path = ".",
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
) -> tuple[list[Finding], list[EntropyFinding]]:
    """
    Scan files staged in the git index for secrets.

    Uses `git diff --cached` to retrieve staged file content without writing
    to disk, which is important for the pre-commit hook use case.

    Args:
        repo_path: Path to the git repository (or any subdirectory).
        entropy_enabled: Whether to run the entropy detector.
        entropy_threshold: Shannon entropy threshold.

    Returns:
        Tuple of (regex_findings, entropy_findings).
    """
    repo = _get_repo(repo_path)
    regex_findings: list[Finding] = []
    entropy_findings: list[EntropyFinding] = []

    try:
        # Get the diff of staged changes vs HEAD (or empty tree for initial commits)
        if repo.head.is_valid():
            # Normal case: compare staged index against HEAD commit
            staged_diff = repo.index.diff("HEAD", create_patch=True)
        else:
            # Initial commit: compare staged index against empty tree
            staged_diff = repo.index.diff(None, create_patch=True)
    except GitCommandError as exc:
        logger.error("Could not retrieve staged diff", error=str(exc))
        return [], []

    files_scanned = 0

    for diff_item in staged_diff:
        file_path = diff_item.b_path or diff_item.a_path
        if file_path is None:
            continue

        # Get the staged content from the index blob
        try:
            if diff_item.b_blob:
                content = diff_item.b_blob.data_stream.read().decode("utf-8", errors="replace")
            else:
                continue  # Deleted file; nothing to scan
        except Exception as exc:
            logger.warning("Could not read staged blob", path=file_path, error=str(exc))
            continue

        # Scan the staged content
        file_findings = scan_content(content, file_path)
        regex_findings.extend(file_findings)

        if entropy_enabled:
            file_entropy = scan_content_for_entropy(content, file_path, threshold=entropy_threshold)
            entropy_findings.extend(file_entropy)

        files_scanned += 1

    logger.info(
        "Staged files scan complete",
        files_scanned=files_scanned,
        regex_findings=len(regex_findings),
        entropy_findings=len(entropy_findings),
    )

    return regex_findings, entropy_findings


def scan_working_tree(
    repo_path: str | Path = ".",
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
    depth: Optional[int] = None,
) -> tuple[list[Finding], list[EntropyFinding]]:
    """
    Scan all non-ignored files in the git working tree for secrets.

    Uses `git ls-files` to enumerate tracked and untracked files, respecting
    .gitignore rules.

    Args:
        repo_path: Path to the git repository.
        entropy_enabled: Whether to run the entropy detector.
        entropy_threshold: Shannon entropy threshold.
        depth: Maximum directory depth to scan. None for unlimited.

    Returns:
        Tuple of (regex_findings, entropy_findings).
    """
    repo = _get_repo(repo_path)
    root = Path(repo.working_dir)
    regex_findings: list[Finding] = []
    entropy_findings: list[EntropyFinding] = []
    files_scanned = 0

    # ls-files with --others --exclude-standard includes untracked files that are not gitignored
    tracked_files = repo.git.ls_files().splitlines()
    untracked_files = repo.git.ls_files("--others", "--exclude-standard").splitlines()
    all_files = tracked_files + untracked_files

    for rel_path in all_files:
        file_path = root / rel_path

        # Apply depth filter if specified
        if depth is not None:
            parts = Path(rel_path).parts
            if len(parts) > depth + 1:
                continue

        if not file_path.exists() or not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Could not read file", path=str(file_path), error=str(exc))
            continue

        file_findings = scan_content(content, rel_path)
        regex_findings.extend(file_findings)

        if entropy_enabled:
            file_entropy = scan_content_for_entropy(content, rel_path, threshold=entropy_threshold)
            entropy_findings.extend(file_entropy)

        files_scanned += 1

    logger.info(
        "Working tree scan complete",
        files_scanned=files_scanned,
        regex_findings=len(regex_findings),
        entropy_findings=len(entropy_findings),
    )

    return regex_findings, entropy_findings
