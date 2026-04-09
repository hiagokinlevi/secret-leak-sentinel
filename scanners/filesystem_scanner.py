"""
Filesystem Scanner
===================
Walks a directory tree and scans files for secrets using the regex and
entropy detectors.

Features:
  - Configurable path exclusions (glob patterns)
  - Binary file detection and skipping
  - Per-file error handling to avoid aborting large scans
  - Suppression file support
  - Progress reporting via structlog

Usage
-----
    from scanners.filesystem_scanner import scan_directory
    from detectors.regex_detector import Finding

    findings = scan_directory(
        root="./my-project",
        entropy_enabled=True,
        entropy_threshold=4.5,
        ignored_patterns=[".git", "node_modules", "*.min.js"],
    )
"""
import fnmatch
import os
from pathlib import Path
from typing import Optional

import structlog

from detectors.regex_detector import Finding, scan_content
from detectors.entropy_detector import EntropyFinding, scan_content_for_entropy

logger = structlog.get_logger(__name__)

# File extensions that are almost certainly binary and should be skipped.
# Scanning binary files generates noise and slows the scan.
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".pyc", ".class", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".lock",  # Lockfiles (package-lock.json, poetry.lock) are rarely secret-bearing
}

# Maximum file size to scan in bytes (10 MB). Larger files are skipped to prevent
# memory exhaustion when scanning repos with large assets.
_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024


def _is_binary_file(path: Path) -> bool:
    """
    Heuristically detect binary files.

    First checks the extension, then reads the first 8 KB and looks for null bytes.
    """
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk  # Null bytes are a reliable binary indicator
    except OSError:
        return True  # Cannot read; skip it


def _matches_any_pattern(path: Path, root: Path, patterns: list[str]) -> bool:
    """
    Return True if the path matches any of the provided glob-style ignore patterns.

    Matches are checked against:
      - The full relative path from root
      - Just the filename
      - Each path component (for directory-level ignores like "node_modules")
    """
    rel_path = str(path.relative_to(root))
    filename = path.name

    for pattern in patterns:
        # Strip leading/trailing whitespace from patterns (common in comma-separated env vars)
        pattern = pattern.strip()
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if fnmatch.fnmatch(filename, pattern):
            return True
        # Check each path component to catch directory-level patterns
        for part in path.relative_to(root).parts:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


def scan_directory(
    root: str | Path,
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
    ignored_patterns: Optional[list[str]] = None,
    suppression_file: Optional[str | Path] = None,
) -> tuple[list[Finding], list[EntropyFinding]]:
    """
    Walk a directory tree and scan all non-binary files for secrets.

    Args:
        root: Root directory to scan.
        entropy_enabled: Whether to run the entropy detector in addition to regex.
        entropy_threshold: Shannon entropy threshold for the entropy detector.
        ignored_patterns: List of glob patterns for paths to exclude.
        suppression_file: Path to a YAML suppression file (optional).

    Returns:
        Tuple of (regex_findings, entropy_findings) lists.
    """
    root_path = Path(root).resolve()
    patterns = ignored_patterns or []

    # Load suppressions if a file is provided
    suppressed_files: set[str] = set()
    if suppression_file:
        suppressed_files = _load_suppressed_files(suppression_file)

    regex_findings: list[Finding] = []
    entropy_findings: list[EntropyFinding] = []

    files_scanned = 0
    files_skipped = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        dir_path = Path(dirpath)

        # Prune excluded directories in-place to prevent os.walk from descending into them
        dirnames[:] = [
            d for d in dirnames
            if not _matches_any_pattern(dir_path / d, root_path, patterns)
        ]

        for filename in filenames:
            file_path = dir_path / filename

            # Skip files matching ignore patterns
            if _matches_any_pattern(file_path, root_path, patterns):
                files_skipped += 1
                continue

            # Skip suppressed files
            rel_str = str(file_path.relative_to(root_path))
            if rel_str in suppressed_files:
                logger.debug("Suppressed file skipped", path=rel_str)
                files_skipped += 1
                continue

            # Skip binary files and oversized files
            if _is_binary_file(file_path):
                files_skipped += 1
                continue

            if file_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                logger.warning("File too large to scan; skipping", path=str(file_path))
                files_skipped += 1
                continue

            # Read and scan the file
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Could not read file", path=str(file_path), error=str(exc))
                files_skipped += 1
                continue

            str_path = str(file_path)

            # Run regex detector
            file_findings = scan_content(content, str_path)
            regex_findings.extend(file_findings)

            # Run entropy detector if enabled
            if entropy_enabled:
                file_entropy = scan_content_for_entropy(
                    content, str_path, threshold=entropy_threshold
                )
                entropy_findings.extend(file_entropy)

            files_scanned += 1

    logger.info(
        "Filesystem scan complete",
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        regex_findings=len(regex_findings),
        entropy_findings=len(entropy_findings),
    )

    return regex_findings, entropy_findings


def _load_suppressed_files(suppression_file: str | Path) -> set[str]:
    """
    Load the list of suppressed file paths from a YAML suppression file.

    Args:
        suppression_file: Path to .k1n-suppressions.yaml or equivalent.

    Returns:
        Set of relative file path strings to suppress.
    """
    import yaml

    path = Path(suppression_file)
    if not path.exists():
        logger.debug("Suppression file not found; no suppressions applied", path=str(path))
        return set()

    with path.open() as f:
        data = yaml.safe_load(f) or {}

    suppressed: set[str] = set()
    for entry in data.get("suppressions", []):
        if "file" in entry:
            suppressed.add(entry["file"])

    return suppressed
