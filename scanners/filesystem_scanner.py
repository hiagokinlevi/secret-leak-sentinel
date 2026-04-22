from __future__ import annotations

from pathlib import Path
from typing import Any

from detectors.composite import CompositeDetector


class FilesystemScanner:
    def __init__(self, detector: CompositeDetector) -> None:
        self.detector = detector

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        path = Path(file_path)
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings = self.detector.detect(content, file_path=str(path))
        return self._filter_inline_ignores(findings, content)

    def scan_path(self, root_path: str, exclude: list[str] | None = None) -> list[dict[str, Any]]:
        root = Path(root_path)
        if not root.exists():
            return []

        exclude = exclude or []
        findings: list[dict[str, Any]] = []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            path_str = str(path)
            if any(ex in path_str for ex in exclude):
                continue
            findings.extend(self.scan_file(path_str))

        return findings

    def _filter_inline_ignores(self, findings: list[dict[str, Any]], content: str) -> list[dict[str, Any]]:
        if not findings:
            return findings

        lines = content.splitlines()
        filtered: list[dict[str, Any]] = []
        for finding in findings:
            line_no = finding.get("line")
            if not isinstance(line_no, int) or line_no < 1 or line_no > len(lines):
                filtered.append(finding)
                continue

            line = lines[line_no - 1]
            if self._line_has_inline_ignore(line):
                continue
            filtered.append(finding)

        return filtered

    @staticmethod
    def _line_has_inline_ignore(line: str) -> bool:
        lower = line.lower()
        for token in ("#", "//"):
            idx = lower.find(token)
            if idx == -1:
                continue
            comment_text = lower[idx + len(token) :]
            if "sls:ignore" in comment_text:
                return True
        return False
