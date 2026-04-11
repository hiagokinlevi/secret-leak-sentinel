from __future__ import annotations

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

fake_git = types.ModuleType("git")
fake_git_exc = types.ModuleType("git.exc")


class _DummyRepoType:
    pass


class _DummyInvalidGitRepositoryError(Exception):
    pass


class _DummyGitCommandError(Exception):
    pass


fake_git.Repo = _DummyRepoType
fake_git.InvalidGitRepositoryError = _DummyInvalidGitRepositoryError
fake_git_exc.GitCommandError = _DummyGitCommandError

sys.modules.setdefault("git", fake_git)
sys.modules.setdefault("git.exc", fake_git_exc)

from scanners.git_scanner import scan_working_tree


_FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


class _FakeGit:
    def __init__(self, tracked: list[str] | None = None, untracked: list[str] | None = None):
        self._tracked = tracked or []
        self._untracked = untracked or []

    def ls_files(self, *args: str) -> str:
        if args == ("--others", "--exclude-standard"):
            return "\n".join(self._untracked)
        return "\n".join(self._tracked)


class _FakeRepo:
    def __init__(self, working_dir: Path, tracked: list[str] | None = None, untracked: list[str] | None = None):
        self.working_dir = str(working_dir)
        self.git = _FakeGit(tracked=tracked, untracked=untracked)


def test_scan_working_tree_skips_symlinked_file_pointing_outside_repo(tmp_path, monkeypatch):
    repo = _FakeRepo(tmp_path, untracked=["linked-secret.txt"])
    monkeypatch.setattr("scanners.git_scanner._get_repo", lambda repo_path: repo)

    outside_file = tmp_path.parent / "outside-secret.txt"
    outside_file.write_text(f'AWS_ACCESS_KEY_ID="{_FAKE_AWS}"\n', encoding="utf-8")

    linked_file = tmp_path / "linked-secret.txt"
    linked_file.symlink_to(outside_file)

    regex_findings, entropy_findings = scan_working_tree(
        repo_path=tmp_path,
        entropy_enabled=True,
    )

    assert regex_findings == []
    assert entropy_findings == []


def test_scan_working_tree_still_scans_regular_repo_files(tmp_path, monkeypatch):
    repo = _FakeRepo(tmp_path, untracked=["config.env"])
    monkeypatch.setattr("scanners.git_scanner._get_repo", lambda repo_path: repo)

    repo_file = tmp_path / "config.env"
    repo_file.write_text(f'AWS_ACCESS_KEY_ID="{_FAKE_AWS}"\n', encoding="utf-8")

    regex_findings, _ = scan_working_tree(
        repo_path=tmp_path,
        entropy_enabled=False,
    )

    assert len(regex_findings) == 1
    assert regex_findings[0].detector_name == "aws_access_key_id"
    assert regex_findings[0].file_path == "config.env"
