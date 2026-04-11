from __future__ import annotations

from pathlib import Path

import pytest

from scripts.github_action_entrypoint import (
    _parse_bool,
    build_command,
    discover_report_outputs,
    parse_action_args,
    resolve_output_directory,
    resolve_working_directory,
    validate_command,
)


def test_validate_command_rejects_unknown_subcommand() -> None:
    with pytest.raises(ValueError, match="Unsupported command"):
        validate_command("rm -rf")


def test_parse_action_args_rejects_root_level_cli_flags() -> None:
    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--fail-on high .")

    with pytest.raises(ValueError, match="dedicated action inputs"):
        parse_action_args("--output-dir ./tmp")


def test_build_command_places_root_options_before_subcommand(tmp_path: Path) -> None:
    command = build_command(
        subcommand="scan-path",
        raw_args=". --ignore '**/dist/**'",
        output_dir=tmp_path / "reports",
        fail_on="critical",
        entropy_enabled=False,
        entropy_threshold=5.25,
        policy_profile="strict",
    )

    assert command == [
        "secret-leak-sentinel",
        "--output-dir",
        str((tmp_path / "reports").resolve()),
        "--fail-on",
        "critical",
        "--entropy-threshold",
        "5.25",
        "--policy-profile",
        "strict",
        "--no-entropy",
        "scan-path",
        ".",
        "--ignore",
        "**/dist/**",
    ]


def test_resolve_paths_use_workspace_and_workdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    workdir = resolve_working_directory("repo")
    output_dir = resolve_output_directory("./artifacts", workdir)

    assert workdir == (workspace / "repo").resolve()
    assert output_dir == (workspace / "repo" / "artifacts").resolve()


def test_resolve_working_directory_rejects_parent_traversal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="working-directory must stay within GITHUB_WORKSPACE"):
        resolve_working_directory("../outside")


def test_resolve_working_directory_rejects_absolute_path_outside_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="working-directory must stay within GITHUB_WORKSPACE"):
        resolve_working_directory(str(outside))


def test_resolve_output_directory_rejects_parent_traversal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="output-dir must stay within GITHUB_WORKSPACE"):
        resolve_output_directory("../../outside", repo)


def test_resolve_output_directory_rejects_absolute_path_outside_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))

    with pytest.raises(ValueError, match="output-dir must stay within GITHUB_WORKSPACE"):
        resolve_output_directory(str(outside), repo)


def test_discover_report_outputs_returns_newest_report_per_extension(tmp_path: Path) -> None:
    markdown_old = tmp_path / "secret_scan_20260411_010101.md"
    markdown_new = tmp_path / "secret_scan_20260411_020202.md"
    csv_report = tmp_path / "secret_scan_20260411_020202.csv"

    markdown_old.write_text("old", encoding="utf-8")
    markdown_new.write_text("new", encoding="utf-8")
    csv_report.write_text("a,b\n", encoding="utf-8")

    outputs = discover_report_outputs(tmp_path)

    assert outputs["report_markdown"] == str(markdown_new.resolve())
    assert outputs["report_csv"] == str(csv_report.resolve())
    assert outputs["report_html"] == ""


def test_parse_bool_supports_common_action_input_values() -> None:
    assert _parse_bool("true") is True
    assert _parse_bool("YES") is True
    assert _parse_bool("0") is False

    with pytest.raises(ValueError, match="Boolean inputs"):
        _parse_bool("sometimes")
