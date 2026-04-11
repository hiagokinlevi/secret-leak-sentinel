from __future__ import annotations

from pathlib import Path

import yaml


ACTION_PATH = Path(__file__).resolve().parent.parent / "action.yml"


def test_action_metadata_uses_composite_runtime() -> None:
    data = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))

    assert data["name"] == "Secret Leak Sentinel"
    assert data["runs"]["using"] == "composite"


def test_action_metadata_invokes_validated_entrypoint() -> None:
    data = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    steps = data["runs"]["steps"]

    setup_step = next(step for step in steps if step["name"] == "Set up Python")
    install_step = next(step for step in steps if step["name"] == "Install secret-leak-sentinel")
    run_step = next(step for step in steps if step["id"] == "run")

    assert setup_step["uses"] == "actions/setup-python@v5"
    assert 'python -m pip install "${{ github.action_path }}"' in install_step["run"]
    assert "scripts/github_action_entrypoint.py" in run_step["run"]
    assert "--command" in run_step["run"]
