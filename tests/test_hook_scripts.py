from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PRE_COMMIT_HOOK = ROOT / "hooks" / "pre-commit" / "secret-leak-check"
PRE_PUSH_HOOK = ROOT / "hooks" / "pre-push" / "secret-leak-check-push"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    path.chmod(0o755)


def test_pre_commit_hook_reads_dotenv_and_orders_group_options(tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    log_path = tmp_path / "pre-commit-args.log"

    _write_executable(
        stub_dir / "secret-leak-sentinel",
        f"""
        #!/usr/bin/env bash
        printf '%s\n' "$@" > "{log_path}"
        exit 0
        """,
    )

    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "SECRET_LEAK_FAIL_ON_SEVERITY=critical",
                "SECRET_LEAK_ENTROPY_ENABLED=false",
                "SECRET_LEAK_POLICY_PROFILE=strict",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = subprocess.run(
        ["bash", str(PRE_COMMIT_HOOK)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    args = log_path.read_text(encoding="utf-8").splitlines()
    assert args == [
        "--fail-on",
        "critical",
        "--policy-profile",
        "strict",
        "--no-entropy",
        "scan-staged",
    ]


def test_pre_push_hook_uses_patch_mode_scan_file(tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    log_path = tmp_path / "pre-push-args.log"

    _write_executable(
        stub_dir / "git",
        """
        #!/usr/bin/env bash
        if [ "$1" = "log" ]; then
            echo "abcdef1234567890"
            exit 0
        fi

        if [ "$1" = "show" ]; then
            cat <<'EOF'
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -0,0 +1 @@
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
EOF
            exit 0
        fi

        exit 1
        """,
    )

    _write_executable(
        stub_dir / "secret-leak-sentinel",
        f"""
        #!/usr/bin/env bash
        printf '%s\n' "$@" > "{log_path}"
        exit 0
        """,
    )

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = subprocess.run(
        ["bash", str(PRE_PUSH_HOOK)],
        cwd=tmp_path,
        env=env,
        input="refs/heads/main abcdef1234567890 refs/remotes/origin/main fedcba0987654321\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    args = log_path.read_text(encoding="utf-8").splitlines()
    assert args[:3] == ["--fail-on", "high", "--entropy"]
    assert "scan-file" in args
    assert "--patch-mode" in args
