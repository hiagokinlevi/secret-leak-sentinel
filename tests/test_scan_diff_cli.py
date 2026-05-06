from __future__ import annotations

from click.testing import CliRunner

from cli.main import cli


def test_scan_diff_detects_added_lines_ignores_removed_only_match() -> None:
    patch = """diff --git a/app.env b/app.env
index e69de29..4b825dc 100644
--- a/app.env
+++ b/app.env
@@ -1,2 +1,3 @@
-OLD_SECRET=sk_live_removed_only_1234567890abcdef
 CONTEXT_LINE=ok
+NEW_SECRET=sk_live_added_line_1234567890abcdef
+ANOTHER_LINE=safe
"""

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-diff"], input=patch)

    # Findings should fail the command
    assert result.exit_code == 1
    # Added Stripe-like token should be detected
    assert "NEW_SECRET" in result.output or "sk_live_added_line_1234567890abcdef" in result.output
    # Removed-only token must not be surfaced
    assert "sk_live_removed_only_1234567890abcdef" not in result.output
