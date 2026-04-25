from secret_leak_sentinel_cli import _apply_runtime_exclusions_to_result


def test_exclude_rule_id_filters_only_requested_rules():
    result = {
        "findings": [
            {"rule_id": "aws-access-key", "path": "a.txt"},
            {"rule_id": "github-token", "path": "b.txt"},
            {"rule_id": "entropy-high", "path": "c.txt"},
        ],
        "total_findings": 3,
    }

    filtered = _apply_runtime_exclusions_to_result(result, ["github-token"])

    assert [f["rule_id"] for f in filtered["findings"]] == ["aws-access-key", "entropy-high"]
    assert filtered["total_findings"] == 2
