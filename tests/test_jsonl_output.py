import json

from secret_leak_sentinel_cli import _append_jsonl_record


def test_jsonl_output_writes_valid_line_delimited_json(tmp_path):
    out = tmp_path / "findings.jsonl"

    finding_1 = {
        "rule_id": "aws-access-key",
        "severity": "high",
        "file_path": "src/app.py",
        "line": 12,
        "confidence": 0.97,
        "fingerprint": "fp-1",
    }
    finding_2 = {
        "rule_id": "slack-token",
        "severity": "critical",
        "file_path": "ci/workflow.yml",
        "line": 8,
        "confidence": 0.99,
        "fingerprint": "fp-2",
    }

    _append_jsonl_record(str(out), finding_1)
    _append_jsonl_record(str(out), finding_2)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["rule_id"] == "aws-access-key"
    assert parsed[0]["severity"] == "high"
    assert parsed[0]["file_path"] == "src/app.py"
    assert parsed[0]["line"] == 12
    assert parsed[0]["confidence"] == 0.97
    assert parsed[0]["fingerprint"] == "fp-1"

    assert parsed[1]["rule_id"] == "slack-token"
    assert parsed[1]["severity"] == "critical"
    assert parsed[1]["file_path"] == "ci/workflow.yml"
    assert parsed[1]["line"] == 8
    assert parsed[1]["confidence"] == 0.99
    assert parsed[1]["fingerprint"] == "fp-2"
