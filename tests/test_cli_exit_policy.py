import pytest


def _sev_rank(sev: str) -> int:
    order = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return order.get((sev or "").strip().lower(), -1)


def should_fail(findings, fail_on_severity=None, max_allowed_findings=None):
    if max_allowed_findings is not None and len(findings) > max_allowed_findings:
        return True

    if fail_on_severity:
        threshold = _sev_rank(fail_on_severity)
        for f in findings:
            sev = f.get("severity", "")
            if _sev_rank(sev) >= threshold:
                return True

    return False


@pytest.mark.parametrize(
    "findings,fail_on,max_allowed,expected",
    [
        ([], None, None, False),
        ([{"severity": "low"}], None, 1, False),
        ([{"severity": "low"}, {"severity": "medium"}], None, 1, True),
        ([{"severity": "medium"}], "high", None, False),
        ([{"severity": "high"}], "high", None, True),
        ([{"severity": "critical"}], "high", None, True),
        ([{"severity": "low"}, {"severity": "medium"}], "critical", 5, False),
        ([{"severity": "low"}, {"severity": "critical"}], "critical", 5, True),
        ([{"severity": "high"}, {"severity": "high"}], "critical", 1, True),
    ],
)
def test_exit_policy_combinations(findings, fail_on, max_allowed, expected):
    assert should_fail(findings, fail_on, max_allowed) is expected
