"""
Tests for alerting/webhook_alerts.py

Validates:
  - WebhookConfig.threshold_criticality() parses string and enum inputs
  - WebhookConfig.meets_threshold() filters by severity correctly
  - build_slack_payload() structure: has 'blocks', caps at 10 findings
  - build_slack_payload() never includes unmasked secrets
  - build_pagerduty_payload() structure: routing_key, event_action, payload fields
  - build_pagerduty_payload() severity mapping (critical → 'critical', high → 'error')
  - build_pagerduty_payload() finding summary capped at 20
  - send_alert() dry_run=True returns success, correct findings_alerted count
  - send_alert() with no alertable findings returns success, findings_alerted=0
  - send_alert() threshold filtering: LOW config alerts more than HIGH config
  - AlertResult fields populated correctly
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from alerting.webhook_alerts import (
    AlertChannel,
    AlertResult,
    WebhookConfig,
    build_pagerduty_payload,
    build_slack_payload,
    send_alert,
)
from classifiers.criticality_classifier import ClassifiedFinding
from detectors.regex_detector import Criticality, Finding, SecretType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    criticality: Criticality = Criticality.HIGH,
    file_path: str = "src/config.py",
    line_number: int = 42,
    detector_name: str = "aws_access_key",
    secret_type: SecretType = SecretType.AWS_ACCESS_KEY,
) -> ClassifiedFinding:
    f = Finding(
        detector_name=detector_name,
        secret_type=secret_type,
        criticality=criticality,
        file_path=file_path,
        line_number=line_number,
        masked_excerpt="aws_access_key = AKIA***EXAMPLE (masked)",
        confidence=0.92,
    )
    return ClassifiedFinding(
        original_finding=f,
        final_criticality=criticality,
        confidence=0.92,
        rationale="Regex pattern matched; high-risk file.",
        entropy_corroboration=False,
        context_penalty=False,
        context_escalation=False,
    )


def _slack_config() -> WebhookConfig:
    return WebhookConfig(
        url="https://hooks.slack.com/services/FAKE/FAKE/FAKE",
        channel=AlertChannel.SLACK,
        severity_threshold="high",
        source_label="test-suite",
    )


def _pd_config() -> WebhookConfig:
    return WebhookConfig(
        url="https://events.pagerduty.com/v2/enqueue",
        channel=AlertChannel.PAGERDUTY,
        severity_threshold="high",
        routing_key="FAKE_ROUTING_KEY_32chars_aaaa_1234",
        source_label="test-suite",
    )


# ---------------------------------------------------------------------------
# WebhookConfig
# ---------------------------------------------------------------------------

class TestWebhookConfig:

    def test_threshold_from_string_high(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="high")
        assert cfg.threshold_criticality() == Criticality.HIGH

    def test_threshold_from_string_critical(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="critical")
        assert cfg.threshold_criticality() == Criticality.CRITICAL

    def test_threshold_from_enum(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold=Criticality.MEDIUM)
        assert cfg.threshold_criticality() == Criticality.MEDIUM

    def test_threshold_invalid_string_defaults_to_high(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="nonsense")
        assert cfg.threshold_criticality() == Criticality.HIGH

    def test_meets_threshold_exact_match(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="high")
        finding = _make_finding(Criticality.HIGH)
        assert cfg.meets_threshold(finding) is True

    def test_meets_threshold_above(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="high")
        finding = _make_finding(Criticality.CRITICAL)
        assert cfg.meets_threshold(finding) is True

    def test_does_not_meet_threshold_below(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="high")
        finding = _make_finding(Criticality.MEDIUM)
        assert cfg.meets_threshold(finding) is False

    def test_low_threshold_matches_all(self):
        cfg = WebhookConfig(url="x", channel=AlertChannel.SLACK, severity_threshold="low")
        for crit in Criticality:
            assert cfg.meets_threshold(_make_finding(crit)) is True


# ---------------------------------------------------------------------------
# build_slack_payload
# ---------------------------------------------------------------------------

class TestBuildSlackPayload:
    cfg = _slack_config()

    def test_returns_dict_with_blocks(self):
        payload = build_slack_payload([_make_finding()], "my-repo", self.cfg)
        assert "blocks" in payload

    def test_blocks_is_list(self):
        payload = build_slack_payload([_make_finding()], "my-repo", self.cfg)
        assert isinstance(payload["blocks"], list)

    def test_header_block_mentions_scan_path(self):
        payload = build_slack_payload([_make_finding()], "my-special-repo", self.cfg)
        full_text = str(payload)
        assert "my-special-repo" in full_text

    def test_finding_excerpt_appears(self):
        payload = build_slack_payload([_make_finding()], ".", self.cfg)
        full_text = str(payload)
        assert "masked" in full_text     # from masked_excerpt string

    def test_no_unmasked_akid_in_payload(self):
        # The masked_excerpt has "AKIA***EXAMPLE" — not a valid AKID
        payload = build_slack_payload([_make_finding()], ".", self.cfg)
        import re
        assert not re.search(r"AKIA[A-Z0-9]{16}", str(payload))

    def test_capped_at_10_finding_blocks(self):
        findings = [_make_finding() for _ in range(15)]
        payload = build_slack_payload(findings, ".", self.cfg)
        # 10 finding blocks + header + divider(s) + footer context
        finding_blocks = [b for b in payload["blocks"] if b.get("type") == "section"
                          and "line" in str(b).lower()]
        assert len(finding_blocks) <= 10

    def test_overflow_message_added_when_more_than_10(self):
        findings = [_make_finding() for _ in range(15)]
        payload = build_slack_payload(findings, ".", self.cfg)
        full_text = str(payload)
        assert "more" in full_text

    def test_empty_findings_list_still_returns_blocks(self):
        payload = build_slack_payload([], ".", self.cfg)
        assert "blocks" in payload


# ---------------------------------------------------------------------------
# build_pagerduty_payload
# ---------------------------------------------------------------------------

class TestBuildPagerdutyPayload:
    cfg = _pd_config()

    def test_returns_dict_with_routing_key(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert "routing_key" in payload

    def test_event_action_is_trigger(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert payload["event_action"] == "trigger"

    def test_has_dedup_key(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert "dedup_key" in payload

    def test_dedup_key_prefix(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert payload["dedup_key"].startswith("k1n-sentinel")

    def test_custom_dedup_suffix(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg, dedup_suffix="abc123")
        assert "abc123" in payload["dedup_key"]

    def test_severity_critical_maps_to_critical(self):
        finding = _make_finding(Criticality.CRITICAL)
        payload = build_pagerduty_payload([finding], ".", self.cfg)
        assert payload["payload"]["severity"] == "critical"

    def test_severity_high_maps_to_error(self):
        finding = _make_finding(Criticality.HIGH)
        payload = build_pagerduty_payload([finding], ".", self.cfg)
        assert payload["payload"]["severity"] == "error"

    def test_severity_medium_maps_to_warning(self):
        finding = _make_finding(Criticality.MEDIUM)
        payload = build_pagerduty_payload([finding], ".", self.cfg)
        assert payload["payload"]["severity"] == "warning"

    def test_summary_contains_finding_count(self):
        findings = [_make_finding() for _ in range(3)]
        payload = build_pagerduty_payload(findings, ".", self.cfg)
        assert "3" in payload["payload"]["summary"]

    def test_custom_details_has_findings(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert "findings" in payload["payload"]["custom_details"]

    def test_findings_capped_at_20_in_custom_details(self):
        findings = [_make_finding() for _ in range(25)]
        payload = build_pagerduty_payload(findings, ".", self.cfg)
        assert len(payload["payload"]["custom_details"]["findings"]) <= 20

    def test_empty_findings_returns_empty_dict(self):
        payload = build_pagerduty_payload([], ".", self.cfg)
        assert payload == {}

    def test_routing_key_in_payload(self):
        payload = build_pagerduty_payload([_make_finding()], ".", self.cfg)
        assert payload["routing_key"] == self.cfg.routing_key


# ---------------------------------------------------------------------------
# send_alert — dry run
# ---------------------------------------------------------------------------

class TestSendAlertDryRun:

    def test_returns_alert_result(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert isinstance(result, AlertResult)

    def test_success_true_on_dry_run(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert result.success is True

    def test_dry_run_flag_set(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert result.dry_run is True

    def test_findings_alerted_count_correct(self):
        findings = [_make_finding(Criticality.CRITICAL), _make_finding(Criticality.HIGH)]
        result = send_alert(findings, ".", _slack_config(), dry_run=True)
        assert result.findings_alerted == 2

    def test_low_severity_filtered_out_by_high_threshold(self):
        findings = [
            _make_finding(Criticality.HIGH),
            _make_finding(Criticality.MEDIUM),
            _make_finding(Criticality.LOW),
        ]
        result = send_alert(findings, ".", _slack_config(), dry_run=True)
        assert result.findings_alerted == 1

    def test_payload_preview_populated(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert result.payload_preview != {}

    def test_no_alertable_findings_returns_empty_payload(self):
        # MEDIUM finding with HIGH threshold → nothing to alert
        result = send_alert(
            [_make_finding(Criticality.MEDIUM)], ".", _slack_config(), dry_run=True
        )
        assert result.findings_alerted == 0
        assert result.payload_preview == {}
        assert result.success is True

    def test_pagerduty_channel_dry_run(self):
        result = send_alert([_make_finding()], ".", _pd_config(), dry_run=True)
        assert result.success is True
        assert result.channel == AlertChannel.PAGERDUTY

    def test_slack_channel_set_in_result(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert result.channel == AlertChannel.SLACK

    def test_http_status_none_on_dry_run(self):
        result = send_alert([_make_finding()], ".", _slack_config(), dry_run=True)
        assert result.http_status is None

    def test_low_threshold_alerts_all_severities(self):
        cfg = WebhookConfig(
            url="x", channel=AlertChannel.SLACK, severity_threshold="low"
        )
        findings = [
            _make_finding(Criticality.CRITICAL),
            _make_finding(Criticality.HIGH),
            _make_finding(Criticality.MEDIUM),
            _make_finding(Criticality.LOW),
        ]
        result = send_alert(findings, ".", cfg, dry_run=True)
        assert result.findings_alerted == 4
