"""
Webhook Alerting for Secret Leak Detections
=============================================
Sends formatted alert payloads to Slack and PagerDuty when high-severity
secrets are detected during a scan.

Design:
  - Alerting fires only for findings that meet or exceed the configured
    severity threshold (default: HIGH and above).
  - dry_run=True (default) builds the payload and returns it without sending
    any HTTP requests — safe for CI preview and testing.
  - The actual HTTP send uses only the stdlib `urllib.request` to avoid
    adding dependencies. Callers that need retry logic, mTLS, or proxy support
    should wrap `send_alert()` in their own transport.
  - Secret values are never included in alert payloads — only masked excerpts
    from ClassifiedFinding.original_finding.masked_excerpt.

Supported channels:
  - Slack: Incoming Webhooks with Block Kit formatting
  - PagerDuty: Events API v2 (trigger/resolve)

Usage:
    from alerting.webhook_alerts import WebhookConfig, AlertChannel, send_alert

    cfg = WebhookConfig(
        url="https://hooks.slack.com/services/T000/B000/xxxx",
        channel=AlertChannel.SLACK,
        severity_threshold="high",   # alert on HIGH and CRITICAL
        source_label="CI / k1n-sentinel",
    )

    result = send_alert(classified_findings, scan_path="./my-repo", config=cfg, dry_run=True)
    print(result.findings_alerted)   # number of findings that triggered this alert
    print(result.payload_preview)    # the payload dict that would be sent
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from classifiers.criticality_classifier import ClassifiedFinding
from detectors.regex_detector import Criticality


# ---------------------------------------------------------------------------
# Enumerations and constants
# ---------------------------------------------------------------------------

class AlertChannel(str, Enum):
    """Supported webhook destinations."""
    SLACK      = "slack"
    PAGERDUTY  = "pagerduty"


# Numeric order for severity comparison
_SEVERITY_ORDER: dict[Criticality, int] = {
    Criticality.LOW:      0,
    Criticality.MEDIUM:   1,
    Criticality.HIGH:     2,
    Criticality.CRITICAL: 3,
}

# Slack color attachments by severity
_SLACK_COLORS: dict[Criticality, str] = {
    Criticality.CRITICAL: "#FF0000",  # red
    Criticality.HIGH:     "#FF7700",  # orange
    Criticality.MEDIUM:   "#FFCC00",  # yellow
    Criticality.LOW:      "#4A90D9",  # blue
}

# PagerDuty severity strings
_PD_SEVERITY: dict[Criticality, str] = {
    Criticality.CRITICAL: "critical",
    Criticality.HIGH:     "error",
    Criticality.MEDIUM:   "warning",
    Criticality.LOW:      "info",
}


# ---------------------------------------------------------------------------
# Configuration and result types
# ---------------------------------------------------------------------------

@dataclass
class WebhookConfig:
    """
    Configuration for a single webhook destination.

    Attributes:
        url:                 Webhook URL (Slack incoming webhook or PagerDuty
                             Events API endpoint).
        channel:             AlertChannel.SLACK or AlertChannel.PAGERDUTY.
        severity_threshold:  Minimum criticality to alert on. Findings below
                             this level are silently ignored. Accepts string
                             ('low', 'medium', 'high', 'critical') or Criticality
                             enum value. Default: 'high'.
        source_label:        Human-readable source identifier shown in alert
                             body (e.g., 'CI / k1n-sentinel', 'Dev laptop').
        routing_key:         PagerDuty integration key (required for PAGERDUTY
                             channel). Ignored for Slack.
        dedup_key_prefix:    PagerDuty dedup key prefix for alert de-duplication.
                             Default: 'k1n-sentinel'.
        timeout_seconds:     HTTP request timeout. Default: 10.
    """
    url:                str
    channel:            AlertChannel
    severity_threshold: str | Criticality  = "high"
    source_label:       str                = "secret-leak-sentinel"
    routing_key:        Optional[str]      = None
    dedup_key_prefix:   str                = "k1n-sentinel"
    timeout_seconds:    int                = 10

    def threshold_criticality(self) -> Criticality:
        """Return the severity_threshold as a Criticality enum."""
        if isinstance(self.severity_threshold, Criticality):
            return self.severity_threshold
        try:
            return Criticality(self.severity_threshold.lower())
        except ValueError:
            return Criticality.HIGH

    def meets_threshold(self, finding: ClassifiedFinding) -> bool:
        """Return True if this finding should trigger an alert."""
        threshold = self.threshold_criticality()
        return _SEVERITY_ORDER[finding.final_criticality] >= _SEVERITY_ORDER[threshold]


@dataclass
class AlertResult:
    """
    Result of a send_alert() call.

    Attributes:
        success:          True if the payload was sent (or dry_run=True).
        dry_run:          Whether this was a preview-only run.
        channel:          Which AlertChannel was targeted.
        findings_alerted: Number of findings included in the alert payload.
        payload_preview:  The payload dict that was (or would be) sent.
        http_status:      HTTP response status code (None in dry-run mode).
        error:            Error message if success=False, else None.
    """
    success:          bool
    dry_run:          bool
    channel:          AlertChannel
    findings_alerted: int
    payload_preview:  dict[str, Any]    = field(default_factory=dict)
    http_status:      Optional[int]     = None
    error:            Optional[str]     = None


# ---------------------------------------------------------------------------
# Slack payload builder
# ---------------------------------------------------------------------------

def build_slack_payload(
    findings: list[ClassifiedFinding],
    scan_path: str,
    config: WebhookConfig,
) -> dict[str, Any]:
    """
    Build a Slack Block Kit payload for the given findings.

    Layout:
      - Header block with severity count badges
      - One section block per finding (capped at 10 for readability)
      - Footer with scan path and timestamp

    Args:
        findings:   Pre-filtered ClassifiedFinding list (only alertable).
        scan_path:  The scan target shown in the header.
        config:     WebhookConfig used for source label.

    Returns:
        Dict ready for JSON serialisation and POST to a Slack webhook URL.
    """
    critical_count = sum(1 for f in findings if f.final_criticality == Criticality.CRITICAL)
    high_count     = sum(1 for f in findings if f.final_criticality == Criticality.HIGH)
    ts             = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header_text = (
        f":rotating_light: *Secret Leak Detected* — `{scan_path}`\n"
        f"*{len(findings)} finding(s)* — "
        f"CRITICAL: {critical_count}  |  HIGH: {high_count}"
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": header_text},
        },
        {"type": "divider"},
    ]

    for cf in findings[:10]:   # Cap at 10 blocks to stay within Slack limits
        f = cf.original_finding
        color = _SLACK_COLORS.get(cf.final_criticality, "#AAAAAA")
        severity_label = cf.final_criticality.value.upper()

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*[{severity_label}]* `{f.detector_name}` "
                    f"— `{f.file_path}` line {f.line_number}\n"
                    f"> {f.masked_excerpt[:200]}"
                ),
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": severity_label},
                "style": "danger" if cf.final_criticality in (
                    Criticality.CRITICAL, Criticality.HIGH
                ) else "primary",
                "action_id": f"finding_{f.file_path}_{f.line_number}",
            },
        })

    if len(findings) > 10:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"_... and {len(findings) - 10} more finding(s). Run the full report._",
            },
        })

    blocks += [
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Source: *{config.source_label}*  |  {ts}",
                }
            ],
        },
    ]

    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# PagerDuty payload builder
# ---------------------------------------------------------------------------

def build_pagerduty_payload(
    findings: list[ClassifiedFinding],
    scan_path: str,
    config: WebhookConfig,
    dedup_suffix: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a PagerDuty Events API v2 trigger payload.

    Uses the highest-criticality finding to set the event severity. Includes
    a summary of all findings in custom_details.

    Args:
        findings:     Pre-filtered ClassifiedFinding list (only alertable).
        scan_path:    Scan target string (shown in PagerDuty alert title).
        config:       WebhookConfig with routing_key and source_label.
        dedup_suffix: Optional suffix for the dedup_key (e.g., git commit SHA).

    Returns:
        Dict in PagerDuty Events API v2 format.
    """
    if not findings:
        return {}

    # Highest severity determines event severity
    worst = max(findings, key=lambda f: _SEVERITY_ORDER[f.final_criticality])
    pd_sev = _PD_SEVERITY.get(worst.final_criticality, "error")

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dedup_key = f"{config.dedup_key_prefix}-{scan_path.replace('/', '-')}"
    if dedup_suffix:
        dedup_key += f"-{dedup_suffix}"

    # Build finding summaries (no secret values — masked excerpts only)
    finding_summaries = [
        {
            "severity":    cf.final_criticality.value,
            "detector":    cf.original_finding.detector_name,
            "file":        cf.original_finding.file_path,
            "line":        cf.original_finding.line_number,
            "excerpt":     cf.original_finding.masked_excerpt[:200],
            "confidence":  round(cf.confidence, 3),
        }
        for cf in findings[:20]  # Cap custom_details to avoid payload size limits
    ]

    return {
        "routing_key": config.routing_key or "",
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": (
                f"[k1n-sentinel] {len(findings)} secret(s) detected in {scan_path} "
                f"— worst severity: {worst.final_criticality.value.upper()}"
            ),
            "source":    config.source_label,
            "severity":  pd_sev,
            "timestamp": ts,
            "custom_details": {
                "scan_path":      scan_path,
                "total_findings": len(findings),
                "findings":       finding_summaries,
            },
        },
    }


# ---------------------------------------------------------------------------
# Main alerting function
# ---------------------------------------------------------------------------

def send_alert(
    classified_findings: list[ClassifiedFinding],
    scan_path: str,
    config: WebhookConfig,
    dry_run: bool = True,
    dedup_suffix: Optional[str] = None,
) -> AlertResult:
    """
    Send a webhook alert for findings that meet the configured severity threshold.

    In dry_run=True mode (default), the payload is built and returned in
    AlertResult.payload_preview without sending any HTTP request.

    Args:
        classified_findings: All findings from a scan run.
        scan_path:           The scanned path (for display in the alert).
        config:              WebhookConfig with url, channel, severity_threshold.
        dry_run:             If True, build the payload but do not send it.
        dedup_suffix:        Optional string appended to the PagerDuty dedup key
                             to distinguish alerts from the same scan path (e.g.,
                             a git commit SHA).

    Returns:
        AlertResult with payload_preview populated regardless of dry_run.
    """
    # Filter findings to those that meet the threshold
    alertable = [f for f in classified_findings if config.meets_threshold(f)]

    if not alertable:
        return AlertResult(
            success=True,
            dry_run=dry_run,
            channel=config.channel,
            findings_alerted=0,
            payload_preview={},
        )

    # Build the payload for the configured channel
    if config.channel == AlertChannel.SLACK:
        payload = build_slack_payload(alertable, scan_path, config)
    else:
        payload = build_pagerduty_payload(alertable, scan_path, config, dedup_suffix)

    if dry_run:
        return AlertResult(
            success=True,
            dry_run=True,
            channel=config.channel,
            findings_alerted=len(alertable),
            payload_preview=payload,
        )

    # Live send — POST the JSON payload to the webhook URL
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            config.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=config.timeout_seconds) as response:
            status = response.status

        return AlertResult(
            success=status in (200, 202),
            dry_run=False,
            channel=config.channel,
            findings_alerted=len(alertable),
            payload_preview=payload,
            http_status=status,
        )

    except urllib.error.HTTPError as exc:
        return AlertResult(
            success=False,
            dry_run=False,
            channel=config.channel,
            findings_alerted=len(alertable),
            payload_preview=payload,
            http_status=exc.code,
            error=f"HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        return AlertResult(
            success=False,
            dry_run=False,
            channel=config.channel,
            findings_alerted=len(alertable),
            payload_preview=payload,
            error=f"{type(exc).__name__}: {exc}",
        )
