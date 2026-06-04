"""
alerting/slack.py — Slack alerting for SLAForge anomalies.

Sends a rich Slack message when an anomaly is diagnosed.
Includes: integration name, anomaly type, severity, root cause,
CUSUM score, confidence, and remediation script link if available.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

from slaforge.settings import settings

logger = logging.getLogger(__name__)


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
    }.get(severity.lower(), "⚪")


def _severity_color(severity: str) -> str:
    return {
        "critical": "#FF0000",
        "high":     "#FF8C00",
        "medium":   "#FFD700",
        "low":      "#36a64f",
    }.get(severity.lower(), "#888888")


async def send_anomaly_alert(
    anomaly_id: int,
    integration_name: str,
    integration_url: str,
    anomaly_type: str,
    severity: str,
    cusum_score: float,
    root_cause: Optional[str],
    confidence: Optional[float],
    affected_component: Optional[str],
    has_remediation: bool = False,
) -> bool:
    """
    Send a Slack alert for a diagnosed anomaly.
    Returns True if sent successfully.
    """
    if not settings.slack_webhook_url:
        logger.debug("Slack webhook not configured — skipping alert")
        return False

    emoji = _severity_emoji(severity)
    color = _severity_color(severity)
    conf_str = f"{confidence * 100:.0f}%" if confidence else "unknown"
    remediation_note = (
        f"✅ Remediation script available: `GET /anomalies/{anomaly_id}/remediation`"
        if has_remediation else
        "⏳ Confidence below threshold — no remediation script generated"
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} SLAForge Alert — {anomaly_type.replace('_', ' ').title()}",
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Integration:*\n`{integration_name}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n`{severity.upper()}`"},
                {"type": "mrkdwn", "text": f"*CUSUM Score:*\n`{cusum_score:.2f}`"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n`{conf_str}`"},
                {"type": "mrkdwn", "text": f"*Component:*\n`{affected_component or 'unknown'}`"},
                {"type": "mrkdwn", "text": f"*Anomaly ID:*\n`#{anomaly_id}`"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Root Cause:*\n{root_cause or 'Diagnosing...'}",
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": remediation_note,
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🔗 `{integration_url}` | SLAForge autonomous integration monitor"
                }
            ]
        }
    ]

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                settings.slack_webhook_url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                logger.info(
                    "Slack alert sent for anomaly %d (%s/%s)",
                    anomaly_id, integration_name, anomaly_type,
                )
                return True
            else:
                logger.error(
                    "Slack alert failed: %d %s", resp.status_code, resp.text
                )
                return False
    except Exception:
        logger.exception("Slack alert error for anomaly %d", anomaly_id)
        return False