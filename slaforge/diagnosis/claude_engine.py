"""
diagnosis/claude_engine.py
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from textwrap import dedent
from typing import Optional

import anthropic

from slaforge.database import get_db
from slaforge.models import Anomaly, AnomalyType, LogEvent, ResolutionStatus
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

_ANOMALY_CONTEXT = {
    AnomalyType.ERROR_RATE_SPIKE: dedent("""
        The integration's error rate has spiked significantly above its baseline.
        This typically indicates: API endpoint changes, auth token expiry,
        network connectivity issues, rate limiting, or server-side failures.
    """).strip(),

    AnomalyType.LATENCY_DEGRADATION: dedent("""
        API response latency has degraded significantly above baseline.
        This typically indicates: network congestion, API server load,
        DNS resolution delays, TLS renegotiation, connection pool exhaustion,
        or upstream database slowness.
    """).strip(),

    AnomalyType.RATE_LIMIT_APPROACH: dedent("""
        The integration is consuming API rate limit at an accelerating rate.
        At the current trajectory it may hit the limit within minutes.
        This typically indicates: polling too frequently, inefficient queries
        fetching more data than needed, or a runaway retry loop.
    """).strip(),

    AnomalyType.AUTH_FAILURE: dedent("""
        The integration is experiencing authentication failures (401/403 responses).
        This typically indicates: expired token, revoked token,
        insufficient token scopes, IP allowlist violation, or a token rotation
        that wasn't propagated to this service.
    """).strip(),

    AnomalyType.THROUGHPUT_DROP: dedent("""
        The integration's throughput has dropped significantly.
        This typically indicates: network partition, service health issue,
        or a configuration change that reduced the polling frequency.
    """).strip(),

    AnomalyType.WEBHOOK_FAILURE: dedent("""
        Webhook delivery failures are occurring.
        This typically indicates: endpoint unreachable, SSL certificate issue,
        HMAC signature mismatch, response timeout, or incorrect Content-Type handling.
    """).strip(),

    AnomalyType.SLA_BREACH_PREDICTED: dedent("""
        SLAForge predicts an SLA breach within 30 minutes based on current metric trends.
        Linear regression over recent data points shows the metric is trending toward
        the SLA threshold faster than normal recovery patterns would allow.
    """).strip(),
}

_DIAGNOSIS_PROMPT = dedent("""
    You are an expert Forward Deployment Engineer diagnosing a production integration failure.
    You have deep expertise in REST APIs, OAuth 2.0, webhooks, rate limiting, and enterprise networking.

    ## Anomaly Context
    {anomaly_context}

    ## CUSUM Detection Score
    Score: {cusum_score} (threshold: {threshold}, baseline_window: {baseline_window} points)
    Severity: {severity}

    ## Integration
    Name: {integration_name}
    Base URL: {integration_url}

    ## Metric Timeline (last 20 data points, chronological)
    Each row: timestamp | error_rate | p95_latency_ms | rate_limit_remaining | auth_failures
    {metric_timeline}

    ## Recent Log Events (last 30, most recent last)
    {log_context}

    ## Your Task
    Analyze this data and produce a diagnosis. Be specific — do not say "the system may be experiencing issues."
    Say exactly what you think is wrong and why the data supports that conclusion.

    Respond with ONLY a valid JSON object matching this exact schema:
    {{
        "root_cause": "<one specific sentence describing the exact failure>",
        "confidence": <float between 0.0 and 1.0>,
        "affected_component": "<one of: api_endpoint | auth_token | network | rate_limiter | webhook | dns | tls | integration_code>",
        "evidence": "<2-3 sentences explaining which data points support this conclusion>",
        "fix_steps": [
            "<specific actionable step 1>",
            "<specific actionable step 2>",
            "<specific actionable step 3>"
        ],
        "runbook_entry": "<markdown formatted runbook entry including: symptom, root cause, detection signal, resolution steps, and prevention>"
    }}

    Do not include any text outside the JSON object.
""").strip()

# Phase 2: Auto-remediation prompt
_REMEDIATION_PROMPT = dedent("""
    You are an expert Forward Deployment Engineer. A production integration failure has been diagnosed
    with high confidence ({confidence:.0%}). Generate a runnable remediation script.

    ## Integration
    Name: {integration_name}
    Base URL: {integration_url}
    Anomaly type: {anomaly_type}
    Root cause: {root_cause}
    Affected component: {affected_component}

    ## Fix Steps
    {fix_steps}

    ## Your Task
    Generate a single runnable script that implements the fix steps above.
    The script should be safe to run, include validation steps, and print clear output.

    Rules:
    - Prefer bash/curl for API-level fixes (rate limiting, latency testing, auth verification)
    - Prefer Python for more complex logic (token rotation, retry configuration)
    - Include comments explaining each step
    - Add a validation step at the end that confirms the fix worked
    - Make it copy-paste ready — no placeholders left unfilled except for secrets (use ENV vars)

    Respond with ONLY the script, no explanation before or after.
    Start with a shebang line (#!/bin/bash or #!/usr/bin/env python3).
""").strip()


def _format_metric_timeline(snapshot_json: Optional[str]) -> str:
    if not snapshot_json:
        return "No metric data available."
    try:
        rows = json.loads(snapshot_json)
        lines = []
        for r in rows:
            lines.append(
                f"{r.get('ts','?')[:19]} | "
                f"err={r.get('err_rate', 0):.3f} | "
                f"p95={r.get('p95_ms') or 'N/A'} ms | "
                f"rl={r.get('rl_rem','?')} | "
                f"auth_fail={r.get('auth_fail',0)}"
            )
        return "\n".join(lines)
    except Exception:
        return snapshot_json[:500]


def _fetch_log_context(limit: int = 30) -> str:
    try:
        with get_db() as db:
            events = (
                db.query(LogEvent)
                .order_by(LogEvent.recorded_at.desc())
                .limit(limit)
                .all()
            )
            if not events:
                return "No log events available."
            lines = []
            for e in reversed(events):
                ts = e.recorded_at.strftime("%H:%M:%S") if e.recorded_at else "?"
                lines.append(
                    f"[{ts}] {e.level:<5} "
                    f"{e.method or ''} {e.url or ''} "
                    f"-> {e.status_code or '?'} "
                    f"({e.latency_ms:.0f}ms)" if e.latency_ms else
                    f"[{ts}] {e.level:<5} {e.message}"
                )
            return "\n".join(lines)
    except Exception:
        return "Error fetching log context."


async def _generate_remediation(
    integration_name: str,
    integration_url: str,
    anomaly_type: AnomalyType,
    root_cause: str,
    affected_component: str,
    confidence: float,
    fix_steps: list,
) -> Optional[str]:
    """Phase 2: Generate a runnable remediation script when confidence > 0.85."""
    try:
        steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(fix_steps))
        prompt = _REMEDIATION_PROMPT.format(
            confidence=confidence,
            integration_name=integration_name,
            integration_url=integration_url,
            anomaly_type=anomaly_type.value,
            root_cause=root_cause,
            affected_component=affected_component,
            fix_steps=steps_text,
        )

        message = _client.messages.create(
            model=settings.claude_model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        script = message.content[0].text.strip()
        logger.info("Remediation script generated (%d chars)", len(script))
        return script

    except Exception:
        logger.exception("Remediation generation failed")
        return None


async def diagnose_anomaly(anomaly_id: int) -> None:
    with get_db() as db:
        anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
        if not anomaly:
            logger.error("Anomaly %d not found for diagnosis", anomaly_id)
            return
        if anomaly.status != ResolutionStatus.OPEN:
            return

        anomaly.status = ResolutionStatus.DIAGNOSING
        db.flush()

        anomaly_context = _ANOMALY_CONTEXT.get(anomaly.anomaly_type, "Unknown anomaly type.")
        metric_timeline = _format_metric_timeline(anomaly.metric_snapshot)
        log_context     = _fetch_log_context(30)

        # Get integration info for context
        integration_name = "unknown"
        integration_url  = "unknown"
        if anomaly.integration_id:
            from slaforge.models import Integration
            integ = db.query(Integration).filter(
                Integration.id == anomaly.integration_id
            ).first()
            if integ:
                integration_name = integ.name
                integration_url  = integ.base_url

        prompt = _DIAGNOSIS_PROMPT.format(
            anomaly_context=anomaly_context,
            cusum_score=anomaly.cusum_score,
            threshold=settings.cusum_threshold,
            baseline_window=settings.baseline_window,
            severity=anomaly.severity.value,
            integration_name=integration_name,
            integration_url=integration_url,
            metric_timeline=metric_timeline,
            log_context=log_context,
        )

    logger.info("Calling Claude for anomaly %d diagnosis...", anomaly_id)

    try:
        message = _client.messages.create(
            model=settings.claude_model,
            max_tokens=settings.diagnosis_max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_response = message.content[0].text.strip()
        logger.info("Claude raw: %.300s", raw_response)

        match = re.search(r'\{.*\}', raw_response, re.DOTALL)
        if not match:
            raise json.JSONDecodeError("No JSON found", raw_response, 0)
        diagnosis = json.loads(match.group())

        confidence  = float(diagnosis.get("confidence", 0.0))
        root_cause  = diagnosis.get("root_cause", "Unknown")
        fix_steps   = diagnosis.get("fix_steps", [])
        affected    = diagnosis.get("affected_component", "unknown")

        # Phase 2: Generate remediation script if confidence > 0.85
        remediation_script = None
        if confidence >= 0.80:
            logger.info(
                "Confidence %.2f >= 0.85 — generating remediation script for anomaly %d",
                confidence, anomaly_id,
            )
            remediation_script = await _generate_remediation(
                integration_name=integration_name,
                integration_url=integration_url,
                anomaly_type=anomaly_type_val if 'anomaly_type_val' in dir() else AnomalyType.ERROR_RATE_SPIKE,
                root_cause=root_cause,
                affected_component=affected,
                confidence=confidence,
                fix_steps=fix_steps,
            )

        # Save back to DB
        with get_db() as db:
            anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
            if not anomaly:
                return

            anomaly.root_cause          = root_cause
            anomaly.confidence          = confidence
            anomaly.affected_component  = affected
            anomaly.fix_steps           = json.dumps(fix_steps)
            anomaly.runbook_entry       = diagnosis.get("runbook_entry", "")
            anomaly.log_context         = log_context[:4000]
            anomaly.status              = ResolutionStatus.OPEN
            anomaly.remediation_script  = remediation_script

            a_type  = anomaly.anomaly_type
            a_sev   = anomaly.severity
            a_score = anomaly.cusum_score

        logger.info(
            "Diagnosis complete for anomaly %d: %s (confidence=%.2f)%s",
            anomaly_id,
            root_cause[:80],
            confidence,
            " — remediation script generated" if remediation_script else "",
        )

        _append_runbook(anomaly_id, diagnosis, a_type, a_sev, a_score, remediation_script)

    except json.JSONDecodeError:
        logger.error("Claude returned invalid JSON for anomaly %d", anomaly_id)
        with get_db() as db:
            anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
            if anomaly:
                anomaly.root_cause = "LLM returned unparseable response"
                anomaly.status     = ResolutionStatus.OPEN
    except Exception:
        logger.exception("Diagnosis failed for anomaly %d", anomaly_id)
        with get_db() as db:
            anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
            if anomaly:
                anomaly.status = ResolutionStatus.OPEN


def _append_runbook(
    anomaly_id: int,
    diagnosis: dict,
    anomaly_type: AnomalyType,
    severity,
    cusum_score: float,
    remediation_script: Optional[str] = None,
) -> None:
    os.makedirs(os.path.dirname(settings.runbook_path), exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    fix_steps = diagnosis.get("fix_steps", [])
    steps_md  = "\n".join(f"{i+1}. {s}" for i, s in enumerate(fix_steps))

    remediation_section = ""
    if remediation_script:
        remediation_section = f"\n\n### Auto-Generated Remediation Script\n```bash\n{remediation_script}\n```"

    entry = dedent(f"""
        ---

        ## [{timestamp}] Anomaly #{anomaly_id} — {anomaly_type.value.replace('_', ' ').title()}

        **Severity:** {severity.value.upper()}
        **CUSUM Score:** {cusum_score}
        **Confidence:** {diagnosis.get('confidence', '?')}
        **Affected Component:** `{diagnosis.get('affected_component', 'unknown')}`

        ### Root Cause
        {diagnosis.get('root_cause', 'Not determined')}

        ### Evidence
        {diagnosis.get('evidence', '')}

        ### Fix Steps
        {steps_md}

        ### Runbook Entry
        {diagnosis.get('runbook_entry', '')}
        {remediation_section}

        **Status:** OPEN

        ---
    """).strip()

    try:
        with open(settings.runbook_path, "a") as f:
            f.write(entry + "\n\n")
        logger.info("Runbook updated: %s", settings.runbook_path)
    except Exception:
        logger.exception("Failed to write runbook")