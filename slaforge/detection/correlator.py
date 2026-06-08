"""
detection/correlator.py — Phase 5: Blast radius correlation.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import anthropic

from slaforge.database import get_db
from slaforge.models import Anomaly, Incident, IncidentStatus, Integration, ResolutionStatus
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

CORRELATION_WINDOW_SECONDS = 60


async def check_blast_radius(new_anomaly_id: int) -> Optional[int]:
    with get_db() as db:
        new_anomaly = db.query(Anomaly).filter(Anomaly.id == new_anomaly_id).first()
        if not new_anomaly:
            return None

        window_start = datetime.now(timezone.utc) - timedelta(seconds=CORRELATION_WINDOW_SECONDS)

        recent_anomalies = (
            db.query(Anomaly)
            .filter(
                Anomaly.id != new_anomaly_id,
                Anomaly.detected_at >= window_start,
                Anomaly.integration_id != new_anomaly.integration_id,
                Anomaly.status.in_([ResolutionStatus.OPEN, ResolutionStatus.DIAGNOSING]),
            )
            .all()
        )

        if not recent_anomalies:
            return None

        affected_integration_ids = list(set(
            ([str(new_anomaly.integration_id)] if new_anomaly.integration_id else []) +
            [str(a.integration_id) for a in recent_anomalies if a.integration_id]
        ))

        if len(affected_integration_ids) < 2:
            return None

        integrations = db.query(Integration).filter(
            Integration.id.in_(affected_integration_ids)
        ).all()

        integration_map = {str(i.id): i for i in integrations}

        anomaly_context = []
        all_anomalies = [new_anomaly] + recent_anomalies
        for a in all_anomalies:
            integ = integration_map.get(str(a.integration_id), None)
            anomaly_context.append({
                "anomaly_id":       a.id,
                "integration_name": integ.name if integ else "unknown",
                "integration_url":  integ.base_url if integ else "unknown",
                "anomaly_type":     a.anomaly_type.value,
                "severity":         a.severity.value,
                "cusum_score":      round(a.cusum_score, 2),
                "detected_at":      a.detected_at.isoformat(),
                "root_cause":       a.root_cause or "diagnosing...",
            })

        integration_names = [integration_map[i].name for i in affected_integration_ids if i in integration_map]

        existing_incident = (
            db.query(Incident)
            .filter(
                Incident.status == IncidentStatus.OPEN,
                Incident.detected_at >= window_start,
            )
            .first()
        )

        if existing_incident:
            existing_ids = existing_incident.integration_ids or []
            merged_ids = list(set(existing_ids + affected_integration_ids))
            existing_incident.integration_ids = merged_ids
            incident_id = existing_incident.id
        else:
            incident = Incident(
                detected_at=datetime.now(timezone.utc),
                integration_ids=affected_integration_ids,
                correlation_window_seconds=CORRELATION_WINDOW_SECONDS,
                status=IncidentStatus.OPEN,
            )
            db.add(incident)
            db.flush()
            incident_id = incident.id

        for a in all_anomalies:
            a.incident_id = incident_id

        logger.info(
            "Blast radius detected: incident %d — %d integrations: %s",
            incident_id, len(affected_integration_ids), ", ".join(integration_names),
        )

    blast_radius_summary = await _analyze_blast_radius(
        anomaly_context=anomaly_context,
        integration_names=integration_names,
        incident_id=incident_id,
    )

    with get_db() as db:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            incident.blast_radius_summary = blast_radius_summary

    try:
        from slaforge.alerting.slack import send_incident_alert
        await send_incident_alert(
            incident_id=incident_id,
            integration_names=integration_names,
            blast_radius_summary=blast_radius_summary,
            anomaly_count=len(all_anomalies),
        )
    except Exception:
        logger.exception("Slack incident alert failed")

    return incident_id


async def _analyze_blast_radius(
    anomaly_context: list,
    integration_names: List[str],
    incident_id: int,
) -> str:
    context_json = json.dumps(anomaly_context, indent=2)

    prompt = f"""You are an expert Forward Deployment Engineer analyzing a multi-integration incident.

Multiple integrations have failed simultaneously within a 60-second window.

## Affected Integrations
{', '.join(integration_names)}

## Simultaneous Anomalies
{context_json}

Analyze this correlated incident: what is the likely shared root cause, blast radius, and recommended immediate action?
Respond in 3-4 concise sentences as a paragraph an FDE would send to a customer. No bullet points."""

    try:
        message = _client.messages.create(
            model=settings.claude_model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        summary = message.content[0].text.strip()
        logger.info("Blast radius analysis complete for incident %d", incident_id)
        return summary
    except Exception:
        logger.exception("Blast radius analysis failed for incident %d", incident_id)
        return f"Correlated incident across {len(integration_names)} integrations: {', '.join(integration_names)}. Manual investigation required."