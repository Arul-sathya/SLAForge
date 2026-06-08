"""
api/routes.py — All SLAForge REST endpoints.
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.orm import Session

from slaforge.database import get_db_dep
from slaforge.detection.cusum import get_detectors
from slaforge.ingestion.github_client import get_metrics, set_simulation
from slaforge.integration_manager import (
    start_poller, stop_poller, get_active_pollers,
)
from slaforge.models import (
    Anomaly, AnomalySchema, AnomalyType, HealthResponse,
    Incident, Integration, IntegrationCreateRequest, IntegrationSchema,
    IntegrationStatus, MetricPoint, MetricPointSchema,
    ProbeRequest, ProbeResult, ResolutionStatus,
    ResolveRequest, Severity, SimulateRequest,
)
from slaforge.probe import probe_integration
from slaforge.storage.prometheus_metrics import (
    registry, open_anomalies, health_score, cusum_score,
)

router = APIRouter()
logger = logging.getLogger(__name__)
_start_time = time.time()

_simulation_task: Optional[asyncio.Task] = None


# ── Health ─────────────────────────────────────────────────────────────────────
@router.get("/health", response_model=HealthResponse, tags=["monitoring"])
def get_health(db: Session = Depends(get_db_dep)) -> HealthResponse:
    open_count = (
        db.query(Anomaly)
        .filter(Anomaly.status.in_([
            ResolutionStatus.OPEN, ResolutionStatus.DIAGNOSING
        ]))
        .count()
    )

    last_metric = (
        db.query(MetricPoint)
        .order_by(MetricPoint.recorded_at.desc())
        .first()
    )

    integrations_count = db.query(Integration).filter(
        Integration.status != IntegrationStatus.INACTIVE
    ).count()

    score = 1.0
    if open_count >= 3:
        score -= 0.5
    elif open_count >= 1:
        score -= 0.2 * open_count

    rl_pct_used = None
    if last_metric:
        if last_metric.error_rate > 0.1:
            score -= last_metric.error_rate * 0.5
        if (last_metric.rate_limit_limit and
                last_metric.rate_limit_remaining is not None):
            used = (last_metric.rate_limit_limit -
                    last_metric.rate_limit_remaining)
            rl_pct_used = used / last_metric.rate_limit_limit
            if rl_pct_used > 0.9:
                score -= 0.3

    score = max(0.0, min(1.0, round(score, 3)))
    status = "healthy" if score >= 0.8 else "degraded" if score >= 0.5 else "critical"

    health_score.set(score)
    open_anomalies.set(open_count)
    for name, det in get_detectors().items():
        cusum_score.labels(detector=name).set(max(det.s_pos, det.s_neg))

    return HealthResponse(
        status=status,
        health_score=score,
        open_anomalies=open_count,
        last_metric=MetricPointSchema.from_orm(last_metric) if last_metric else None,
        rate_limit_pct_used=rl_pct_used,
        uptime_seconds=round(time.time() - _start_time, 1),
        integrations_count=integrations_count,
    )


# ── Integrations ───────────────────────────────────────────────────────────────
@router.get("/integrations", response_model=list[IntegrationSchema], tags=["integrations"])
def list_integrations(db: Session = Depends(get_db_dep)):
    return db.query(Integration).order_by(Integration.created_at.asc()).all()


@router.get("/integrations/{integration_id}", response_model=IntegrationSchema, tags=["integrations"])
def get_integration(integration_id: str, db: Session = Depends(get_db_dep)):
    integration = db.query(Integration).filter(
        Integration.id == integration_id
    ).first()
    if not integration:
        raise HTTPException(404, f"Integration {integration_id} not found")
    return integration


@router.post("/integrations/probe", response_model=ProbeResult, tags=["integrations"])
async def probe_api(body: ProbeRequest) -> ProbeResult:
    """Claude probes an API URL — discovers endpoints, tests auth, suggests SLOs."""
    result = await probe_integration(
        name=body.name,
        base_url=body.base_url,
        auth_type=body.auth_type,
        auth_token=body.auth_token,
    )
    return result


@router.post("/integrations", response_model=IntegrationSchema, tags=["integrations"])
async def create_integration(
    body: IntegrationCreateRequest,
    db: Session = Depends(get_db_dep),
) -> Integration:
    """Add a new integration. Claude probes it first, then spins up a poller."""
    existing = db.query(Integration).filter(Integration.name == body.name).first()
    if existing:
        raise HTTPException(409, f"Integration '{body.name}' already exists")

    probe = await probe_integration(
        name=body.name,
        base_url=body.base_url,
        auth_type=body.auth_type,
        auth_token=body.auth_token,
    )

    if not probe.success:
        raise HTTPException(422, f"Probe failed: {probe.probe_summary}")

    import uuid
    integration = Integration(
        id=uuid.uuid4(),
        name=body.name,
        base_url=body.base_url,
        auth_type=body.auth_type,
        auth_token=body.auth_token,
        endpoints=probe.endpoints,
        slo_thresholds=probe.slo_suggestions,
        status=IntegrationStatus.ACTIVE,
        health_score=1.0,
        is_default=False,
        probe_summary=probe.probe_summary,
    )
    db.add(integration)
    db.flush()

    integration_id = str(integration.id)
    logger.info("Created integration %s (%s)", body.name, integration_id)

    await start_poller(integration_id)
    return integration


@router.delete("/integrations/{integration_id}", tags=["integrations"])
async def delete_integration(
    integration_id: str,
    db: Session = Depends(get_db_dep),
) -> dict:
    """Remove an integration and stop its poller."""
    integration = db.query(Integration).filter(
        Integration.id == integration_id
    ).first()
    if not integration:
        raise HTTPException(404, f"Integration {integration_id} not found")
    if integration.is_default:
        raise HTTPException(400, "Cannot delete the default GitHub integration")

    await stop_poller(integration_id)
    db.delete(integration)
    return {"status": "deleted", "id": integration_id}


@router.get("/integrations/{integration_id}/metrics",
            response_model=list[MetricPointSchema], tags=["integrations"])
def get_integration_metrics(
    integration_id: str,
    limit: int = 100,
    db: Session = Depends(get_db_dep),
):
    return (
        db.query(MetricPoint)
        .filter(MetricPoint.integration_id == integration_id)
        .order_by(MetricPoint.recorded_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/integrations/{integration_id}/anomalies",
            response_model=list[AnomalySchema], tags=["integrations"])
def get_integration_anomalies(
    integration_id: str,
    limit: int = 50,
    db: Session = Depends(get_db_dep),
):
    return (
        db.query(Anomaly)
        .filter(Anomaly.integration_id == integration_id)
        .order_by(Anomaly.detected_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/pollers", tags=["debug"])
def get_pollers() -> dict:
    return get_active_pollers()


# ── Anomalies ──────────────────────────────────────────────────────────────────
@router.get("/anomalies", response_model=list[AnomalySchema], tags=["anomalies"])
def list_anomalies(
    status: Optional[str] = None,
    integration_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db_dep),
) -> list:
    q = db.query(Anomaly).order_by(Anomaly.detected_at.desc())
    if status:
        try:
            q = q.filter(Anomaly.status == ResolutionStatus(status))
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")
    if integration_id:
        q = q.filter(Anomaly.integration_id == integration_id)
    return q.limit(limit).all()


@router.get("/anomalies/{anomaly_id}", response_model=AnomalySchema, tags=["anomalies"])
def get_anomaly(anomaly_id: int, db: Session = Depends(get_db_dep)):
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    return anomaly


@router.get("/anomalies/{anomaly_id}/remediation", tags=["anomalies"])
def get_remediation(anomaly_id: int, db: Session = Depends(get_db_dep)):
    """Get the auto-generated remediation script for an anomaly."""
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    if not anomaly.remediation_script:
        raise HTTPException(
            404,
            "No remediation script available — confidence threshold not met (need >80%)"
        )
    return PlainTextResponse(anomaly.remediation_script)


@router.post("/anomalies/{anomaly_id}/resolve",
             response_model=AnomalySchema, tags=["anomalies"])
def resolve_anomaly(
    anomaly_id: int,
    body: ResolveRequest,
    db: Session = Depends(get_db_dep),
):
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    anomaly.status          = ResolutionStatus.RESOLVED
    anomaly.resolved_at     = datetime.now(timezone.utc)
    anomaly.resolution_note = body.resolution_note
    db.flush()
    return anomaly


# ── Incidents ──────────────────────────────────────────────────────────────────
@router.get("/incidents", tags=["incidents"])
def list_incidents(db: Session = Depends(get_db_dep)):
    """List correlated multi-integration incidents with blast radius analysis."""
    from slaforge.models import IncidentStatus
    incidents = db.query(Incident).order_by(Incident.detected_at.desc()).limit(20).all()
    return [
        {
            "id":                    i.id,
            "detected_at":           i.detected_at.isoformat(),
            "integration_ids":       i.integration_ids,
            "blast_radius_summary":  i.blast_radius_summary,
            "anomaly_count":         len(i.anomalies) if i.anomalies else 0,
            "status":                i.status.value,
            "correlation_window_s":  i.correlation_window_seconds,
        }
        for i in incidents
    ]


@router.get("/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: int, db: Session = Depends(get_db_dep)):
    """Get a specific incident with all correlated anomalies."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        "id":                   incident.id,
        "detected_at":          incident.detected_at.isoformat(),
        "integration_ids":      incident.integration_ids,
        "blast_radius_summary": incident.blast_radius_summary,
        "status":               incident.status.value,
        "anomalies":            [
            {
                "id":           a.id,
                "anomaly_type": a.anomaly_type.value,
                "severity":     a.severity.value,
                "root_cause":   a.root_cause,
                "confidence":   a.confidence,
            }
            for a in incident.anomalies
        ] if incident.anomalies else [],
    }


# ── Metrics ────────────────────────────────────────────────────────────────────
@router.get("/metrics/history", response_model=list[MetricPointSchema], tags=["metrics"])
def get_metric_history(limit: int = 100, db: Session = Depends(get_db_dep)):
    return (
        db.query(MetricPoint)
        .order_by(MetricPoint.recorded_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/metrics", tags=["metrics"])
def prometheus_metrics() -> Response:
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


# ── Runbook ────────────────────────────────────────────────────────────────────
@router.get("/runbook", response_class=PlainTextResponse, tags=["runbook"])
def get_runbook() -> str:
    from slaforge.settings import settings
    import os
    if not os.path.exists(settings.runbook_path):
        return "# SLAForge Runbook\n\nNo anomalies detected yet.\n"
    with open(settings.runbook_path) as f:
        return f.read()


# ── Simulation ─────────────────────────────────────────────────────────────────
@router.post("/simulate", tags=["debug"])
async def simulate_anomaly(body: SimulateRequest) -> dict:
    global _simulation_task
    if _simulation_task and not _simulation_task.done():
        raise HTTPException(409, "A simulation is already running")

    async def _run_sim():
        logger.info("Starting simulation: %s for %ds",
                    body.anomaly_type.value, body.duration_seconds)
        set_simulation(
            errors=body.anomaly_type == AnomalyType.ERROR_RATE_SPIKE,
            latency=body.anomaly_type == AnomalyType.LATENCY_DEGRADATION,
            ratelimit=body.anomaly_type == AnomalyType.RATE_LIMIT_APPROACH,
        )
        await asyncio.sleep(body.duration_seconds)
        set_simulation(errors=False, latency=False, ratelimit=False)
        logger.info("Simulation ended")

    _simulation_task = asyncio.get_event_loop().create_task(_run_sim())

    return {
        "status":   "simulation_started",
        "type":     body.anomaly_type.value,
        "severity": body.severity.value,
        "duration": body.duration_seconds,
        "message":  "Watch /anomalies for the detected anomaly and LLM diagnosis",
    }


@router.get("/simulate/status", tags=["debug"])
def simulation_status() -> dict:
    running = _simulation_task is not None and not _simulation_task.done()
    return {"simulation_running": running}


# ── Debug ──────────────────────────────────────────────────────────────────────
@router.get("/debug/cusum", tags=["debug"])
def debug_cusum() -> dict:
    detectors = get_detectors()
    return {
        name: {
            "s_pos":         round(d.s_pos, 3),
            "s_neg":         round(d.s_neg, 3),
            "score":         round(max(d.s_pos, d.s_neg), 3),
            "baseline_mean": round(d.baseline_mean, 4),
            "baseline_std":  round(d.baseline_std, 4),
            "history_len":   len(d.history),
        }
        for name, d in detectors.items()
    }