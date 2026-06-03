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
from slaforge.models import (
    Anomaly, AnomalySchema, AnomalyType, HealthResponse,
    MetricPoint, MetricPointSchema, ResolutionStatus,
    ResolveRequest, Severity, SimulateRequest,
)
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from slaforge.storage.prometheus_metrics import (
    registry, open_anomalies, health_score, cusum_score,
)

router = APIRouter()
logger = logging.getLogger(__name__)
_start_time = time.time()

# Track active simulation tasks
_simulation_task: Optional[asyncio.Task] = None


# ── Health ────────────────────────────────────────────────────────────────────
@router.get("/health", response_model=HealthResponse, tags=["monitoring"])
def get_health(db: Session = Depends(get_db_dep)) -> HealthResponse:
    """
    Current integration health.
    health_score: 1.0 = healthy, 0.0 = dead.
    Degraded by: error rate, open anomalies, rate limit exhaustion.
    """
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

    # Compute health score
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

    if score >= 0.8:
        status = "healthy"
    elif score >= 0.5:
        status = "degraded"
    else:
        status = "critical"

    # Update Prometheus gauges
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
    )


# ── Anomalies ─────────────────────────────────────────────────────────────────
@router.get("/anomalies", response_model=list[AnomalySchema], tags=["anomalies"])
def list_anomalies(
    status: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db_dep),
) -> list:
    """List detected anomalies, optionally filtered by status."""
    q = db.query(Anomaly).order_by(Anomaly.detected_at.desc())
    if status:
        try:
            q = q.filter(Anomaly.status == ResolutionStatus(status))
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")
    return q.limit(limit).all()


@router.get("/anomalies/{anomaly_id}", response_model=AnomalySchema, tags=["anomalies"])
def get_anomaly(anomaly_id: int, db: Session = Depends(get_db_dep)):
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    return anomaly


@router.post("/anomalies/{anomaly_id}/resolve",
             response_model=AnomalySchema, tags=["anomalies"])
def resolve_anomaly(
    anomaly_id: int,
    body: ResolveRequest,
    db: Session = Depends(get_db_dep),
):
    """Mark an anomaly as resolved with a resolution note."""
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    anomaly.status          = ResolutionStatus.RESOLVED
    anomaly.resolved_at     = datetime.now(timezone.utc)
    anomaly.resolution_note = body.resolution_note
    db.flush()
    return anomaly


# ── Metrics ───────────────────────────────────────────────────────────────────
@router.get("/metrics/history", response_model=list[MetricPointSchema],
            tags=["metrics"])
def get_metric_history(limit: int = 100, db: Session = Depends(get_db_dep)):
    """Last N metric data points for charting."""
    return (
        db.query(MetricPoint)
        .order_by(MetricPoint.recorded_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/metrics", tags=["metrics"])
def prometheus_metrics() -> Response:
    """Prometheus metrics endpoint. Scraped by Grafana."""
    return Response(
        generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Runbook ───────────────────────────────────────────────────────────────────
@router.get("/runbook", response_class=PlainTextResponse, tags=["runbook"])
def get_runbook() -> str:
    """Return the auto-generated runbook as markdown."""
    from slaforge.settings import settings
    import os
    if not os.path.exists(settings.runbook_path):
        return "# SLAForge Runbook\n\nNo anomalies detected yet.\n"
    with open(settings.runbook_path) as f:
        return f.read()


# ── Simulation ────────────────────────────────────────────────────────────────
@router.post("/simulate", tags=["debug"])
async def simulate_anomaly(body: SimulateRequest) -> dict:
    """
    Inject a simulated anomaly for demo/testing purposes.
    Sets simulation flags on the GitHub client for duration_seconds,
    then clears them. CUSUM will detect the anomaly and Claude will diagnose it.
    """
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
    """Check if a simulation is currently running."""
    running = _simulation_task is not None and not _simulation_task.done()
    return {"simulation_running": running}


# ── CUSUM debug ───────────────────────────────────────────────────────────────
@router.get("/debug/cusum", tags=["debug"])
def debug_cusum() -> dict:
    """Current CUSUM state for all detectors."""
    detectors = get_detectors()
    return {
        name: {
            "s_pos":         round(d.s_pos, 3),
            "s_neg":         round(d.s_neg, 3),
            "score":         round(max(d.s_pos, d.s_neg), 3),
            "baseline_mean": round(d.baseline_mean, 4),
            "baseline_std":  round(d.baseline_std, 4),
            "history_len":   len(d.history),
            "threshold":     d.__class__.__dataclass_fields__  # just show name
        }
        for name, d in detectors.items()
    }
