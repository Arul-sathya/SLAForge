"""
detection/cusum.py

CUSUM (Cumulative Sum) anomaly detection for integration metrics.

Why CUSUM over simple threshold alerting:
- Thresholds fire on spikes (one bad second triggers an alert)
- CUSUM detects SUSTAINED shifts (error rate drifting up over 5 minutes)
- Real integration degradation is almost always gradual, not instantaneous
- CUSUM accumulates evidence of a shift before firing — fewer false positives

The algorithm:
    S_pos[t] = max(0, S_pos[t-1] + (x[t] - mean - drift))
    S_neg[t] = max(0, S_neg[t-1] + (mean - x[t] - drift))
    Alert when S_pos[t] > threshold OR S_neg[t] > threshold

Where:
    x[t]      = current value (e.g., error_rate at time t)
    mean      = baseline mean computed from recent history
    drift     = allowable drift (ignore small natural variation)
    threshold = detection threshold (tune for sensitivity)

References: Page (1954), Montgomery (2009) Introduction to Statistical Quality Control
"""
from __future__ import annotations

import json
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from slaforge.database import get_db
from slaforge.models import Anomaly, AnomalyType, MetricPoint, Severity
from slaforge.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class CUSUMState:
    """
    State for one CUSUM detector monitoring one metric stream.
    One instance per metric we want to detect anomalies in.
    """
    name:       str
    anomaly_type: AnomalyType

    # Rolling history for baseline estimation
    history:    deque = field(default_factory=lambda: deque(maxlen=120))

    # CUSUM accumulators
    s_pos: float = 0.0   # detects upward shifts
    s_neg: float = 0.0   # detects downward shifts

    # Baseline (computed from history)
    baseline_mean: float = 0.0
    baseline_std:  float = 1.0

    # Cooldown: don't fire multiple anomalies in a short window
    last_anomaly_at: Optional[datetime] = None
    cooldown_seconds: int = 300  # 5 minutes

    def update(self, value: float) -> Optional[float]:
        """
        Feed a new data point. Returns the CUSUM score if an anomaly
        is detected, None otherwise.
        """
        self.history.append(value)

        # Need enough history to establish a baseline
        if len(self.history) < settings.baseline_window:
            return None

        # Recompute baseline from recent history
        arr = np.array(list(self.history))
        self.baseline_mean = float(np.mean(arr))
        self.baseline_std  = float(np.std(arr)) or 1.0  # avoid division by zero

        # Normalize the current value to z-score
        z = (value - self.baseline_mean) / self.baseline_std

        # CUSUM update
        self.s_pos = max(0.0, self.s_pos + z - settings.cusum_drift)
        self.s_neg = max(0.0, self.s_neg - z - settings.cusum_drift)

        score = max(self.s_pos, self.s_neg)

        if score >= settings.cusum_threshold:
            # Check cooldown
            if self.last_anomaly_at is not None:
                elapsed = (datetime.now(timezone.utc) -
                           self.last_anomaly_at).total_seconds()
                if elapsed < self.cooldown_seconds:
                    return None   # still in cooldown

            return score

        return None

    def reset(self) -> None:
        """Reset accumulators after an anomaly is handled."""
        self.s_pos = 0.0
        self.s_neg = 0.0
        self.last_anomaly_at = datetime.now(timezone.utc)


def _severity_from_score(score: float) -> Severity:
    if score >= 15:
        return Severity.CRITICAL
    if score >= 10:
        return Severity.HIGH
    if score >= 5:
        return Severity.MEDIUM
    return Severity.LOW


# ── One detector per metric stream ───────────────────────────────────────────
_detectors: dict[str, CUSUMState] = {
    "error_rate": CUSUMState(
        name="error_rate",
        anomaly_type=AnomalyType.ERROR_RATE_SPIKE,
        cooldown_seconds=300,
    ),
    "latency_p95": CUSUMState(
        name="latency_p95",
        anomaly_type=AnomalyType.LATENCY_DEGRADATION,
        cooldown_seconds=300,
    ),
    "rate_limit_pct": CUSUMState(
        name="rate_limit_pct",
        anomaly_type=AnomalyType.RATE_LIMIT_APPROACH,
        cooldown_seconds=600,
    ),
    "auth_failures": CUSUMState(
        name="auth_failures",
        anomaly_type=AnomalyType.AUTH_FAILURE,
        cooldown_seconds=180,
    ),
}


def get_detectors() -> dict[str, CUSUMState]:
    return _detectors


async def run_detection_cycle(metric: MetricPoint) -> list[int]:
    """
    Feed a new MetricPoint through all CUSUM detectors.
    Returns list of Anomaly IDs created (usually empty, occasionally one).
    """
    anomaly_ids = []

    # Compute rate_limit usage percentage
    rl_pct = 0.0
    if metric.rate_limit_limit and metric.rate_limit_limit > 0:
        used = metric.rate_limit_limit - (metric.rate_limit_remaining or 0)
        rl_pct = used / metric.rate_limit_limit

    feed = {
        "error_rate":    metric.error_rate,
        "latency_p95":   metric.latency_p95_ms or 0.0,
        "rate_limit_pct": rl_pct,
        "auth_failures": float(metric.auth_failures or 0),
    }

    for key, value in feed.items():
        detector = _detectors[key]
        score    = detector.update(value)

        if score is None:
            continue

        severity = _severity_from_score(score)
        logger.warning(
            "ANOMALY DETECTED: %s score=%.2f severity=%s value=%.4f",
            key, score, severity.value, value
        )

        # Build metric snapshot for LLM context
        with get_db() as db:
            recent = (
                db.query(MetricPoint)
                .order_by(MetricPoint.recorded_at.desc())
                .limit(20)
                .all()
            )
            snapshot = [
                {
                    "ts":       m.recorded_at.isoformat(),
                    "err_rate": round(m.error_rate, 4),
                    "p95_ms":   m.latency_p95_ms,
                    "rl_rem":   m.rate_limit_remaining,
                    "auth_fail":m.auth_failures,
                }
                for m in reversed(recent)
            ]

            anomaly = Anomaly(
                detected_at=datetime.now(timezone.utc),
                anomaly_type=detector.anomaly_type,
                severity=severity,
                cusum_score=round(score, 3),
                metric_snapshot=json.dumps(snapshot),
            )
            db.add(anomaly)
            db.flush()  # get the ID
            anomaly_id = anomaly.id

        detector.reset()
        anomaly_ids.append(anomaly_id)
        logger.info("Anomaly %d created — queuing for LLM diagnosis", anomaly_id)

    return anomaly_ids
