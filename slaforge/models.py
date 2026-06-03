from __future__ import annotations
import enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Enum, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class AnomalyType(str, enum.Enum):
    ERROR_RATE_SPIKE    = "error_rate_spike"
    LATENCY_DEGRADATION = "latency_degradation"
    RATE_LIMIT_APPROACH = "rate_limit_approach"
    AUTH_FAILURE        = "auth_failure"
    THROUGHPUT_DROP     = "throughput_drop"
    WEBHOOK_FAILURE     = "webhook_failure"


class Severity(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ResolutionStatus(str, enum.Enum):
    OPEN           = "open"
    DIAGNOSING     = "diagnosing"
    RESOLVED       = "resolved"
    FALSE_POSITIVE = "false_positive"


class MetricPoint(Base):
    __tablename__ = "metric_points"
    id                   = Column(Integer, primary_key=True, autoincrement=True)
    recorded_at          = Column(DateTime, default=func.now(), nullable=False, index=True)
    requests_total       = Column(Integer, default=0)
    errors_total         = Column(Integer, default=0)
    error_rate           = Column(Float,   default=0.0)
    latency_p50_ms       = Column(Float,   nullable=True)
    latency_p95_ms       = Column(Float,   nullable=True)
    rate_limit_remaining = Column(Integer, nullable=True)
    rate_limit_limit     = Column(Integer, nullable=True)
    webhook_deliveries   = Column(Integer, default=0)
    webhook_failures     = Column(Integer, default=0)
    auth_failures        = Column(Integer, default=0)


class Anomaly(Base):
    __tablename__ = "anomalies"
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    detected_at        = Column(DateTime, default=func.now(), nullable=False, index=True)
    anomaly_type       = Column(Enum(AnomalyType), nullable=False)
    severity           = Column(Enum(Severity), nullable=False)
    cusum_score        = Column(Float, nullable=False)
    metric_snapshot    = Column(Text, nullable=True)
    log_context        = Column(Text, nullable=True)
    root_cause         = Column(Text, nullable=True)
    confidence         = Column(Float, nullable=True)
    affected_component = Column(String(128), nullable=True)
    fix_steps          = Column(Text, nullable=True)
    runbook_entry      = Column(Text, nullable=True)
    status             = Column(Enum(ResolutionStatus), default=ResolutionStatus.OPEN, nullable=False)
    resolved_at        = Column(DateTime, nullable=True)
    resolution_note    = Column(Text, nullable=True)


class LogEvent(Base):
    __tablename__ = "log_events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    recorded_at = Column(DateTime, default=func.now(), nullable=False, index=True)
    level       = Column(String(16), nullable=False, index=True)
    message     = Column(Text, nullable=False)
    method      = Column(String(16),  nullable=True)
    url         = Column(String(512), nullable=True)
    status_code = Column(Integer,     nullable=True, index=True)
    latency_ms  = Column(Float,       nullable=True)
    error_type  = Column(String(128), nullable=True)
    raw         = Column(Text,        nullable=True)


class MetricPointSchema(BaseModel):
    id:                   int
    recorded_at:          datetime
    requests_total:       int
    errors_total:         int
    error_rate:           float
    latency_p50_ms:       Optional[float] = None
    latency_p95_ms:       Optional[float] = None
    rate_limit_remaining: Optional[int]   = None
    rate_limit_limit:     Optional[int]   = None
    webhook_deliveries:   int
    webhook_failures:     int
    auth_failures:        int
    class Config:
        from_attributes = True


class AnomalySchema(BaseModel):
    id:                 int
    detected_at:        datetime
    anomaly_type:       AnomalyType
    severity:           Severity
    cusum_score:        float
    root_cause:         Optional[str] = None
    confidence:         Optional[float] = None
    affected_component: Optional[str] = None
    fix_steps:          Optional[str] = None
    runbook_entry:      Optional[str] = None
    status:             ResolutionStatus
    resolved_at:        Optional[datetime] = None
    resolution_note:    Optional[str] = None
    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    status:              str
    health_score:        float
    open_anomalies:      int
    last_metric:         Optional[MetricPointSchema] = None
    rate_limit_pct_used: Optional[float] = None
    uptime_seconds:      float


class SimulateRequest(BaseModel):
    anomaly_type:     AnomalyType = AnomalyType.ERROR_RATE_SPIKE
    severity:         Severity    = Severity.HIGH
    duration_seconds: int         = Field(default=60, ge=10, le=300)


class ResolveRequest(BaseModel):
    resolution_note: str = Field(..., min_length=10)