from __future__ import annotations
import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey,
    Integer, String, Text, func
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class AnomalyType(str, enum.Enum):
    ERROR_RATE_SPIKE     = "error_rate_spike"
    LATENCY_DEGRADATION  = "latency_degradation"
    RATE_LIMIT_APPROACH  = "rate_limit_approach"
    AUTH_FAILURE         = "auth_failure"
    THROUGHPUT_DROP      = "throughput_drop"
    WEBHOOK_FAILURE      = "webhook_failure"
    SLA_BREACH_PREDICTED = "sla_breach_predicted"


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


class IntegrationStatus(str, enum.Enum):
    PROBING  = "probing"
    ACTIVE   = "active"
    DEGRADED = "degraded"
    INACTIVE = "inactive"
    ERROR    = "error"


class AuthType(str, enum.Enum):
    BEARER  = "bearer"
    API_KEY = "api_key"
    BASIC   = "basic"
    NONE    = "none"


class IncidentStatus(str, enum.Enum):
    OPEN     = "open"
    RESOLVED = "resolved"


# ── ORM Models ────────────────────────────────────────────────────────────────

class Integration(Base):
    __tablename__ = "integrations"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name           = Column(String(128), nullable=False, unique=True, index=True)
    base_url       = Column(String(512), nullable=False)
    auth_type      = Column(Enum(AuthType), default=AuthType.BEARER, nullable=False)
    auth_token     = Column(Text, nullable=True)
    endpoints      = Column(JSON, nullable=True)
    slo_thresholds = Column(JSON, nullable=True)
    status         = Column(Enum(IntegrationStatus), default=IntegrationStatus.PROBING, nullable=False)
    health_score   = Column(Float, default=1.0)
    is_default     = Column(Boolean, default=False)
    probe_summary  = Column(Text, nullable=True)
    created_at     = Column(DateTime, default=func.now(), nullable=False)
    last_polled_at = Column(DateTime, nullable=True)

    metric_points  = relationship("MetricPoint",  back_populates="integration", cascade="all, delete-orphan")
    anomalies      = relationship("Anomaly",      back_populates="integration", cascade="all, delete-orphan")
    sla_contracts  = relationship("SlaContract",  back_populates="integration", cascade="all, delete-orphan")
    webhook_events = relationship("WebhookEvent", back_populates="integration", cascade="all, delete-orphan")


class MetricPoint(Base):
    __tablename__ = "metric_points"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    integration_id       = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=True, index=True)
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

    integration          = relationship("Integration", back_populates="metric_points")


class Incident(Base):
    __tablename__ = "incidents"

    id                         = Column(Integer, primary_key=True, autoincrement=True)
    detected_at                = Column(DateTime, default=func.now(), nullable=False, index=True)
    integration_ids            = Column(JSON, nullable=False)
    blast_radius_summary       = Column(Text, nullable=True)
    correlation_window_seconds = Column(Float, default=60.0)
    status                     = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False)
    resolved_at                = Column(DateTime, nullable=True)

    anomalies                  = relationship("Anomaly", back_populates="incident")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    integration_id     = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=True, index=True)
    incident_id        = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
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
    remediation_script = Column(Text, nullable=True)
    is_recurring       = Column(Boolean, default=False)
    pattern_summary    = Column(Text, nullable=True)
    status             = Column(Enum(ResolutionStatus), default=ResolutionStatus.OPEN, nullable=False)
    resolved_at        = Column(DateTime, nullable=True)
    resolution_note    = Column(Text, nullable=True)

    integration        = relationship("Integration", back_populates="anomalies")
    incident           = relationship("Incident",    back_populates="anomalies")


class SlaContract(Base):
    __tablename__ = "sla_contracts"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    integration_id     = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    max_error_rate     = Column(Float, default=0.01)
    max_latency_p95_ms = Column(Float, default=1000.0)
    min_uptime_pct     = Column(Float, default=99.9)
    period_start       = Column(DateTime, nullable=False)
    period_end         = Column(DateTime, nullable=True)
    compliance_pct     = Column(Float, nullable=True)
    created_at         = Column(DateTime, default=func.now(), nullable=False)

    integration        = relationship("Integration", back_populates="sla_contracts")


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    integration_id  = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    received_at     = Column(DateTime, default=func.now(), nullable=False, index=True)
    payload         = Column(JSON, nullable=False)
    normalized_type = Column(String(64), nullable=True)
    processed       = Column(Boolean, default=False)

    integration     = relationship("Integration", back_populates="webhook_events")


class LogEvent(Base):
    __tablename__ = "log_events"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=True, index=True)
    recorded_at    = Column(DateTime, default=func.now(), nullable=False, index=True)
    level          = Column(String(16), nullable=False, index=True)
    message        = Column(Text, nullable=False)
    method         = Column(String(16),  nullable=True)
    url            = Column(String(512), nullable=True)
    status_code    = Column(Integer,     nullable=True, index=True)
    latency_ms     = Column(Float,       nullable=True)
    error_type     = Column(String(128), nullable=True)
    raw            = Column(Text,        nullable=True)


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class IntegrationSchema(BaseModel):
    id:             str
    name:           str
    base_url:       str
    auth_type:      AuthType
    status:         IntegrationStatus
    health_score:   float
    is_default:     bool
    probe_summary:  Optional[str] = None
    endpoints:      Optional[List[Dict[str, Any]]] = None
    slo_thresholds: Optional[Dict[str, Any]] = None
    created_at:     datetime
    last_polled_at: Optional[datetime] = None

    @field_validator('id', mode='before')
    @classmethod
    def coerce_id(cls, v: Any) -> str:
        return str(v)

    class Config:
        from_attributes = True


class IntegrationCreateRequest(BaseModel):
    name:       str = Field(..., min_length=1, max_length=128)
    base_url:   str = Field(..., min_length=8)
    auth_type:  AuthType = AuthType.BEARER
    auth_token: Optional[str] = None


class MetricPointSchema(BaseModel):
    id:                   int
    integration_id:       Optional[str] = None
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

    @field_validator('integration_id', mode='before')
    @classmethod
    def coerce_integration_id(cls, v: Any) -> Optional[str]:
        return str(v) if v is not None else None

    class Config:
        from_attributes = True


class AnomalySchema(BaseModel):
    id:                  int
    integration_id:      Optional[str] = None
    incident_id:         Optional[int] = None
    detected_at:         datetime
    anomaly_type:        AnomalyType
    severity:            Severity
    cusum_score:         float
    root_cause:          Optional[str] = None
    confidence:          Optional[float] = None
    affected_component:  Optional[str] = None
    fix_steps:           Optional[str] = None
    runbook_entry:       Optional[str] = None
    remediation_script:  Optional[str] = None
    is_recurring:        bool = False
    pattern_summary:     Optional[str] = None
    status:              ResolutionStatus
    resolved_at:         Optional[datetime] = None
    resolution_note:     Optional[str] = None

    @field_validator('integration_id', mode='before')
    @classmethod
    def coerce_integration_id(cls, v: Any) -> Optional[str]:
        return str(v) if v is not None else None

    class Config:
        from_attributes = True


class IncidentSchema(BaseModel):
    id:                         int
    detected_at:                datetime
    integration_ids:            List[str]
    blast_radius_summary:       Optional[str] = None
    correlation_window_seconds: float
    status:                     IncidentStatus
    resolved_at:                Optional[datetime] = None

    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    status:              str
    health_score:        float
    open_anomalies:      int
    last_metric:         Optional[MetricPointSchema] = None
    rate_limit_pct_used: Optional[float] = None
    uptime_seconds:      float
    integrations_count:  int = 1


class SimulateRequest(BaseModel):
    anomaly_type:     AnomalyType = AnomalyType.ERROR_RATE_SPIKE
    severity:         Severity    = Severity.HIGH
    duration_seconds: int         = Field(default=60, ge=10, le=300)
    integration_name: Optional[str] = None


class ResolveRequest(BaseModel):
    resolution_note: str = Field(..., min_length=10)


class ProbeRequest(BaseModel):
    name:       str
    base_url:   str
    auth_type:  AuthType = AuthType.BEARER
    auth_token: Optional[str] = None


class ProbeResult(BaseModel):
    success:         bool
    endpoints:       List[Dict[str, Any]]
    slo_suggestions: Dict[str, Any]
    probe_summary:   str
    auth_valid:      bool