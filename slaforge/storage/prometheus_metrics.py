"""
storage/prometheus_metrics.py

Prometheus metrics exported at /metrics.
Grafana scrapes this endpoint every 15 seconds.
"""
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry

registry = CollectorRegistry()

# ── Integration health metrics ────────────────────────────────────────────────
health_score = Gauge(
    "slaforge_health_score",
    "Integration health score (0=dead, 1=perfect)",
    registry=registry,
)

open_anomalies = Gauge(
    "slaforge_open_anomalies_total",
    "Number of open (unresolved) anomalies",
    registry=registry,
)

# ── GitHub API metrics ────────────────────────────────────────────────────────
github_requests_total = Counter(
    "slaforge_github_requests_total",
    "Total GitHub API requests made",
    ["method", "status_class"],   # status_class: 2xx, 4xx, 5xx
    registry=registry,
)

github_request_latency = Histogram(
    "slaforge_github_request_latency_ms",
    "GitHub API request latency in milliseconds",
    buckets=[50, 100, 200, 500, 1000, 2000, 5000],
    registry=registry,
)

github_error_rate = Gauge(
    "slaforge_github_error_rate",
    "Current GitHub API error rate (0-1)",
    registry=registry,
)

github_rate_limit_remaining = Gauge(
    "slaforge_github_rate_limit_remaining",
    "GitHub API rate limit remaining",
    registry=registry,
)

github_rate_limit_used_pct = Gauge(
    "slaforge_github_rate_limit_used_pct",
    "GitHub API rate limit used percentage (0-1)",
    registry=registry,
)

# ── CUSUM detector metrics ────────────────────────────────────────────────────
cusum_score = Gauge(
    "slaforge_cusum_score",
    "Current CUSUM score for each detector",
    ["detector"],
    registry=registry,
)

anomalies_detected_total = Counter(
    "slaforge_anomalies_detected_total",
    "Total anomalies detected by CUSUM",
    ["anomaly_type", "severity"],
    registry=registry,
)

# ── LLM diagnosis metrics ─────────────────────────────────────────────────────
diagnosis_latency = Histogram(
    "slaforge_diagnosis_latency_seconds",
    "Time taken for LLM diagnosis",
    buckets=[1, 2, 5, 10, 20, 30, 60],
    registry=registry,
)

diagnosis_confidence = Histogram(
    "slaforge_diagnosis_confidence",
    "LLM diagnosis confidence scores",
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    registry=registry,
)


def update_from_metric_point(metric) -> None:
    """Update Prometheus gauges from a MetricPoint ORM object."""
    github_error_rate.set(metric.error_rate or 0)

    if metric.rate_limit_remaining is not None:
        github_rate_limit_remaining.set(metric.rate_limit_remaining)
    if metric.rate_limit_limit and metric.rate_limit_limit > 0:
        used = metric.rate_limit_limit - (metric.rate_limit_remaining or 0)
        github_rate_limit_used_pct.set(used / metric.rate_limit_limit)

    if metric.latency_p95_ms:
        github_request_latency.observe(metric.latency_p95_ms)

    if metric.requests_total:
        status_class = "5xx" if (metric.errors_total or 0) > 0 else "2xx"
        github_requests_total.labels(
            method="GET", status_class=status_class
        ).inc(metric.requests_total)
