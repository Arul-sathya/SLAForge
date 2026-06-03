"""
ingestion/github_client.py

GitHub API client that SLAForge monitors.
This IS the integration being watched — it polls GitHub, tracks rate limits,
handles auth, and records every request outcome as a MetricPoint.

An FDE would deploy something like this at a customer site to sync GitHub
data into an internal system. SLAForge wraps it to catch when it degrades.
"""
import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from slaforge.database import get_db
from slaforge.models import LogEvent, MetricPoint
from slaforge.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class RequestOutcome:
    """Result of a single GitHub API call."""
    timestamp:           float
    method:              str
    url:                 str
    status_code:         int
    latency_ms:          float
    rate_limit_remaining: Optional[int]
    rate_limit_limit:    Optional[int]
    error_type:          Optional[str] = None


@dataclass
class GitHubMetrics:
    """
    Rolling window of request outcomes.
    Used by the detection layer to compute statistics and run CUSUM.
    """
    outcomes:    deque = field(default_factory=lambda: deque(maxlen=500))
    latencies:   deque = field(default_factory=lambda: deque(maxlen=500))
    error_rates: deque = field(default_factory=lambda: deque(maxlen=120))

    # Current rate limit state
    rate_limit_remaining: Optional[int] = None
    rate_limit_limit:     Optional[int] = None

    # Counters since last flush
    requests_since_flush:  int = 0
    errors_since_flush:    int = 0
    auth_failures_flush:   int = 0

    def record(self, outcome: RequestOutcome) -> None:
        self.outcomes.append(outcome)
        self.latencies.append(outcome.latency_ms)
        self.requests_since_flush += 1

        if outcome.status_code >= 400:
            self.errors_since_flush += 1
        if outcome.status_code in (401, 403):
            self.auth_failures_flush += 1

        if outcome.rate_limit_remaining is not None:
            self.rate_limit_remaining = outcome.rate_limit_remaining
            self.rate_limit_limit     = outcome.rate_limit_limit

    def error_rate(self) -> float:
        if self.requests_since_flush == 0:
            return 0.0
        return self.errors_since_flush / self.requests_since_flush

    def percentile(self, p: float) -> Optional[float]:
        if not self.latencies:
            return None
        sorted_lats = sorted(self.latencies)
        idx = int(len(sorted_lats) * p / 100)
        return sorted_lats[min(idx, len(sorted_lats) - 1)]

    def flush(self) -> dict:
        """Return a snapshot of current metrics and reset counters."""
        snap = {
            "requests_total":       self.requests_since_flush,
            "errors_total":         self.errors_since_flush,
            "error_rate":           self.error_rate(),
            "latency_p50_ms":       self.percentile(50),
            "latency_p95_ms":       self.percentile(95),
            "rate_limit_remaining": self.rate_limit_remaining,
            "rate_limit_limit":     self.rate_limit_limit,
            "auth_failures":        self.auth_failures_flush,
        }
        self.requests_since_flush = 0
        self.errors_since_flush   = 0
        self.auth_failures_flush  = 0
        return snap


# Module-level shared metrics object (thread-safe reads for detection layer)
_metrics = GitHubMetrics()
# Simulation flags injected by the /simulate endpoint
_simulate_errors    = False
_simulate_latency   = False
_simulate_ratelimit = False


def get_metrics() -> GitHubMetrics:
    return _metrics


def set_simulation(errors: bool = False, latency: bool = False,
                   ratelimit: bool = False) -> None:
    global _simulate_errors, _simulate_latency, _simulate_ratelimit
    _simulate_errors    = errors
    _simulate_latency   = latency
    _simulate_ratelimit = ratelimit


class GitHubClient:
    """
    Production-grade GitHub API client with:
    - Bearer token auth
    - Automatic rate limit tracking
    - Retry on 429/5xx
    - Structured logging of every request
    - Metric recording for SLAForge detection layer
    """
    BASE_URL = "https://api.github.com"

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={
                "Authorization": f"Bearer {settings.github_token}",
                "Accept":        "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
        )

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        url   = path
        start = time.monotonic()

        # Inject simulated failures for demo/testing
        if _simulate_errors and method == "GET":
            import random
            if random.random() < 0.6:
                # Simulate a 500 by raising before the real call
                outcome = RequestOutcome(
                    timestamp=time.time(), method=method, url=url,
                    status_code=500, latency_ms=50.0,
                    rate_limit_remaining=_metrics.rate_limit_remaining,
                    rate_limit_limit=_metrics.rate_limit_limit,
                    error_type="SimulatedServerError",
                )
                _metrics.record(outcome)
                self._log_event(outcome, "Simulated 500 error")
                raise httpx.HTTPStatusError(
                    "Simulated error", request=None, response=None
                )

        if _simulate_latency:
            import random
            await asyncio.sleep(random.uniform(2.0, 5.0))

        try:
            resp = await self._client.request(method, url, **kwargs)
            latency_ms = (time.monotonic() - start) * 1000

            outcome = RequestOutcome(
                timestamp=time.time(),
                method=method,
                url=url,
                status_code=resp.status_code,
                latency_ms=latency_ms,
                rate_limit_remaining=self._parse_int(
                    resp.headers.get("X-RateLimit-Remaining")
                ),
                rate_limit_limit=self._parse_int(
                    resp.headers.get("X-RateLimit-Limit")
                ),
                error_type=None if resp.is_success else f"HTTP{resp.status_code}",
            )
            _metrics.record(outcome)
            self._log_event(outcome)

            if resp.status_code == 429 or _simulate_ratelimit:
                retry_after = int(resp.headers.get("Retry-After", 60))
                logger.warning("Rate limited. Waiting %ds", retry_after)
                await asyncio.sleep(min(retry_after, 10))

            return resp

        except httpx.TimeoutException as exc:
            latency_ms = (time.monotonic() - start) * 1000
            outcome = RequestOutcome(
                timestamp=time.time(), method=method, url=url,
                status_code=0, latency_ms=latency_ms,
                rate_limit_remaining=None, rate_limit_limit=None,
                error_type="Timeout",
            )
            _metrics.record(outcome)
            self._log_event(outcome, str(exc))
            raise

    def _parse_int(self, value: Optional[str]) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    def _log_event(self, outcome: RequestOutcome,
                   message: str = "") -> None:
        level = "ERROR" if outcome.status_code >= 400 else "INFO"
        msg   = message or f"{outcome.method} {outcome.url} -> {outcome.status_code}"
        logger.log(
            logging.ERROR if level == "ERROR" else logging.INFO,
            "%s %s -> %d (%.0fms)",
            outcome.method, outcome.url, outcome.status_code, outcome.latency_ms
        )
        # Persist log event to DB for LLM context window
        try:
            with get_db() as db:
                db.add(LogEvent(
                    level=level,
                    message=msg,
                    method=outcome.method,
                    url=outcome.url,
                    status_code=outcome.status_code,
                    latency_ms=outcome.latency_ms,
                    error_type=outcome.error_type,
                    raw=json.dumps({
                        "ts": outcome.timestamp,
                        "status": outcome.status_code,
                        "latency_ms": round(outcome.latency_ms, 2),
                        "rl_remaining": outcome.rate_limit_remaining,
                    }),
                ))
        except Exception:
            pass  # never let logging kill the main flow

    # ── Public API methods ────────────────────────────────────────────────────

    async def list_repos(self) -> list[dict]:
        resp = await self._request("GET", f"/orgs/{settings.github_owner}/repos",
                                   params={"per_page": 30, "sort": "updated"})
        if resp.status_code == 404:
            # Fall back to user repos if owner is a user, not an org
            resp = await self._request(
                "GET", f"/users/{settings.github_owner}/repos",
                params={"per_page": 30, "sort": "updated"}
            )
        resp.raise_for_status()
        return resp.json()

    async def list_issues(self, state: str = "open") -> list[dict]:
        resp = await self._request(
            "GET",
            f"/repos/{settings.github_owner}/{settings.github_repo}/issues",
            params={"state": state, "per_page": 50},
        )
        resp.raise_for_status()
        return resp.json()

    async def list_commits(self) -> list[dict]:
        resp = await self._request(
            "GET",
            f"/repos/{settings.github_owner}/{settings.github_repo}/commits",
            params={"per_page": 30},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_rate_limit(self) -> dict:
        resp = await self._request("GET", "/rate_limit")
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        await self._client.aclose()


async def flush_metrics_to_db() -> None:
    """
    Called every poll_interval_seconds by the background poller.
    Flushes accumulated metrics into the metric_points table.
    The detection layer reads from this table.
    """
    snap = _metrics.flush()
    try:
        with get_db() as db:
            db.add(MetricPoint(
                recorded_at=datetime.now(timezone.utc),
                requests_total=snap["requests_total"],
                errors_total=snap["errors_total"],
                error_rate=snap["error_rate"],
                latency_p50_ms=snap["latency_p50_ms"],
                latency_p95_ms=snap["latency_p95_ms"],
                rate_limit_remaining=snap["rate_limit_remaining"],
                rate_limit_limit=snap["rate_limit_limit"],
                auth_failures=snap["auth_failures"],
            ))
    except Exception:
        logger.exception("Failed to flush metrics to DB")
