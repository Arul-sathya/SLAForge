"""
integration_manager.py

Manages N integrations simultaneously. Each integration gets its own
isolated poller, CUSUM detectors, and diagnosis queue.

GitHub is auto-created as the default integration on startup.
New integrations are added dynamically via the API.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

import httpx

from slaforge.database import get_db
from slaforge.models import (
    AuthType, Integration, IntegrationStatus, MetricPoint,
)
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_pollers: Dict[str, asyncio.Task] = {}


# ── Default GitHub integration ─────────────────────────────────────────────────

async def ensure_default_integration() -> None:
    with get_db() as db:
        existing = db.query(Integration).filter(Integration.is_default == True).first()
        if existing:
            logger.info("Default GitHub integration already exists: %s", existing.name)
            return

        github = Integration(
            id=uuid.uuid4(),
            name="github",
            base_url="https://api.github.com",
            auth_type=AuthType.BEARER,
            auth_token=settings.github_token,
            is_default=True,
            status=IntegrationStatus.ACTIVE,
            health_score=1.0,
            endpoints=[
                {"path": f"/repos/{settings.github_owner}/{settings.github_repo}/issues", "method": "GET"},
                {"path": f"/repos/{settings.github_owner}/{settings.github_repo}/commits", "method": "GET"},
                {"path": "/rate_limit", "method": "GET"},
            ],
            slo_thresholds={
                "max_error_rate": 0.05,
                "max_latency_p95_ms": 2000.0,
                "min_uptime_pct": 99.0,
            },
            probe_summary="Default GitHub integration — monitors issues, commits, and rate limit.",
        )
        db.add(github)
        db.flush()
        logger.info("Created default GitHub integration: %s", github.id)


# ── Generic poller ─────────────────────────────────────────────────────────────

async def _poll_integration(integration_id: str) -> None:
    logger.info("Poller started for integration %s", integration_id)

    while True:
        try:
            # Load integration data inside session, extract all values before closing
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()

                if not integration:
                    logger.info("Integration %s not found — stopping poller", integration_id)
                    break

                # Check status by value to avoid enum comparison issues
                status_val = integration.status.value if integration.status else "inactive"
                if status_val == "inactive":
                    logger.info("Integration %s inactive — stopping poller", integration_id)
                    break

                # Extract all values while session is open
                endpoints  = list(integration.endpoints or [])
                auth_token = integration.auth_token
                base_url   = integration.base_url
                auth_type  = integration.auth_type
                int_id     = integration.id

            if not endpoints:
                await asyncio.sleep(settings.poll_interval_seconds)
                continue

            # Poll all endpoints
            results = []
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                headers = {"User-Agent": "SLAForge/2.0"}
                if auth_type == AuthType.BEARER and auth_token:
                    headers["Authorization"] = f"Bearer {auth_token}"
                elif auth_type == AuthType.API_KEY and auth_token:
                    headers["X-API-Key"] = auth_token

                for endpoint in endpoints:
                    path = endpoint.get("path", "/")
                    url = base_url.rstrip("/") + path
                    try:
                        t0 = time.perf_counter()
                        resp = await client.get(url, headers=headers)
                        latency_ms = (time.perf_counter() - t0) * 1000
                        results.append({
                            "path":         path,
                            "status_code":  resp.status_code,
                            "latency_ms":   latency_ms,
                            "ok":           resp.status_code < 400,
                            "auth_fail":    resp.status_code in (401, 403),
                            "rate_limited": resp.status_code == 429,
                        })
                    except Exception as e:
                        results.append({
                            "path":         path,
                            "status_code":  0,
                            "latency_ms":   10000.0,
                            "ok":           False,
                            "auth_fail":    False,
                            "rate_limited": False,
                            "error":        str(e),
                        })

            if not results:
                await asyncio.sleep(settings.poll_interval_seconds)
                continue

            # Aggregate metrics
            total      = len(results)
            errors     = sum(1 for r in results if not r["ok"])
            error_rate = errors / total if total > 0 else 0.0
            latencies  = sorted(r["latency_ms"] for r in results)
            p50        = latencies[int(len(latencies) * 0.50)] if latencies else None
            p95        = latencies[int(len(latencies) * 0.95)] if latencies else None
            auth_fails = sum(1 for r in results if r["auth_fail"])

            with get_db() as db:
                db.add(MetricPoint(
                    integration_id       = int_id,
                    requests_total       = total,
                    errors_total         = errors,
                    error_rate           = error_rate,
                    latency_p50_ms       = p50,
                    latency_p95_ms       = p95,
                    auth_failures        = auth_fails,
                ))

                integ = db.query(Integration).filter(Integration.id == int_id).first()
                if integ:
                    integ.health_score   = round(max(0.0, 1.0 - min(error_rate * 2, 1.0)), 3)
                    integ.status         = IntegrationStatus.ACTIVE if error_rate < 0.1 else IntegrationStatus.DEGRADED
                    integ.last_polled_at = datetime.now(timezone.utc)

            logger.debug(
                "Polled %s: %d endpoints, err=%.1f%%, p95=%.0fms",
                integration_id, total, error_rate * 100, p95 or 0,
            )

        except asyncio.CancelledError:
            logger.info("Poller cancelled for integration %s", integration_id)
            break
        except Exception:
            logger.exception("Poller error for integration %s", integration_id)

        await asyncio.sleep(settings.poll_interval_seconds)


# ── Manager API ────────────────────────────────────────────────────────────────

async def start_poller(integration_id: str) -> None:
    if integration_id in _pollers and not _pollers[integration_id].done():
        logger.warning("Poller already running for %s", integration_id)
        return
    task = asyncio.get_event_loop().create_task(
        _poll_integration(integration_id),
        name=f"poller_{integration_id}",
    )
    _pollers[integration_id] = task
    logger.info("Poller started for integration %s", integration_id)


async def stop_poller(integration_id: str) -> None:
    task = _pollers.get(integration_id)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    _pollers.pop(integration_id, None)
    logger.info("Poller stopped for integration %s", integration_id)


async def start_all_pollers() -> None:
    with get_db() as db:
        integrations = db.query(Integration).filter(
            Integration.status != IntegrationStatus.INACTIVE
        ).all()
        ids = [str(i.id) for i in integrations]

    for integration_id in ids:
        await start_poller(integration_id)
    logger.info("Started %d pollers", len(ids))


async def stop_all_pollers() -> None:
    for integration_id in list(_pollers.keys()):
        await stop_poller(integration_id)


def get_active_pollers() -> Dict[str, str]:
    return {
        iid: "running" if not task.done() else "stopped"
        for iid, task in _pollers.items()
    }