"""
detection/watcher.py
"""
import asyncio
import logging

from slaforge.database import get_db
from slaforge.detection.cusum import run_detection_cycle
from slaforge.diagnosis.claude_engine import diagnose_anomaly
from slaforge.models import MetricPoint
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_watcher_task = None
_last_processed_id = 0


async def _watch_loop() -> None:
    global _last_processed_id
    logger.info("Anomaly watcher started")

    while True:
        try:
            # Load metric points and detach them from session before closing
            metrics_data = []
            with get_db() as db:
                new_points = (
                    db.query(MetricPoint)
                    .filter(MetricPoint.id > _last_processed_id)
                    .order_by(MetricPoint.id.asc())
                    .limit(50)
                    .all()
                )
                # Extract all data while session is open
                for m in new_points:
                    metrics_data.append({
                        "id":                    m.id,
                        "recorded_at":           m.recorded_at,
                        "requests_total":        m.requests_total,
                        "errors_total":          m.errors_total,
                        "error_rate":            m.error_rate,
                        "latency_p50_ms":        m.latency_p50_ms,
                        "latency_p95_ms":        m.latency_p95_ms,
                        "rate_limit_remaining":  m.rate_limit_remaining,
                        "rate_limit_limit":      m.rate_limit_limit,
                        "webhook_deliveries":    m.webhook_deliveries,
                        "webhook_failures":      m.webhook_failures,
                        "auth_failures":         m.auth_failures,
                    })

            for data in metrics_data:
                # Create a detached MetricPoint-like object
                metric = MetricPoint(**{k: v for k, v in data.items() if k != "id"})
                metric.id = data["id"]

                anomaly_ids = await run_detection_cycle(metric)
                _last_processed_id = data["id"]

                for aid in anomaly_ids:
                    asyncio.get_event_loop().create_task(
                        diagnose_anomaly(aid),
                        name=f"diagnose_anomaly_{aid}"
                    )

        except asyncio.CancelledError:
            logger.info("Watcher cancelled")
            break
        except Exception:
            logger.exception("Watcher error — will retry")

        await asyncio.sleep(10)


def start_watcher() -> None:
    global _watcher_task
    loop = asyncio.get_event_loop()
    _watcher_task = loop.create_task(_watch_loop(), name="anomaly_watcher")


async def stop_watcher() -> None:
    global _watcher_task
    if _watcher_task and not _watcher_task.done():
        _watcher_task.cancel()
        try:
            await _watcher_task
        except asyncio.CancelledError:
            pass