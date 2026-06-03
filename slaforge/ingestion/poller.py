"""
ingestion/poller.py

Background asyncio task that continuously polls GitHub and flushes metrics.
This is the heartbeat of SLAForge — if this stops, monitoring stops.
"""
import asyncio
import logging

from slaforge.ingestion.github_client import (
    GitHubClient, flush_metrics_to_db
)
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_client: GitHubClient | None = None
_poller_task: asyncio.Task | None = None


async def _poll_loop() -> None:
    global _client
    _client = GitHubClient()
    logger.info("Poller started. Polling every %ds", settings.poll_interval_seconds)

    while True:
        try:
            # Run a realistic set of API calls that an integration would make
            await _client.list_issues(state="open")
            await asyncio.sleep(2)
            await _client.list_commits()
            await asyncio.sleep(2)
            await _client.get_rate_limit()

            # Flush accumulated metrics to DB for detection layer
            await flush_metrics_to_db()

        except asyncio.CancelledError:
            logger.info("Poller cancelled")
            break
        except Exception:
            logger.exception("Poller iteration failed — will retry")

        await asyncio.sleep(settings.poll_interval_seconds)

    if _client:
        await _client.close()


def start_poller() -> None:
    global _poller_task
    loop = asyncio.get_event_loop()
    _poller_task = loop.create_task(_poll_loop(), name="github_poller")
    logger.info("Poller task created")


async def stop_poller() -> None:
    global _poller_task
    if _poller_task and not _poller_task.done():
        _poller_task.cancel()
        try:
            await _poller_task
        except asyncio.CancelledError:
            pass
    logger.info("Poller stopped")
