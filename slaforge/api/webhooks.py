"""
api/webhooks.py

GitHub webhook receiver.
GitHub can be configured to POST events here when:
- Issues are opened/closed
- PRs are merged
- Pushes happen
- etc.

SLAForge uses webhook delivery success/failure as another health signal.
"""
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse

from slaforge.database import get_db
from slaforge.models import LogEvent, MetricPoint
from slaforge.settings import settings

router  = APIRouter()
logger  = logging.getLogger(__name__)

# Counters for webhook tracking
_deliveries = 0
_failures   = 0


def verify_github_signature(payload_bytes: bytes, sig_header: str) -> bool:
    """
    Verify GitHub's HMAC-SHA256 webhook signature.
    GitHub sends: X-Hub-Signature-256: sha256=<hex_digest>
    """
    if not sig_header:
        return False
    try:
        algo, provided = sig_header.split("=", 1)
    except ValueError:
        return False
    if algo != "sha256":
        return False

    expected = hmac.new(
        settings.github_webhook_secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided, expected)


async def _process_event(event_type: str, payload: dict) -> None:
    global _deliveries
    _deliveries += 1
    logger.info("Processing GitHub webhook event: %s", event_type)

    # Record as a log event for LLM context
    with get_db() as db:
        db.add(LogEvent(
            level="INFO",
            message=f"GitHub webhook: {event_type}",
            method="POST",
            url="/webhooks/github",
            status_code=200,
            latency_ms=0,
        ))


@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    global _failures
    raw_body = await request.body()

    # Verify signature
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not verify_github_signature(raw_body, sig):
        _failures += 1
        logger.warning("Invalid GitHub webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        _failures += 1
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = request.headers.get("X-GitHub-Event", "unknown")
    background_tasks.add_task(_process_event, event_type, payload)

    return JSONResponse({"status": "accepted"}, status_code=200)


def get_webhook_stats() -> dict:
    return {"deliveries": _deliveries, "failures": _failures}
