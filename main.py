"""
main.py — SLAForge application entry point.

Startup sequence:
1. Create DB tables
2. Start GitHub poller (ingestion)
3. Start anomaly watcher (detection + diagnosis queue)
4. Serve FastAPI

Shutdown sequence:
1. Stop poller
2. Stop watcher
3. Close DB connections
"""
import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from slaforge.api.routes import router as main_router
from slaforge.api.webhooks import router as webhook_router
from slaforge.database import create_tables
from slaforge.detection.watcher import start_watcher, stop_watcher
from slaforge.ingestion.poller import start_poller, stop_poller
from slaforge.settings import settings

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)-30s %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler — startup and shutdown."""
    logger.info("=" * 60)
    logger.info("SLAForge %s starting up", settings.app_version)
    logger.info("Monitoring: github.com/%s/%s",
                settings.github_owner, settings.github_repo)
    logger.info("=" * 60)

    # 1. Database
    create_tables()
    logger.info("Database tables ready")

    # 2. Ingestion poller
    start_poller()
    logger.info("GitHub poller started")

    # 3. Anomaly watcher + diagnosis queue
    start_watcher()
    logger.info("Anomaly watcher started")

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down SLAForge...")
    await stop_poller()
    await stop_watcher()
    logger.info("Shutdown complete")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="SLAForge",
    description=(
        "Autonomous integration health monitor. "
        "Detects anomalies in enterprise API integrations using CUSUM "
        "statistical detection and diagnoses them with LLM-powered root "
        "cause analysis."
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(main_router)
app.include_router(webhook_router)


@app.get("/", tags=["meta"])
def root():
    return {
        "service":     "SLAForge",
        "version":     settings.app_version,
        "description": "Autonomous integration health monitor",
        "docs":        "/docs",
        "health":      "/health",
        "anomalies":   "/anomalies",
        "runbook":     "/runbook",
        "simulate":    "POST /simulate",
        "metrics":     "/metrics",
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level=settings.log_level.lower(),
    )
