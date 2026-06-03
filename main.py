"""
main.py — SLAForge v2 application entry point.
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
from slaforge.integration_manager import (
    ensure_default_integration,
    start_all_pollers,
    stop_all_pollers,
)
from slaforge.settings import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)-30s %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("SLAForge %s starting up", settings.app_version)
    logger.info("=" * 60)

    # 1. Database
    create_tables()
    logger.info("Database tables ready")

    # 2. Ensure default GitHub integration exists
    await ensure_default_integration()
    logger.info("Default integration ready")

    # 3. Legacy GitHub poller (keeps existing detection/diagnosis pipeline)
    start_poller()
    logger.info("GitHub poller started")

    # 4. Anomaly watcher + diagnosis queue
    start_watcher()
    logger.info("Anomaly watcher started")

    # 5. Start pollers for all integrations (including dynamic ones)
    await start_all_pollers()
    logger.info("Integration pollers started")

    yield

    logger.info("Shutting down SLAForge...")
    await stop_poller()
    await stop_watcher()
    await stop_all_pollers()
    logger.info("Shutdown complete")


app = FastAPI(
    title="SLAForge",
    description=(
        "Autonomous integration health monitor. "
        "Paste any API URL — SLAForge probes it, monitors it with CUSUM, "
        "diagnoses anomalies with Claude AI, and generates runbooks."
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
        "service":      "SLAForge",
        "version":      settings.app_version,
        "description":  "Autonomous integration health monitor",
        "docs":         "/docs",
        "health":       "/health",
        "integrations": "/integrations",
        "anomalies":    "/anomalies",
        "runbook":      "/runbook",
        "simulate":     "POST /simulate",
        "metrics":      "/metrics",
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level=settings.log_level.lower(),
    )