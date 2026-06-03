# SLAForge

Autonomous integration health monitor. Watches GitHub API endpoints, detects anomalies using CUSUM control charts, and generates root cause analysis + runbooks using Claude AI.

**Live demo:** https://slaforge-ui.vercel.app  
**API:** https://slaforge-production.up.railway.app/docs

## Stack
FastAPI · PostgreSQL · Claude API · Prometheus · Next.js · Railway · Vercel

## How it works
1. Polls GitHub API every 10s across 4 metric streams
2. CUSUM detectors fire when a stream drifts from baseline
3. Claude diagnoses the anomaly and generates fix steps
4. Runbook auto-updated with every diagnosis

## Quick start
\`\`\`bash
cp .env.example .env  # add your keys
docker compose up -d
curl http://localhost:8000/health
\`\`\`