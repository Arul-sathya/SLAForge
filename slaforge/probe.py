"""
probe.py

Claude-powered API probe. When a user adds a new integration,
this module:
1. Tests connectivity and auth
2. Discovers monitorable endpoints
3. Measures baseline latency
4. Suggests SLO thresholds
5. Returns a human-readable probe summary

This is the zero-config onboarding layer — paste a URL, Claude figures the rest out.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import httpx
import anthropic

from slaforge.models import AuthType, ProbeResult
from slaforge.settings import settings

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

_KNOWN_PROBES = {
    "github.com": [
        "/rate_limit",
        "/user",
        "/repos",
    ],
    "api.stripe.com": [
        "/v1/balance",
        "/v1/charges?limit=1",
        "/v1/events?limit=1",
    ],
    "api.hubapi.com": [
        "/crm/v3/objects/contacts?limit=1",
        "/integrations/v1/limit/daily",
    ],
    "slack.com": [
        "/api/api.test",
        "/api/auth.test",
    ],
    "api.sendgrid.com": [
        "/v3/user/profile",
        "/v3/stats?start_date=2024-01-01",
    ],
    "api.twilio.com": [
        "/2010-04-01/Accounts.json",
    ],
    "jsonplaceholder.typicode.com": [
        "/posts?_limit=1",
        "/users?_limit=1",
        "/todos?_limit=1",
    ],
    "httpbin.org": [
        "/get",
        "/status/200",
        "/json",
    ],
    "api.github.com": [
        "/rate_limit",
        "/user",
    ],
    "dog.ceo": [
        "/api/breeds/list/all",
        "/api/breeds/image/random",
    ],
    "catfact.ninja": [
        "/fact",
        "/facts?limit=1",
    ],
}

_GENERIC_PROBES = [
    "/health",
    "/healthz",
    "/status",
    "/ping",
    "/api/health",
    "/api/v1/health",
    "/v1/health",
    "/api/status",
    "/ready",
    "/live",
    "/",
    "/api",
    "/api/v1",
    "/v1",
    "/v2",
    "/posts",
    "/users",
    "/todos",
    "/items",
    "/products",
    "/orders",
    "/events",
]


async def probe_integration(
    name: str,
    base_url: str,
    auth_type: AuthType,
    auth_token: Optional[str] = None,
) -> ProbeResult:
    """
    Main entry point. Probes the API and returns a ProbeResult with
    discovered endpoints and SLO suggestions.
    """
    logger.info("Probing integration: %s (%s)", name, base_url)

    headers = {"User-Agent": "SLAForge/2.0"}
    if auth_type == AuthType.BEARER and auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif auth_type == AuthType.API_KEY and auth_token:
        headers["X-API-Key"] = auth_token
    elif auth_type == AuthType.BASIC and auth_token:
        import base64
        headers["Authorization"] = f"Basic {base64.b64encode(auth_token.encode()).decode()}"

    domain = _extract_domain(base_url)
    probe_paths = _KNOWN_PROBES.get(domain, _GENERIC_PROBES)

    probe_results = []
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        for path in probe_paths:
            url = base_url.rstrip("/") + path
            try:
                t0 = time.perf_counter()
                resp = await client.get(url, headers=headers)
                latency_ms = (time.perf_counter() - t0) * 1000
                probe_results.append({
                    "path": path,
                    "url": url,
                    "status_code": resp.status_code,
                    "latency_ms": round(latency_ms, 1),
                    "ok": resp.status_code < 400,
                    "auth_fail": resp.status_code in (401, 403),
                    "content_type": resp.headers.get("content-type", ""),
                    "body_preview": resp.text[:200] if resp.status_code < 400 else "",
                })
            except Exception as e:
                probe_results.append({
                    "path": path,
                    "url": url,
                    "status_code": 0,
                    "latency_ms": 8000.0,
                    "ok": False,
                    "auth_fail": False,
                    "error": str(e),
                })

    auth_valid = any(r["ok"] for r in probe_results)
    auth_failed = all(r.get("auth_fail") for r in probe_results if r["status_code"] > 0)

    if auth_failed:
        return ProbeResult(
            success=False,
            endpoints=[],
            slo_suggestions={},
            probe_summary=f"Authentication failed for {base_url}. Check your token and auth type.",
            auth_valid=False,
        )

    successful = [r for r in probe_results if r["ok"]]

    if not successful:
        return ProbeResult(
            success=False,
            endpoints=[],
            slo_suggestions={},
            probe_summary=f"No accessible endpoints found at {base_url}. The API may require specific paths or different auth.",
            auth_valid=auth_valid,
        )

    probe_summary, endpoints, slo_suggestions = await _claude_analyze_probe(
        name=name,
        base_url=base_url,
        probe_results=probe_results,
        successful=successful,
    )

    return ProbeResult(
        success=True,
        endpoints=endpoints,
        slo_suggestions=slo_suggestions,
        probe_summary=probe_summary,
        auth_valid=True,
    )


async def _claude_analyze_probe(
    name: str,
    base_url: str,
    probe_results: List[Dict[str, Any]],
    successful: List[Dict[str, Any]],
) -> tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    probe_text = json.dumps(probe_results, indent=2)

    prompt = f"""You are an expert Forward Deployment Engineer analyzing an API integration probe.

Integration name: {name}
Base URL: {base_url}

Probe results (latency in ms, status codes, response previews):
{probe_text}

Your task:
1. Identify which endpoints are worth monitoring for health (prefer /health, /status, high-value business endpoints)
2. Suggest SLO thresholds based on the observed baseline latency
3. Write a 2-3 sentence summary of what this API does and what to watch for

Respond ONLY with a valid JSON object:
{{
    "endpoints": [
        {{"path": "/health", "method": "GET", "description": "Health check endpoint", "priority": "high"}},
        {{"path": "/api/users", "method": "GET", "description": "User listing endpoint", "priority": "medium"}}
    ],
    "slo_thresholds": {{
        "max_error_rate": 0.05,
        "max_latency_p95_ms": <2x the observed p95 latency>,
        "min_uptime_pct": 99.0
    }},
    "probe_summary": "<2-3 sentences about what this API does and what SLAForge will monitor>"
}}

Only include endpoints that responded successfully. Set max_latency_p95_ms to 2x the slowest successful response."""

    try:
        message = _client.messages.create(
            model=settings.claude_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()

        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if not match:
            raise ValueError("No JSON in Claude response")
        result = json.loads(match.group())

        endpoints = result.get("endpoints", [])
        slo_suggestions = result.get("slo_thresholds", {
            "max_error_rate": 0.05,
            "max_latency_p95_ms": max((r["latency_ms"] for r in successful), default=1000) * 2,
            "min_uptime_pct": 99.0,
        })
        probe_summary = result.get("probe_summary", f"Monitoring {len(endpoints)} endpoints at {base_url}")

        logger.info("Claude probe analysis complete: %d endpoints discovered", len(endpoints))
        return probe_summary, endpoints, slo_suggestions

    except Exception as e:
        logger.exception("Claude probe analysis failed: %s", e)
        endpoints = [
            {"path": r["path"], "method": "GET", "description": "Auto-discovered", "priority": "medium"}
            for r in successful
        ]
        latencies = [r["latency_ms"] for r in successful]
        p95 = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 1000
        slo_suggestions = {
            "max_error_rate": 0.05,
            "max_latency_p95_ms": p95 * 2,
            "min_uptime_pct": 99.0,
        }
        return f"Monitoring {len(endpoints)} endpoints at {base_url}", endpoints, slo_suggestions


def _extract_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""