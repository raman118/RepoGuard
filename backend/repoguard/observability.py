"""Bounded structured events: never log body, headers, source or exception text."""

import json
import logging
import time
from datetime import UTC
from uuid import UUID, uuid4

import redis
from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select, text
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from repoguard.auth import DB, Actor
from repoguard.models import Job, Scan, utcnow

logger = logging.getLogger("repoguard.events")
router = APIRouter()


def configure_logging() -> None:
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)


def emit(event: str, **fields: str | int | float | bool | None) -> None:
    logger.info(json.dumps({"event": event, **fields}, sort_keys=True))


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            request_id = str(UUID(request.headers.get("X-Request-ID", "")))
        except ValueError:
            request_id = str(uuid4())
        started = time.monotonic()
        request.state.request_id = request_id
        response = await call_next(request)
        route = request.scope.get("route")
        emit(
            "http.completed",
            request_id=request_id,
            route=getattr(route, "path", "unmatched"),
            status=response.status_code,
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response


@router.get("/health/ready")
def ready(request: Request, response: Response) -> dict[str, object]:
    database = False
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            # Missing migrations must not report ready.
            connection.execute(text("SELECT id FROM jobs LIMIT 1"))
        database = True
    except Exception:
        pass
    cache = redis.Redis.from_url(
        request.app.state.settings.redis_url, socket_timeout=0.2, socket_connect_timeout=0.2
    )
    try:
        redis_ready = bool(cache.ping())
    except redis.RedisError:
        redis_ready = False
    finally:
        cache.close()
    local = request.app.state.settings.environment != "production"
    available = database and (redis_ready or local)
    response.status_code = 200 if available else 503
    return {
        "status": "ready" if available else "unavailable",
        "database": database,
        "redis": redis_ready,
        "notification_fallback": not redis_ready,
    }


@router.get("/v1/metrics")
def metrics(db: DB, actor: Actor) -> dict[str, object]:
    rows = db.execute(
        select(Job.state, func.count(Job.id))
        .join(Scan, Scan.id == Job.scan_id)
        .where(Scan.tenant_id == actor.tenant_id)
        .group_by(Job.state)
    )
    states = {state: count for state, count in rows}
    expired = db.scalar(
        select(func.count(Job.id))
        .join(Scan, Scan.id == Job.scan_id)
        .where(
            Scan.tenant_id == actor.tenant_id, Job.state == "running", Job.lease_until < utcnow()
        )
    )
    retries = db.scalar(
        select(func.count(Job.id))
        .join(Scan, Scan.id == Job.scan_id)
        .where(Scan.tenant_id == actor.tenant_id, Job.attempts > 1)
    )
    oldest = db.scalar(
        select(func.min(Scan.created_at))
        .join(Job, Job.scan_id == Scan.id)
        .where(Scan.tenant_id == actor.tenant_id, Job.state == "queued")
    )
    return {
        "jobs": {
            state: states.get(state, 0)
            for state in ["queued", "running", "succeeded", "failed", "cancelled"]
        },
        "expired_leases": expired or 0,
        "retried_jobs": retries or 0,
        "oldest_queued_seconds": max(0.0, (utcnow() - oldest.replace(tzinfo=UTC)).total_seconds())
        if oldest
        else 0.0,
    }
