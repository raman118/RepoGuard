import hashlib
import hmac
import json
import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from repoguard.auth import DB
from repoguard.models import AuditEvent, Installation, Job, Repository, Scan, WebhookDelivery
from repoguard.notifications import notify

router = APIRouter()


@router.post("/webhooks/github")
async def github_webhook(request: Request, db: DB) -> dict[str, str]:
    secret = request.app.state.settings.webhook_secret
    if secret is None:
        raise HTTPException(503, "webhook not configured")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 1_000_000:
            raise HTTPException(413, "webhook body limit")
    expected = (
        "sha256=" + hmac.new(secret.get_secret_value().encode(), body, hashlib.sha256).hexdigest()
    )
    supplied = request.headers.get("x-hub-signature-256", "")
    if len(supplied) != len(expected) or not hmac.compare_digest(expected, supplied):
        raise HTTPException(401, "invalid webhook signature")
    try:
        delivery = str(UUID(request.headers.get("x-github-delivery", "")))
        event = request.headers.get("x-github-event", "")
        if event not in {"ping", "push", "installation", "installation_repositories"}:
            return {"status": "ignored"}
        payload = json.loads(body)
        if not isinstance(payload, dict) or not isinstance(payload.get("installation"), dict):
            raise ValueError
        installation_id = payload["installation"]["id"]
        if type(installation_id) is not int or installation_id <= 0:
            raise ValueError
        if event == "push" and not isinstance(payload.get("repository"), dict):
            raise ValueError
    except (ValueError, KeyError, TypeError, RecursionError):
        raise HTTPException(422, "invalid webhook payload") from None
    return await run_in_threadpool(
        persist_event, request, db, installation_id, delivery, event, payload
    )


def persist_event(
    request: Request,
    db: Session,
    installation_id: int,
    delivery: str,
    event: str,
    payload: dict[str, Any],
) -> dict[str, str]:
    installation = db.get(Installation, installation_id)
    if installation is None:
        raise HTTPException(404, "installation not registered")
    db.add(WebhookDelivery(id=delivery, installation_id=installation_id, event=event))
    try:
        db.flush()
        if (
            event == "push"
            and not payload.get("deleted", False)
            and str(payload.get("ref", "")).startswith("refs/heads/")
        ):
            sha = payload.get("after", "")
            provider_id = payload.get("repository", {}).get("id")
            if (
                not isinstance(sha, str)
                or re.fullmatch(r"[0-9a-f]{40}", sha) is None
                or sha == "0" * 40
                or type(provider_id) is not int
            ):
                raise HTTPException(422, "invalid push identity")
            repository = db.scalar(
                select(Repository).where(
                    Repository.provider_id == provider_id,
                    Repository.installation_id == installation_id,
                    Repository.tenant_id == installation.tenant_id,
                )
            )
            if repository:
                scan = Scan(
                    tenant_id=installation.tenant_id,
                    repository_id=repository.id,
                    sha=sha,
                    idempotency_key="webhook:" + delivery,
                )
                db.add(scan)
                db.flush()
                db.add(Job(scan_id=scan.id))
                db.add(
                    AuditEvent(
                        tenant_id=installation.tenant_id,
                        actor="github-app",
                        action="scan.webhook_queued",
                        entity_id=scan.id,
                    )
                )
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"status": "duplicate"}
    if event.startswith("installation"):
        request.app.state.github.invalidate(installation_id)
    if event == "push":
        notify(request.app.state.settings.redis_url)
    return {"status": "accepted"}
