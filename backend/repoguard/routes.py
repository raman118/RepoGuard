from datetime import UTC
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from repoguard.auth import DB, Actor, Identity
from repoguard.fixtures import IDS, fixture_sha
from repoguard.github import GitHubError
from repoguard.models import AuditEvent, Finding, Installation, Job, Repository, Scan
from repoguard.notifications import notify
from repoguard.schemas import RepositoryInput, ScanInput

router = APIRouter(prefix="/v1")


def audit(db: Session, actor: Identity, action: str, entity_id: str) -> None:
    db.add(
        AuditEvent(tenant_id=actor.tenant_id, actor=actor.actor, action=action, entity_id=entity_id)
    )


def owned_repository(db: Session, actor: Identity, repository_id: str) -> Repository:
    row = db.scalar(
        select(Repository).where(
            Repository.id == repository_id, Repository.tenant_id == actor.tenant_id
        )
    )
    if row is None:
        raise HTTPException(404, "repository not found")
    return row


def owned_scan(db: Session, actor: Identity, scan_id: str) -> Scan:
    row = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.tenant_id == actor.tenant_id))
    if row is None:
        raise HTTPException(404, "scan not found")
    return row


def repository_view(row: Repository) -> dict[str, Any]:
    return {
        "id": row.id,
        "owner": row.owner,
        "name": row.name,
        "fixture_id": row.fixture_id,
        "installation_id": row.installation_id,
        "created_at": row.created_at.replace(tzinfo=UTC).isoformat(),
    }


def scan_view(db: Session, row: Scan) -> dict[str, Any]:
    job = db.scalar(select(Job).where(Job.scan_id == row.id))
    findings = db.scalars(
        select(Finding).where(Finding.scan_id == row.id).order_by(Finding.fingerprint)
    )
    return {
        "id": row.id,
        "repository_id": row.repository_id,
        "sha": row.sha,
        "state": row.state,
        "created_at": row.created_at.replace(tzinfo=UTC).isoformat(),
        "result": row.result,
        "findings": [{"id": f.id, **f.detail} for f in findings],
        "job": None
        if job is None
        else {
            "id": job.id,
            "state": job.state,
            "attempts": job.attempts,
            "cancel_requested": job.cancel_requested,
            "error_code": job.error_code,
        },
    }


@router.get("/repositories")
def list_repositories(db: DB, actor: Actor) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(Repository)
        .where(Repository.tenant_id == actor.tenant_id)
        .order_by(Repository.created_at.desc())
        .limit(100)
    )
    return [repository_view(row) for row in rows]


@router.get("/repositories/{repository_id}/head")
def repository_head(repository_id: str, request: Request, db: DB, actor: Actor) -> dict[str, str]:
    row = owned_repository(db, actor, repository_id)
    if row.fixture_id:
        return {"sha": fixture_sha(row.fixture_id), "mode": "local content digest"}
    if row.installation_id is None or row.provider_id is None:
        raise HTTPException(409, "repository identity missing")
    try:
        sha = request.app.state.github.commit_sha(
            row.installation_id, row.provider_id, row.owner, row.name
        )
        return {"sha": sha, "mode": "GitHub commit"}
    except GitHubError as error:
        raise HTTPException(503, error.code) from None


@router.post("/repositories", status_code=201)
def connect_repository(
    body: RepositoryInput, request: Request, db: DB, actor: Actor
) -> dict[str, Any]:
    provider_id: int | None = None
    if body.fixture_id:
        if not request.app.state.settings.fixture_mode:
            raise HTTPException(403, "fixtures disabled")
    else:
        installation = db.get(Installation, body.installation_id)
        if installation is None or installation.tenant_id != actor.tenant_id:
            raise HTTPException(404, "installation not found")
        try:
            candidates = request.app.state.github.repositories(installation.id)
        except GitHubError as error:
            raise HTTPException(503, error.code) from None
        match = next(
            (
                r
                for r in candidates
                if r["owner"].lower() == body.owner.lower()
                and r["name"].lower() == body.name.lower()
            ),
            None,
        )
        if match is None:
            raise HTTPException(403, "repository not accessible to installation")
        provider_id = int(match["id"])
    row = Repository(
        tenant_id=actor.tenant_id,
        owner=body.owner.lower(),
        name=body.name.lower(),
        fixture_id=body.fixture_id,
        installation_id=body.installation_id,
    )
    db.add(row)
    row.provider_id = provider_id
    try:
        db.flush()
        audit(db, actor, "repository.connected", row.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "repository already connected") from None
    return repository_view(row)


@router.get("/installations/{installation_id}/repositories")
def discover(installation_id: int, request: Request, db: DB, actor: Actor) -> list[dict[str, Any]]:
    installation = db.get(Installation, installation_id)
    if installation is None or installation.tenant_id != actor.tenant_id:
        raise HTTPException(404, "installation not found")
    try:
        result: list[dict[str, Any]] = request.app.state.github.repositories(installation.id)
        return result
    except GitHubError as error:
        raise HTTPException(503, error.code) from None


@router.post("/repositories/{repository_id}/scans", status_code=202)
def enqueue(
    repository_id: str, body: ScanInput, request: Request, db: DB, actor: Actor
) -> dict[str, Any]:
    owned_repository(db, actor, repository_id)
    existing = db.scalar(
        select(Scan).where(
            Scan.repository_id == repository_id,
            Scan.idempotency_key == body.idempotency_key,
        )
    )
    if existing:
        if existing.sha != body.sha:
            raise HTTPException(409, "idempotency key payload conflict")
        return scan_view(db, existing)
    row = Scan(
        tenant_id=actor.tenant_id,
        repository_id=repository_id,
        sha=body.sha,
        idempotency_key=body.idempotency_key,
    )
    db.add(row)
    try:
        db.flush()
        db.add(Job(scan_id=row.id))
        audit(db, actor, "scan.queued", row.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(Scan).where(
                Scan.repository_id == repository_id,
                Scan.idempotency_key == body.idempotency_key,
            )
        )
        if existing is None or existing.sha != body.sha:
            raise HTTPException(409, "idempotency conflict") from None
        return scan_view(db, existing)
    notify(request.app.state.settings.redis_url)
    return scan_view(db, row)


@router.get("/fixtures")
def fixture_catalog(request: Request, actor: Actor) -> list[dict[str, str]]:
    if not request.app.state.settings.fixture_mode:
        raise HTTPException(403, "fixtures disabled")
    return [{"id": name, "sha": fixture_sha(name), "mode": "local content digest"} for name in IDS]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: DB, actor: Actor) -> dict[str, Any]:
    return scan_view(db, owned_scan(db, actor, scan_id))


@router.get("/repositories/{repository_id}/scans")
def history(repository_id: str, db: DB, actor: Actor) -> list[dict[str, Any]]:
    owned_repository(db, actor, repository_id)
    rows = db.scalars(
        select(Scan)
        .where(Scan.repository_id == repository_id)
        .order_by(Scan.created_at.desc())
        .limit(100)
    )
    return [scan_view(db, row) for row in rows]


@router.post("/scans/{scan_id}/cancel")
def cancel(scan_id: str, db: DB, actor: Actor) -> dict[str, Any]:
    row = owned_scan(db, actor, scan_id)
    job = db.scalar(select(Job).where(Job.scan_id == row.id).with_for_update())
    if job is None or job.state not in {"queued", "running"}:
        raise HTTPException(409, "scan is terminal")
    job.cancel_requested = True
    if job.state == "queued":
        job.state = row.state = "cancelled"
    audit(db, actor, "scan.cancelled", row.id)
    db.commit()
    return scan_view(db, row)
