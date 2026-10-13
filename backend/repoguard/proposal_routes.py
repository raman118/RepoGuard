from datetime import UTC
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from repoguard.auth import DB, Actor
from repoguard.github import GitHubError
from repoguard.ingestion import IngestionError, Snapshot, ingest
from repoguard.models import Finding, Proposal, Repository, Scan, utcnow
from repoguard.pull_requests import create_pull_request
from repoguard.remediation import HTTPProposalProvider, PolicyError, apply, propose
from repoguard.routes import audit, owned_scan
from repoguard.scanner import scan as analyze
from repoguard.schemas import StrictModel

router = APIRouter(prefix="/v1")


class ProposalInput(StrictModel):
    finding_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


def view(row: Proposal) -> dict[str, Any]:
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "digest": row.digest,
        "artifact": row.artifact,
        "validation": row.validation,
        "validation_detail": row.validation_detail,
        "approved_by": row.approved_by,
        "pull_request_url": row.pull_request_url,
    }


@router.post("/scans/{scan_id}/proposals", status_code=201)
def create_proposal(
    scan_id: str, body: ProposalInput, request: Request, db: DB, actor: Actor
) -> dict[str, Any]:
    scan = owned_scan(db, actor, scan_id)
    if scan.state != "succeeded":
        raise HTTPException(409, "successful scan required")
    finding = db.scalar(
        select(Finding).where(Finding.id == body.finding_id, Finding.scan_id == scan.id)
    )
    if finding is None:
        raise HTTPException(404, "finding not found")
    repository = db.get(Repository, scan.repository_id)
    assert repository is not None
    try:
        snapshot = ingest(
            repository, scan.sha, request.app.state.settings, request.app.state.github
        )
        provider = (
            HTTPProposalProvider(request.app.state.settings)
            if request.app.state.settings.llm_enabled
            else None
        )
        patch = propose(snapshot, finding.detail, provider)
    except (IngestionError, PolicyError, ValueError) as error:
        raise HTTPException(
            422, str(error) if isinstance(error, PolicyError) else "proposal_source_invalid"
        ) from None
    except GitHubError as error:
        raise HTTPException(503, error.code) from None
    existing = db.scalar(
        select(Proposal).where(Proposal.scan_id == scan_id, Proposal.digest == patch["digest"])
    )
    if existing:
        return view(existing)
    row = Proposal(tenant_id=actor.tenant_id, scan_id=scan.id, **patch)
    db.add(row)
    try:
        db.flush()
        audit(db, actor, "proposal.created", row.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(Proposal).where(Proposal.scan_id == scan_id, Proposal.digest == patch["digest"])
        )
        if existing is None:
            raise HTTPException(409, "proposal identity conflict") from None
        return view(existing)
    return view(row)


class DigestInput(StrictModel):
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def owned_proposal(db: DB, actor: Actor, proposal_id: str) -> Proposal:
    row = db.scalar(
        select(Proposal)
        .where(Proposal.id == proposal_id, Proposal.tenant_id == actor.tenant_id)
        .with_for_update()
    )
    if row is None:
        raise HTTPException(404, "proposal not found")
    return row


def patched_source(row: Proposal, request: Request, db: DB) -> tuple[Snapshot, Repository, Scan]:
    scan = db.get(Scan, row.scan_id)
    assert scan is not None
    repository = db.get(Repository, scan.repository_id)
    assert repository is not None
    snapshot = ingest(repository, scan.sha, request.app.state.settings, request.app.state.github)
    return apply(snapshot, row.artifact, row.digest), repository, scan


@router.post("/proposals/{proposal_id}/validate")
def validate_proposal(proposal_id: str, request: Request, db: DB, actor: Actor) -> dict[str, Any]:
    row = owned_proposal(db, actor, proposal_id)
    if row.approved_by or row.pull_request_url:
        raise HTTPException(409, "approved proposal cannot be revalidated")
    try:
        snapshot, _, _ = patched_source(row, request, db)
        analysis = analyze(snapshot, semgrep_enabled=False)
        if (
            any(
                f["rule_id"] == row.artifact["rule_id"] and f["path"] == row.artifact["path"]
                for f in analysis["findings"]
            )
            or analysis["coverage"][row.artifact["rule_id"]]["status"] != "scanned"
        ):
            raise PolicyError("target_rule_not_resolved")
        detail = request.app.state.validator.validate(snapshot, row.digest)
        row.validation = detail["status"]
        row.validation_detail = detail
        audit(db, actor, "proposal.validated", row.id)
        db.commit()
    except PolicyError as error:
        row.validation = "unavailable"
        row.validation_detail = {"code": str(error)}
        db.commit()
        raise HTTPException(503, str(error)) from None
    except (IngestionError, GitHubError, ValueError):
        raise HTTPException(503, "validation_source_unavailable") from None
    return view(row)


@router.post("/proposals/{proposal_id}/approve")
def approve(proposal_id: str, body: DigestInput, db: DB, actor: Actor) -> dict[str, Any]:
    row = owned_proposal(db, actor, proposal_id)
    if (
        body.digest != row.digest
        or row.validation != "passed"
        or not row.validation_detail
        or row.validation_detail.get("digest") != row.digest
    ):
        raise HTTPException(409, "exact validated digest required")
    if row.approved_by is None:
        row.approved_by = actor.actor
        row.approved_at = utcnow()
        audit(db, actor, "proposal.human_approved", row.id)
        db.commit()
    return view(row)


@router.post("/proposals/{proposal_id}/pull-request")
def publish(
    proposal_id: str, body: DigestInput, request: Request, db: DB, actor: Actor
) -> dict[str, Any]:
    row = owned_proposal(db, actor, proposal_id)
    if body.digest != row.digest or row.validation != "passed" or row.approved_by is None:
        raise HTTPException(409, "human approval of validated exact digest required")
    if row.pull_request_url:
        return view(row)
    try:
        snapshot, repository, scan = patched_source(row, request, db)
        row.pull_request_url = create_pull_request(
            request.app.state.github,
            repository,
            snapshot,
            row.artifact,
            row.digest,
            row.approved_by,
            scan.created_at.replace(tzinfo=UTC).isoformat(),
        )
        audit(db, actor, "proposal.pull_request_created", row.id)
        db.commit()
    except PolicyError as error:
        raise HTTPException(409, str(error)) from None
    except (GitHubError, IngestionError, ValueError, KeyError, TypeError):
        raise HTTPException(503, "pull_request_creation_failed_retry_safe") from None
    return view(row)


@router.get("/proposals/{proposal_id}")
def get_proposal(proposal_id: str, db: DB, actor: Actor) -> dict[str, Any]:
    row = db.scalar(
        select(Proposal).where(Proposal.id == proposal_id, Proposal.tenant_id == actor.tenant_id)
    )
    if row is None:
        raise HTTPException(404, "proposal not found")
    return view(row)
