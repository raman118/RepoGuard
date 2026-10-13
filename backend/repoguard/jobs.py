"""Durable lease claims with optimistic fencing and bounded retry recovery."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from repoguard.models import Finding, Job, RuleVersion, Scan, utcnow
from repoguard.observability import emit


@dataclass(frozen=True)
class Lease:
    job_id: str
    scan_id: str
    token: str


def claim(factory: sessionmaker[Session], seconds: int) -> Lease | None:
    now = utcnow()
    eligible = and_(
        Job.cancel_requested.is_(False),
        Job.attempts < Job.max_attempts,
        or_(
            and_(Job.state == "queued", Job.available_at <= now),
            and_(Job.state == "running", Job.lease_until <= now),
        ),
    )
    with factory() as db:
        # Expired final attempts become terminal, preventing infinite jobs.
        exhausted = db.scalars(
            select(Job)
            .where(
                Job.state == "running",
                Job.lease_until <= now,
                or_(Job.attempts >= Job.max_attempts, Job.cancel_requested.is_(True)),
            )
            .with_for_update()
        )
        for job in exhausted:
            job.state = "cancelled" if job.cancel_requested else "failed"
            job.error_code = "lease_exhausted"
            scan = db.get(Scan, job.scan_id)
            if scan:
                scan.state = job.state
        candidate = db.scalar(select(Job.id).where(eligible).order_by(Job.available_at).limit(1))
        if candidate is None:
            db.commit()
            return None
        token = str(uuid4())
        changed = db.execute(
            update(Job)
            .where(Job.id == candidate, eligible)
            .values(
                state="running",
                attempts=Job.attempts + 1,
                lease_token=token,
                lease_until=now + timedelta(seconds=seconds),
                error_code=None,
            )
            .returning(Job.scan_id)
        ).scalar_one_or_none()
        if changed is None:
            db.commit()
            return None
        db.execute(update(Scan).where(Scan.id == changed).values(state="running"))
        db.commit()
        emit("job.claimed", job_id=candidate, scan_id=changed)
        return Lease(candidate, changed, token)


def finish(
    factory: sessionmaker[Session],
    lease: Lease,
    result: dict[str, Any] | None = None,
    error_code: str | None = None,
    retryable: bool = False,
) -> bool:
    with factory() as db:
        job = db.scalar(
            select(Job)
            .where(
                Job.id == lease.job_id,
                Job.lease_token == lease.token,
                Job.state == "running",
                Job.lease_until > utcnow(),
            )
            .with_for_update()
        )
        if job is None:
            return False
        scan = db.get(Scan, job.scan_id)
        assert scan is not None
        if job.cancel_requested:
            job.state = scan.state = "cancelled"
        elif error_code:
            job.error_code = error_code[:100]
            job.state = scan.state = (
                "queued" if retryable and job.attempts < job.max_attempts else "failed"
            )
            job.available_at = utcnow() + timedelta(seconds=2**job.attempts)
        else:
            if result and "findings" in result:
                for rule_id, definition in result["rule_versions"].items():
                    key = rule_id + "@" + definition["version"]
                    existing = db.get(RuleVersion, key)
                    if existing is None:
                        db.add(RuleVersion(id=key, definition=definition))
                    elif existing.definition != definition:
                        raise ValueError("rule_version_changed")
                db.flush()
                for detail in result["findings"]:
                    db.add(
                        Finding(
                            scan_id=scan.id,
                            fingerprint=detail["fingerprint"],
                            rule_version_id=detail["rule_id"] + "@" + detail["rule_version"],
                            detail=detail,
                        )
                    )
            scan.result = result
            job.state = scan.state = "succeeded"
        job.lease_token = None
        job.lease_until = None
        db.commit()
        emit(
            "job.finished",
            job_id=job.id,
            scan_id=scan.id,
            state=job.state,
            attempts=job.attempts,
            error_code=job.error_code,
        )
        return True
