import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
import redis
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from repoguard.api import create_app
from repoguard.auth import token_digest
from repoguard.config import Settings
from repoguard.database import make_engine, sessions
from repoguard.fixtures import fixture_sha
from repoguard.jobs import claim
from repoguard.models import (
    AuditEvent,
    Base,
    Credential,
    Finding,
    Job,
    Proposal,
    Repository,
    Scan,
    Tenant,
)
from repoguard.notifications import notify
from repoguard.worker import run_once


@pytest.mark.services
def test_redis_notification() -> None:
    url = os.getenv("REPOGUARD_TEST_REDIS_URL")
    if not url:
        pytest.skip("BLOCKED: Redis URL unavailable")
    client = redis.Redis.from_url(url, socket_timeout=2)
    with client.pubsub() as subscriber:
        subscriber.subscribe("repoguard:jobs")
        assert subscriber.get_message(timeout=2)["type"] == "subscribe"
        assert notify(url)
        assert subscriber.get_message(timeout=2)["data"] == b"wake"
    client.close()


@pytest.mark.postgres
@pytest.mark.services
def test_postgres_concurrent_claim_is_unique() -> None:
    url = os.getenv("REPOGUARD_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("BLOCKED: PostgreSQL URL unavailable")
    engine = make_engine(url)
    factory = sessions(engine)
    Base.metadata.create_all(engine)
    tenant_id, repo_id, scan_id, job_id = [str(uuid4()) for _ in range(4)]
    try:
        with factory() as db:
            db.add(Tenant(id=tenant_id, name="concurrency-test"))
            db.flush()
            db.add(Repository(id=repo_id, tenant_id=tenant_id, owner="fixture", name=repo_id))
            db.flush()
            db.add(
                Scan(
                    id=scan_id,
                    tenant_id=tenant_id,
                    repository_id=repo_id,
                    sha="a" * 40,
                    idempotency_key=scan_id,
                )
            )
            db.flush()
            db.add(Job(id=job_id, scan_id=scan_id))
            db.commit()
        with ThreadPoolExecutor(max_workers=8) as pool:
            leases = list(pool.map(lambda _: claim(factory, 30), range(8)))
        assert sum(lease is not None and lease.job_id == job_id for lease in leases) == 1
    finally:
        with factory() as db:
            for model, identity in [
                (Job, job_id),
                (Scan, scan_id),
                (Repository, repo_id),
                (Tenant, tenant_id),
            ]:
                db.execute(delete(model).where(model.id == identity))
            db.commit()
        engine.dispose()


@pytest.mark.postgres
@pytest.mark.services
def test_postgres_fixture_scan_and_proposal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual migrated PostgreSQL/Redis -> worker -> findings/score -> denied approval."""
    url = os.getenv("REPOGUARD_TEST_POSTGRES_URL")
    redis_url = os.getenv("REPOGUARD_TEST_REDIS_URL")
    if not url or not redis_url:
        pytest.skip("BLOCKED: disposable PostgreSQL and Redis unavailable")
    monkeypatch.setenv("REPOGUARD_DATABASE_URL", url)
    command.upgrade(Config("alembic.ini"), "head")
    app = create_app(Settings(environment="test", database_url=url, redis_url=redis_url))
    tenant_id = str(uuid4())
    token = "local-service-test-" + str(uuid4())
    try:
        with app.state.sessions() as db:
            db.add(Tenant(id=tenant_id, name="service-vertical-slice"))
            db.flush()
            db.add(Credential(digest=token_digest(token), tenant_id=tenant_id, actor="tester"))
            db.commit()
        with TestClient(app) as client:
            client.headers["Authorization"] = "Bearer " + token
            readiness = client.get("/health/ready")
            assert readiness.status_code == 200 and readiness.json()["redis"] is True
            repository = client.post(
                "/v1/repositories",
                json={
                    "owner": "fixture",
                    "name": "vulnerable",
                    "fixture_id": "vulnerable",
                },
            )
            assert repository.status_code == 201
            repository_id = repository.json()["id"]
            queued = client.post(
                f"/v1/repositories/{repository_id}/scans",
                json={
                    "sha": fixture_sha("vulnerable"),
                    "idempotency_key": str(uuid4()),
                },
            )
            assert queued.status_code == 202
            scan_id = queued.json()["id"]
            assert run_once(app.state.sessions, app.state.settings, app.state.github)
            result = client.get(f"/v1/scans/{scan_id}").json()
            assert result["state"] == "succeeded"
            assert result["result"]["coverage"]["RG-PY-SHELL"]["status"] == "scanned"
            assert result["result"]["score"]["value"] == 41
            assert len(result["findings"]) == 7
            finding = next(row for row in result["findings"] if row["rule_id"] == "RG-CI-TIMEOUT")
            proposal = client.post(
                f"/v1/scans/{scan_id}/proposals",
                json={
                    "finding_id": finding["id"],
                },
            )
            assert proposal.status_code == 201
            patch = proposal.json()
            assert "timeout-minutes: 15" in patch["artifact"]["diff"]
            assert (
                client.post(
                    f"/v1/proposals/{patch['id']}/approve",
                    json={
                        "digest": patch["digest"],
                    },
                ).status_code
                == 409
            )
            assert client.post(f"/v1/proposals/{patch['id']}/validate", json={}).status_code == 503
    finally:
        with app.state.sessions() as db:
            scans = select(Scan.id).where(Scan.tenant_id == tenant_id)
            for model in [Proposal, Finding, Job]:
                db.execute(delete(model).where(model.scan_id.in_(scans)))
            for model in [AuditEvent, Scan, Repository, Credential]:
                db.execute(delete(model).where(model.tenant_id == tenant_id))
            db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            db.commit()
        app.state.engine.dispose()
