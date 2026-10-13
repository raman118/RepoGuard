import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from repoguard.database import make_engine
from repoguard.models import AuditEvent, Job, Repository


def test_auth_tenancy_and_atomic_enqueue(client: TestClient, repository: str) -> None:
    body = {"sha": "a" * 40, "idempotency_key": "once"}
    first = client.post(f"/v1/repositories/{repository}/scans", json=body)
    assert first.status_code == 202
    scan_id = first.json()["id"]
    assert client.post(f"/v1/repositories/{repository}/scans", json=body).json()["id"] == scan_id
    assert (
        client.post(
            f"/v1/repositories/{repository}/scans", json={**body, "sha": "b" * 40}
        ).status_code
        == 409
    )
    assert client.get(f"/v1/scans/{scan_id}").json()["job"]["state"] == "queued"
    with client.app.state.sessions() as db:
        assert len(list(db.scalars(select(Job)))) == 1
        assert len(list(db.scalars(select(AuditEvent)))) == 2
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.get("/v1/repositories").json() == []
    assert client.get(f"/v1/scans/{scan_id}").status_code == 404
    assert client.post(f"/v1/scans/{scan_id}/cancel").status_code == 404
    assert client.post(f"/v1/repositories/{repository}/scans", json=body).status_code == 404
    client.headers.clear()
    assert client.get("/v1/repositories").status_code == 401


def test_validation_duplicate_and_cancel(client: TestClient, repository: str) -> None:
    assert (
        client.post(
            "/v1/repositories",
            json={
                "owner": "fixture",
                "name": "vulnerable",
                "fixture_id": "vulnerable",
            },
        ).status_code
        == 409
    )
    for bad in ["main", "a" * 39, "../../etc/passwd", "A" * 40]:
        assert (
            client.post(
                f"/v1/repositories/{repository}/scans",
                json={
                    "sha": bad,
                    "idempotency_key": "invalid",
                },
            ).status_code
            == 422
        )
    scan = client.post(
        f"/v1/repositories/{repository}/scans",
        json={
            "sha": "a" * 40,
            "idempotency_key": "cancel",
        },
    ).json()
    assert client.post(f"/v1/scans/{scan['id']}/cancel").json()["state"] == "cancelled"
    assert client.post(f"/v1/scans/{scan['id']}/cancel").status_code == 409
    assert len(client.get(f"/v1/repositories/{repository}/scans").json()) == 1


def test_migration_matches_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("REPOGUARD_DATABASE_URL", url)
    command.upgrade(Config("alembic.ini"), "head")
    engine = make_engine(url)
    tables = set(inspect(engine).get_table_names())
    assert {"repositories", "scans", "findings", "jobs", "audit_events", "rule_versions"} <= tables
    assert {x["name"] for x in inspect(engine).get_columns("repositories")} == set(
        Repository.__table__.columns.keys()
    )
    command.check(Config("alembic.ini"))
    command.downgrade(Config("alembic.ini"), "base")
    assert inspect(engine).get_table_names() == ["alembic_version"]
    engine.dispose()


@pytest.mark.postgres
def test_postgres_migration(monkeypatch: pytest.MonkeyPatch) -> None:
    url = os.getenv("REPOGUARD_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("BLOCKED: disposable PostgreSQL URL unavailable")
    # Only run against a dedicated disposable DB; never drop production schema.
    monkeypatch.setenv("REPOGUARD_DATABASE_URL", url)
    command.upgrade(Config("alembic.ini"), "head")
    command.check(Config("alembic.ini"))
