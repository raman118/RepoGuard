from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from repoguard.api import create_app
from repoguard.auth import token_digest
from repoguard.config import Settings
from repoguard.models import Base, Credential, Tenant


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(
        Settings(
            environment="test",
            database_url=f"sqlite:///{tmp_path / 'test.db'}",
            redis_url="redis://127.0.0.1:1/0",
        )
    )
    Base.metadata.create_all(app.state.engine)
    with app.state.sessions() as db:
        for name in ["alpha", "beta"]:
            tenant = Tenant(id=name, name=name)
            db.add(tenant)
            db.flush()
            db.add(Credential(digest=token_digest(name + "-token"), tenant_id=name, actor=name))
        db.commit()
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = "Bearer alpha-token"
        yield test_client
    app.state.engine.dispose()


@pytest.fixture
def repository(client: TestClient) -> str:
    response = client.post(
        "/v1/repositories",
        json={
            "owner": "fixture",
            "name": "vulnerable",
            "fixture_id": "vulnerable",
        },
    )
    assert response.status_code == 201
    return str(response.json()["id"])
