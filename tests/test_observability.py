import hashlib
import hmac
import json
import logging
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from repoguard.models import Installation, Job, Repository, Scan, WebhookDelivery


def test_signed_push_creates_one_durable_scan_and_atomic_delivery(client: TestClient) -> None:
    client.app.state.settings.webhook_secret = SecretStr("s" * 32)
    with client.app.state.sessions() as db:
        db.add(Installation(id=42, tenant_id="alpha"))
        db.flush()
        db.add(
            Repository(
                tenant_id="alpha", owner="owner", name="repo", installation_id=42, provider_id=7
            )
        )
        db.commit()
    body = json.dumps(
        {
            "installation": {"id": 42},
            "repository": {"id": 7},
            "ref": "refs/heads/main",
            "after": "a" * 40,
        }
    ).encode()
    delivery = str(uuid4())
    headers = {
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": "sha256=" + hmac.new(b"s" * 32, body, hashlib.sha256).hexdigest(),
    }
    assert (
        client.post("/webhooks/github", content=body, headers=headers).json()["status"]
        == "accepted"
    )
    assert (
        client.post("/webhooks/github", content=body, headers=headers).json()["status"]
        == "duplicate"
    )
    with client.app.state.sessions() as db:
        assert len(list(db.scalars(select(Scan)))) == 1
        assert len(list(db.scalars(select(Job)))) == 1
        assert db.get(WebhookDelivery, delivery)
    assert client.get("/v1/metrics").json()["jobs"]["queued"] == 1
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.get("/v1/metrics").json()["jobs"]["queued"] == 0


def test_health_correlation_and_logs_do_not_leak_headers_or_paths(
    client: TestClient, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="repoguard.events")
    request_id = str(uuid4())
    response = client.get("/health/ready", headers={"X-Request-ID": request_id})
    assert response.status_code == 200 and response.json()["notification_fallback"] is True
    assert response.headers["X-Request-ID"] == request_id
    client.get("/private-source-or-secret-token", headers={"X-Request-ID": "malicious-secret"})
    assert "alpha-token" not in caplog.text and "malicious-secret" not in caplog.text
    assert "private-source" not in caplog.text
    assert '"route": "unmatched"' in caplog.text


def test_permanent_job_failure_is_visible_in_metrics_and_history(
    client: TestClient, repository: str
) -> None:
    from repoguard.worker import run_once

    queued = client.post(
        f"/v1/repositories/{repository}/scans",
        json={"sha": "b" * 40, "idempotency_key": "failure-diagnostic"},
    ).json()
    run_once(client.app.state.sessions, client.app.state.settings, client.app.state.github)
    result = client.get(f"/v1/scans/{queued['id']}").json()
    assert result["state"] == "failed" and result["result"] is None
    assert result["job"]["error_code"] == "fixture_sha_mismatch"
    assert client.get("/v1/metrics").json()["jobs"]["failed"] == 1
    assert client.get(f"/v1/repositories/{repository}/scans").json()[0]["state"] == "failed"
