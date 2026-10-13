import hashlib
import hmac
import json
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from repoguard.config import Settings
from repoguard.github import GitHub, GitHubError, token_expiry_example
from repoguard.models import Installation


def adapter(handler: object) -> GitHub:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return GitHub(
        Settings(github_app_id=123, github_private_key=SecretStr(pem)),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_jwt_scoped_token_cache_and_pagination() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            claims = jwt.decode(
                request.headers["authorization"].split()[1], options={"verify_signature": False}
            )
            assert claims["exp"] - claims["iat"] <= 600
            assert claims["iss"] == "123"
            return httpx.Response(
                201, json={"token": "fixture-token", "expires_at": token_expiry_example()}
            )
        row = {"id": 7, "owner": {"login": "owner"}, "name": "repo", "default_branch": "main"}
        return httpx.Response(
            200, json={"repositories": [row] * (100 if request.url.params["page"] == "1" else 1)}
        )

    github = adapter(handler)
    assert len(github.repositories(42)) == 101
    assert github.token(42) == "fixture-token"
    assert len([call for call in calls if call.method == "POST"]) == 1
    github.token(42, 7, write=True)
    payload = json.loads(calls[-1].content)
    assert payload["repository_ids"] == [7]
    assert payload["permissions"]["pull_requests"] == "write"
    github.invalidate(42)
    github.token(42)
    assert len([call for call in calls if call.method == "POST"]) == 3


def test_adapter_errors_are_sanitized_and_fixed_host() -> None:
    github = adapter(lambda _: httpx.Response(429, text="secret-repository-source"))
    with pytest.raises(GitHubError, match="github_http_429") as caught:
        github.token(42)
    assert caught.value.retryable
    assert "secret" not in str(caught.value)
    with pytest.raises(GitHubError, match="path_invalid"):
        github.request("GET", "//evil.test/token", "sensitive")
    with pytest.raises(GitHubError, match="repository_scope_required"):
        github.token(42, write=True)


def test_signed_webhook_replay_and_tenant_discovery(client: TestClient) -> None:
    client.app.state.settings.webhook_secret = SecretStr("s" * 32)
    with client.app.state.sessions() as db:
        db.add(Installation(id=42, tenant_id="alpha"))
        db.commit()
    body = json.dumps({"installation": {"id": 42}}).encode()
    headers = {
        "x-github-delivery": str(uuid4()),
        "x-github-event": "ping",
        "x-hub-signature-256": "sha256=" + hmac.new(b"s" * 32, body, hashlib.sha256).hexdigest(),
    }
    assert (
        client.post("/webhooks/github", content=body, headers=headers).json()["status"]
        == "accepted"
    )
    assert (
        client.post("/webhooks/github", content=body, headers=headers).json()["status"]
        == "duplicate"
    )
    assert client.post("/webhooks/github", content=body + b" ", headers=headers).status_code == 401
    assert client.post("/webhooks/github", content=b"x" * 1_000_001).status_code == 413
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.get("/v1/installations/42/repositories").status_code == 404
    assert (
        client.post(
            "/v1/repositories", json={"owner": "x", "name": "y", "installation_id": 42}
        ).status_code
        == 404
    )
