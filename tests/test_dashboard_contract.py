from fastapi.testclient import TestClient

from repoguard.fixtures import fixture_sha


def test_head_and_catalog_are_authenticated_fixture_identities(
    client: TestClient, repository: str
) -> None:
    catalog = client.get("/v1/fixtures").json()
    assert {entry["id"] for entry in catalog} == {"clean", "vulnerable"}
    assert all(entry["mode"] == "local content digest" for entry in catalog)
    head = client.get(f"/v1/repositories/{repository}/head")
    assert head.json() == {"sha": fixture_sha("vulnerable"), "mode": "local content digest"}
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.get(f"/v1/repositories/{repository}/head").status_code == 404


def test_production_fixture_catalog_is_not_available(client: TestClient) -> None:
    client.app.state.settings.fixture_mode = False
    assert client.get("/v1/fixtures").status_code == 403
    assert (
        client.post(
            "/v1/repositories", json={"owner": "fixture", "name": "clean", "fixture_id": "clean"}
        ).status_code
        == 403
    )
