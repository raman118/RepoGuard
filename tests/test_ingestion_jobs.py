import io
import stat
import zipfile
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from repoguard.config import Settings
from repoguard.fixtures import archive, fixture_sha
from repoguard.ingestion import IngestionError, read_archive
from repoguard.jobs import claim, finish
from repoguard.models import Job, utcnow


def zipped(entries: list[tuple[str, bytes]], mode: int | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as target:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            if mode:
                info.external_attr = mode << 16
            target.writestr(info, content)
    # Windows ZipInfo normalizes backslashes when writing; restore raw attack bytes.
    data = buffer.getvalue()
    for name, _ in entries:
        if "\\" in name:
            data = data.replace(name.replace("\\", "/").encode(), name.encode())
    return data


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/etc/passwd",
        "root/../escape",
        "C:/root/x",
        "root\\x",
        "root/NUL",
        "root/a/./b",
    ],
)
def test_archive_paths_rejected(name: str) -> None:
    with pytest.raises(IngestionError, match="path_invalid"):
        read_archive(zipped([(name, b"x")]), "a" * 40, Settings())


def test_archive_types_limits_duplicates_and_content() -> None:
    with pytest.raises(IngestionError, match="member_type"):
        read_archive(
            zipped([("root/link", b"/etc/passwd")], stat.S_IFLNK | 0o777), "a" * 40, Settings()
        )
    with pytest.raises(IngestionError, match="duplicate"):
        read_archive(zipped([("root/FILE", b"x"), ("root/file", b"y")]), "a" * 40, Settings())
    with pytest.raises(IngestionError, match="expanded_limit"):
        read_archive(zipped([("root/file", b"x" * 1025)]), "a" * 40, Settings(max_file_bytes=1024))
    with pytest.raises(IngestionError, match="path_collision"):
        read_archive(zipped([("root/a", b"x"), ("root/a/b", b"y")]), "a" * 40, Settings())
    result = read_archive(archive("vulnerable"), fixture_sha("vulnerable"), Settings())
    assert "Dockerfile" in result.files
    assert result.sha == fixture_sha("vulnerable")


def test_job_fencing_retry_recovery_and_cancel(client: TestClient, repository: str) -> None:
    response = client.post(
        f"/v1/repositories/{repository}/scans", json={"sha": "a" * 40, "idempotency_key": "lease"}
    )
    scan_id = response.json()["id"]
    factory = client.app.state.sessions
    first = claim(factory, 30)
    assert first is not None
    assert claim(factory, 30) is None
    with factory() as db:
        job = db.scalar(select(Job).where(Job.scan_id == scan_id))
        job.lease_until = utcnow() - timedelta(seconds=1)
        db.commit()
    second = claim(factory, 30)
    assert second is not None and second.token != first.token
    assert not finish(factory, first, {"stale": True})
    assert finish(factory, second, error_code="transport", retryable=True)
    assert client.get(f"/v1/scans/{scan_id}").json()["state"] == "queued"
    assert client.post(f"/v1/scans/{scan_id}/cancel").json()["state"] == "cancelled"
    assert claim(factory, 30) is None


def test_last_expired_attempt_is_terminal(client: TestClient, repository: str) -> None:
    response = client.post(
        f"/v1/repositories/{repository}/scans", json={"sha": "a" * 40, "idempotency_key": "exhaust"}
    )
    factory = client.app.state.sessions
    lease = claim(factory, 30)
    assert lease
    with factory() as db:
        job = db.get(Job, lease.job_id)
        job.attempts = job.max_attempts
        job.lease_until = utcnow() - timedelta(seconds=1)
        db.commit()
    assert claim(factory, 30) is None
    assert client.get(f"/v1/scans/{response.json()['id']}").json()["state"] == "failed"
