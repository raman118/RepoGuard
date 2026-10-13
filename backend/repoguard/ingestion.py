"""Bounded immutable archive reading; no source execution or user host paths."""

import io
import re
import stat
import time
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

import httpx

from repoguard.config import Settings
from repoguard.fixtures import archive, fixture_sha
from repoguard.github import GitHub, GitHubError
from repoguard.models import Repository


class IngestionError(Exception):
    pass


@dataclass(frozen=True)
class Snapshot:
    sha: str
    files: dict[str, bytes]


def safe_path(name: str) -> PurePosixPath:
    parts = name.split("/")
    if (
        not name
        or len(name) > 400
        or "\\" in name
        or ":" in name
        or name.startswith("/")
        or any(ord(c) < 32 for c in name)
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > 20
        or any(part.endswith((".", " ")) for part in parts)
        or any(
            part.split(".")[0].upper()
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *(f"COM{i}" for i in range(10)),
                *(f"LPT{i}" for i in range(10)),
            }
            for part in parts
        )
    ):
        raise IngestionError("archive_path_invalid")
    return PurePosixPath(name)


def read_archive(data: bytes, sha: str, settings: Settings) -> Snapshot:
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise IngestionError("snapshot_sha_invalid")
    if len(data) > settings.max_archive_bytes:
        raise IngestionError("archive_compressed_limit")
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    expanded = 0
    root: str | None = None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as source:
            members = source.infolist()
            if len(members) > settings.max_files * 2:
                raise IngestionError("archive_entry_limit")
            for member in members:
                # ZipInfo normalizes backslashes on Windows and truncates NULs;
                # validate the original archive name before trusting filename.
                safe_path(
                    member.orig_filename.rstrip("/") if member.is_dir() else member.orig_filename
                )
                name = member.filename.rstrip("/") if member.is_dir() else member.filename
                path = safe_path(name)
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or (member.flag_bits & 1):
                    raise IngestionError("archive_member_type_invalid")
                if root is None:
                    root = path.parts[0]
                if path.parts[0] != root:
                    raise IngestionError("archive_multiple_roots")
                collision = str(path).casefold()
                if collision in seen:
                    raise IngestionError("archive_duplicate_path")
                seen.add(collision)
                if member.is_dir():
                    continue
                if len(path.parts) < 2:
                    raise IngestionError("archive_missing_root")
                relative = "/".join(path.parts[1:])
                if len(result) >= settings.max_files:
                    raise IngestionError("archive_file_limit")
                expanded += member.file_size
                if (
                    member.file_size > settings.max_file_bytes
                    or expanded > settings.max_expanded_bytes
                ):
                    raise IngestionError("archive_expanded_limit")
                if member.file_size > max(member.compress_size, 1) * 200:
                    raise IngestionError("archive_ratio_limit")
                with source.open(member) as stream:
                    content = stream.read(settings.max_file_bytes + 1)
                if len(content) != member.file_size or len(content) > settings.max_file_bytes:
                    raise IngestionError("archive_size_mismatch")
                result[relative] = content
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError):
        raise IngestionError("archive_invalid") from None
    if not result:
        raise IngestionError("archive_empty")
    # Reject file-directory collisions independent of entry order.
    file_names = {name.casefold() for name in result}
    for name in file_names:
        if any(
            str(parent) in file_names
            for parent in PurePosixPath(name).parents
            if str(parent) != "."
        ):
            raise IngestionError("archive_path_collision")
    return Snapshot(sha, dict(sorted(result.items())))


def ingest(repository: Repository, sha: str, settings: Settings, github: GitHub) -> Snapshot:
    if repository.fixture_id:
        if not settings.fixture_mode or fixture_sha(repository.fixture_id) != sha:
            raise IngestionError("fixture_sha_mismatch")
        return read_archive(archive(repository.fixture_id), sha, settings)
    if repository.installation_id is None or repository.provider_id is None:
        raise IngestionError("repository_identity_missing")
    token = github.token(repository.installation_id, repository.provider_id)
    url = f"https://api.github.com/repos/{repository.owner}/{repository.name}/zipball/{sha}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    data = bytearray()
    deadline = time.monotonic() + settings.job_timeout_seconds
    try:
        for _ in range(3):
            with github.client.stream("GET", url, headers=headers) as response:
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    target = httpx.URL(location)
                    if (
                        target.scheme != "https"
                        or target.host != "codeload.github.com"
                        or target.port not in {None, 443}
                        or target.userinfo
                    ):
                        raise IngestionError("archive_redirect_denied")
                    headers = {}  # Installation token is never forwarded to another host.
                    url = location
                    continue
                if response.status_code != 200:
                    raise GitHubError(
                        f"github_http_{response.status_code}",
                        response.status_code >= 500 or response.status_code in {403, 429},
                    )
                for chunk in response.iter_bytes(65536):
                    if time.monotonic() > deadline:
                        raise GitHubError("archive_timeout", retryable=True)
                    data.extend(chunk)
                    if len(data) > settings.max_archive_bytes:
                        raise IngestionError("archive_compressed_limit")
                return read_archive(bytes(data), sha, settings)
    except httpx.HTTPError:
        raise GitHubError("github_transport", retryable=True) from None
    raise IngestionError("archive_redirect_limit")
