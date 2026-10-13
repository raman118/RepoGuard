"""Dedicated approved branches, deterministic commits and existing-PR reconciliation."""

import base64
import hashlib
import re
from typing import Any
from urllib.parse import quote

from repoguard.github import GitHub, GitHubError
from repoguard.ingestion import Snapshot
from repoguard.models import Repository
from repoguard.remediation import PolicyError


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False
    ).hexdigest()


def create_pull_request(
    github: GitHub,
    repository: Repository,
    snapshot: Snapshot,
    artifact: dict[str, Any],
    digest: str,
    actor: str,
    date: str,
) -> str:
    if (
        repository.fixture_id
        or repository.installation_id is None
        or repository.provider_id is None
    ):
        raise PolicyError("fixture_has_no_remote_pull_request")
    prefix = f"/repos/{repository.owner}/{repository.name}"
    read_token = github.token(repository.installation_id, repository.provider_id)
    metadata = github.request("GET", prefix, read_token)
    base_branch = str(metadata["default_branch"])
    current = github.request("GET", prefix + "/commits/" + quote(base_branch, safe=""), read_token)
    if current["sha"] != snapshot.sha:
        raise PolicyError("base_branch_changed_rescan_required")
    token = github.token(repository.installation_id, repository.provider_id, write=True)
    branch = "repoguard/" + digest  # Full digest prevents short-prefix identity collisions.
    path = str(artifact["path"])
    content = snapshot.files[path]
    blob = github.request(
        "POST",
        prefix + "/git/blobs",
        token,
        {
            "content": base64.b64encode(content).decode(),
            "encoding": "base64",
        },
    )
    if blob["sha"] != git_blob_sha(content):
        raise PolicyError("github_blob_identity_mismatch")
    tree = github.request(
        "POST",
        prefix + "/git/trees",
        token,
        {
            "base_tree": current["commit"]["tree"]["sha"],
            "tree": [{"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]}],
        },
    )
    identity = {"name": "RepoGuard", "email": "repoguard@users.noreply.github.com", "date": date}
    commit = github.request(
        "POST",
        prefix + "/git/commits",
        token,
        {
            "message": "RepoGuard patch " + digest,
            "tree": tree["sha"],
            "parents": [snapshot.sha],
            "author": identity,
            "committer": identity,
        },
    )
    try:
        reference = github.request("GET", prefix + "/git/ref/heads/" + branch, token)
        if reference["object"]["sha"] != commit["sha"]:
            raise PolicyError("dedicated_branch_conflict")
    except GitHubError as error:
        if error.code != "github_http_404":
            raise
        try:
            github.request(
                "POST",
                prefix + "/git/refs",
                token,
                {"ref": "refs/heads/" + branch, "sha": commit["sha"]},
            )
        except GitHubError as create_error:
            if create_error.code != "github_http_422":
                raise
            reference = github.request("GET", prefix + "/git/ref/heads/" + branch, token)
            if reference["object"]["sha"] != commit["sha"]:
                raise PolicyError("dedicated_branch_conflict") from None
    # A moved base is checked again after remote branch creation; no PR if stale.
    if (
        github.request("GET", prefix + "/commits/" + quote(base_branch, safe=""), read_token)["sha"]
        != snapshot.sha
    ):
        raise PolicyError("base_branch_changed_rescan_required")
    existing = github.request(
        "GET",
        prefix
        + "/pulls?state=all&per_page=100&head="
        + quote(repository.owner + ":" + branch, safe="")
        + "&base="
        + quote(base_branch, safe=""),
        token,
    )
    if existing:
        return checked_pull_request(existing[0], repository, snapshot.sha, commit["sha"], branch)
    try:
        result = github.request(
            "POST",
            prefix + "/pulls",
            token,
            {
                "title": "RepoGuard: " + artifact["rule_id"],
                "head": branch,
                "base": base_branch,
                "body": (
                    f"Human-approved RepoGuard proposal.\n\nRule: {artifact['rule_id']}\n"
                    f"Patch digest: {digest}\nBase: {snapshot.sha}\nApproval actor: {actor}\n"
                    "Validation: isolated static checks and any detected tests.\n\n"
                    "Review workflow permissions/runtime suitability. "
                    "No automatic merge or deployment."
                ),
            },
        )
    except GitHubError as error:
        if error.code != "github_http_422":
            raise
        existing = github.request(
            "GET",
            prefix
            + "/pulls?state=all&per_page=100&head="
            + quote(repository.owner + ":" + branch, safe=""),
            token,
        )
        if not existing:
            raise
        result = existing[0]
    try:
        return checked_pull_request(result, repository, snapshot.sha, commit["sha"], branch)
    except PolicyError:
        if isinstance(result.get("number"), int) and result["number"] > 0:
            github.request(
                "PATCH", prefix + f"/pulls/{result['number']}", token, {"state": "closed"}
            )
        raise


def checked_pull_request(
    result: dict[str, Any], repository: Repository, base_sha: str, commit_sha: str, branch: str
) -> str:
    url = str(result.get("html_url", ""))
    if (
        re.fullmatch(
            rf"https://github\.com/{re.escape(repository.owner)}/{re.escape(repository.name)}/pull/[0-9]+",
            url,
            flags=re.I,
        )
        is None
        or result.get("base", {}).get("sha") != base_sha
        or result.get("head", {}).get("sha") != commit_sha
        or result.get("head", {}).get("ref") != branch
    ):
        raise PolicyError("pull_request_identity_or_base_changed")
    return url
