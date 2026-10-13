"""Fixed-host GitHub adapter; credentials never enter logs or durable artifacts."""

import json
import re
import threading
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt

from repoguard.config import Settings

API = "https://api.github.com"


class GitHubError(Exception):
    def __init__(self, code: str, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class GitHub:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(timeout=20, follow_redirects=False)
        self._tokens: dict[tuple[int, int | None, bool], tuple[str, float]] = {}
        self._lock = threading.RLock()

    def app_jwt(self) -> str:
        key = self.settings.github_private_key
        if key is None or self.settings.github_app_id is None:
            raise GitHubError("github_not_configured")
        now = int(time.time())
        try:
            return jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": str(self.settings.github_app_id)},
                key.get_secret_value(),
                algorithm="RS256",
            )
        except (ValueError, jwt.PyJWTError):
            raise GitHubError("github_key_invalid") from None

    def request(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/") or path.startswith("//") or ".." in path:
            raise GitHubError("github_path_invalid")
        try:
            with self.client.stream(
                method,
                API + path,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            ) as response:
                if response.status_code >= 300:
                    if response.status_code == 401:
                        with self._lock:
                            self._tokens.clear()
                    raise GitHubError(
                        f"github_http_{response.status_code}",
                        retryable=response.status_code in {403, 429} or response.status_code >= 500,
                    )
                data = bytearray()
                deadline = time.monotonic() + 30
                for chunk in response.iter_bytes(65536):
                    data.extend(chunk)
                    if len(data) > 2_000_000:
                        raise GitHubError("github_response_limit")
                    if time.monotonic() > deadline:
                        raise GitHubError("github_timeout", retryable=True)
        except httpx.HTTPError:
            raise GitHubError("github_transport", retryable=True) from None
        try:
            return json.loads(data)
        except (ValueError, RecursionError):
            raise GitHubError("github_response_invalid") from None

    def token(
        self, installation: int, repository_id: int | None = None, write: bool = False
    ) -> str:
        cache_key = (installation, repository_id, write)
        with self._lock:
            cached = self._tokens.get(cache_key)
            if cached and cached[1] > time.time() + 120:
                return cached[0]
            body: dict[str, Any] = {
                "permissions": {"contents": "write" if write else "read", "metadata": "read"},
            }
            if write:
                if repository_id is None:
                    raise GitHubError("repository_scope_required")
                body["permissions"]["pull_requests"] = "write"
                body["permissions"]["workflows"] = "write"
            if repository_id is not None:
                body["repository_ids"] = [repository_id]
            result = self.request(
                "POST", f"/app/installations/{installation}/access_tokens", self.app_jwt(), body
            )
            try:
                token = str(result["token"])
                expiry = datetime.fromisoformat(
                    result["expires_at"].replace("Z", "+00:00")
                ).timestamp()
                if not token or expiry <= time.time() + 120:
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise GitHubError("github_token_invalid") from None
            # Bound cache even when an operator manages many installations.
            if len(self._tokens) >= 100:
                self._tokens.clear()
            self._tokens[cache_key] = (token, expiry)
            return token

    def invalidate(self, installation: int) -> None:
        with self._lock:
            self._tokens = {
                key: value for key, value in self._tokens.items() if key[0] != installation
            }

    def repositories(self, installation: int) -> list[dict[str, Any]]:
        token = self.token(installation)
        rows: list[dict[str, Any]] = []
        for page in range(1, 21):
            result = self.request(
                "GET", f"/installation/repositories?per_page=100&page={page}", token
            )
            batch = result.get("repositories") if isinstance(result, dict) else None
            if not isinstance(batch, list) or len(batch) > 100:
                raise GitHubError("github_response_invalid")
            for row in batch:
                try:
                    rows.append(
                        {
                            "id": int(row["id"]),
                            "owner": str(row["owner"]["login"]),
                            "name": str(row["name"]),
                            "default_branch": str(row["default_branch"]),
                        }
                    )
                except (KeyError, TypeError, ValueError):
                    raise GitHubError("github_response_invalid") from None
            if len(batch) < 100:
                return rows
        raise GitHubError("github_pagination_limit")

    def commit_sha(self, installation: int, provider_id: int, owner: str, name: str) -> str:
        data = self.request(
            "GET",
            f"/repos/{owner}/{name}/commits?per_page=1",
            self.token(installation, provider_id),
        )
        try:
            sha = str(data[0]["sha"])
        except (KeyError, IndexError, TypeError):
            raise GitHubError("github_response_invalid") from None
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise GitHubError("github_sha_invalid")
        return sha


def token_expiry_example() -> str:
    """No credentials: useful to HTTP fixtures generating current expiry."""
    return datetime.fromtimestamp(time.time() + 3600, UTC).isoformat()
