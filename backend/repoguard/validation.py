"""Signed validator client. Missing or mismatched isolation never becomes passing."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import uuid4

import httpx

from repoguard.config import Settings
from repoguard.ingestion import Snapshot
from repoguard.remediation import PolicyError
from repoguard.scanner import canonical


def signature(secret: str, data: bytes) -> str:
    return hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()


class ValidatorClient:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(timeout=55, follow_redirects=False)

    def validate(self, snapshot: Snapshot, digest: str) -> dict[str, Any]:
        settings = self.settings
        if settings.validator_url is None or settings.validator_secret is None:
            raise PolicyError("isolation_unavailable")
        url = httpx.URL(settings.validator_url)
        if url.scheme != "https" and not (
            settings.environment != "production" and url.host in {"127.0.0.1", "localhost"}
        ):
            raise PolicyError("validator_endpoint_denied")
        payload = canonical(
            {
                "sha": snapshot.sha,
                "digest": digest,
                "nonce": str(uuid4()),
                "timestamp": int(time.time()),
                "files": {
                    path: base64.b64encode(content).decode()
                    for path, content in snapshot.files.items()
                },
            }
        )
        secret = settings.validator_secret.get_secret_value()
        try:
            with self.client.stream(
                "POST",
                str(url).rstrip("/") + "/internal/validate",
                content=payload,
                headers={
                    "X-RepoGuard-Signature": signature(secret, payload),
                    "Authorization": "Bearer " + signature(secret, b"repoguard-validator-access"),
                    "Content-Type": "application/json",
                },
            ) as response:
                if response.status_code != 200:
                    raise PolicyError("isolation_unavailable")
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > 8192:
                        raise PolicyError("validator_response_limit")
                supplied = response.headers.get("X-RepoGuard-Signature", "")
            if not hmac.compare_digest(signature(secret, bytes(data)), supplied):
                raise PolicyError("validator_signature_invalid")
            result: dict[str, Any] = json.loads(data)
            request_nonce = json.loads(payload)["nonce"]
            if (
                result.get("digest") != digest
                or result.get("sha") != snapshot.sha
                or result.get("nonce") != request_nonce
                or result.get("status") not in {"passed", "failed"}
                or result.get("profile") != "isolated-static-and-tests/1"
            ):
                raise PolicyError("validator_attestation_invalid")
            return result
        except (httpx.HTTPError, ValueError, TypeError):
            raise PolicyError("isolation_unavailable") from None
