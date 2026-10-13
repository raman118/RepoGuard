"""Deploy only on a dedicated disposable Linux validator host with Docker access."""

import asyncio
import base64
import hmac
import json
import re
import threading
import time
from collections import OrderedDict
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, Response

from repoguard.config import Settings
from repoguard.ingestion import IngestionError, Snapshot, safe_path
from repoguard.remediation import PolicyError
from repoguard.sandbox import run_container
from repoguard.scanner import canonical
from repoguard.validation import signature


def create_validator() -> FastAPI:
    settings = Settings()
    if (
        not settings.validator_secret
        or len(settings.validator_secret.get_secret_value()) < 32
        or not settings.validator_image
    ):
        raise ValueError("validator requires shared secret and pinned image")
    secret = settings.validator_secret.get_secret_value()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    seen: OrderedDict[str, float] = OrderedDict()
    lock = threading.Lock()
    slots = asyncio.Semaphore(2)

    @app.post("/internal/validate")
    async def validate(request: Request) -> Response:
        access = "Bearer " + signature(secret, b"repoguard-validator-access")
        if not hmac.compare_digest(access, request.headers.get("Authorization", "")):
            raise HTTPException(401, "invalid_validator_identity")
        try:
            await asyncio.wait_for(slots.acquire(), timeout=0.01)
        except TimeoutError:
            raise HTTPException(429, "validator_capacity") from None
        try:
            return await process_request(request)
        finally:
            slots.release()

    async def process_request(request: Request) -> Response:
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 60_000_000:
                raise HTTPException(413, "validation_input_limit")
        if not hmac.compare_digest(
            signature(secret, bytes(raw)), request.headers.get("X-RepoGuard-Signature", "")
        ):
            raise HTTPException(401, "invalid_signature")
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "sha",
                "digest",
                "nonce",
                "timestamp",
                "files",
            }:
                raise ValueError
            if (
                re.fullmatch(r"[0-9a-f]{40}", str(payload["sha"])) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(payload["digest"])) is None
            ):
                raise ValueError
            nonce = str(UUID(payload["nonce"]))
            if abs(time.time() - int(payload["timestamp"])) > 60:
                raise ValueError
            with lock:
                if nonce in seen:
                    raise HTTPException(409, "validation_replay")
                while seen and next(iter(seen.values())) < time.time() - 120:
                    seen.popitem(last=False)
                if len(seen) >= 1000:
                    raise HTTPException(429, "validator_capacity")
                seen[nonce] = time.time()
            if (
                not isinstance(payload["files"], dict)
                or not payload["files"]
                or len(payload["files"]) > settings.max_files
            ):
                raise ValueError
            files: dict[str, bytes] = {}
            total = 0
            for path, encoded in payload["files"].items():
                safe_path(path)
                content = base64.b64decode(encoded, validate=True)
                total += len(content)
                if len(content) > settings.max_file_bytes or total > settings.max_expanded_bytes:
                    raise ValueError
                files[path] = content
            snapshot = Snapshot(str(payload["sha"]), files)
            assert settings.validator_image is not None
            result: dict[str, Any] = await run_container(snapshot, settings.validator_image)
            result.update(
                {
                    "digest": payload["digest"],
                    "sha": snapshot.sha,
                    "nonce": nonce,
                    "profile": "isolated-static-and-tests/1",
                }
            )
            data = canonical(result)
            return Response(
                data,
                media_type="application/json",
                headers={"X-RepoGuard-Signature": signature(secret, data)},
            )
        except HTTPException:
            raise
        except PolicyError:
            raise HTTPException(503, "isolation_unavailable") from None
        except (ValueError, KeyError, TypeError, IngestionError, RecursionError):
            raise HTTPException(422, "validation_input_invalid") from None

    return app
