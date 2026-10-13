"""Pure ASGI body buffering with actual byte and wall-clock limits."""

import asyncio
import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class InputLimits:
    def __init__(self, app: ASGIApp, maximum: int = 16_384) -> None:
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        maximum = 1_000_000 if scope["path"] == "/webhooks/github" else self.maximum
        payload = bytearray()
        status = 413
        try:
            async with asyncio.timeout(15):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    payload.extend(message.get("body", b""))
                    if len(payload) > maximum:
                        raise OverflowError
                    if not message.get("more_body", False):
                        break
        except (OverflowError, TimeoutError):
            status = 408 if len(payload) <= maximum else 413
            body = json.dumps(
                {"detail": "request body timeout" if status == 408 else "request body limit"}
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(payload), "more_body": False}

        await self.app(scope, bounded_receive, send)
