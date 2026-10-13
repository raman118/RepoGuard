"""Trusted analysis subprocess: stdin is bounded snapshot data, never executable code."""

import base64
import json
import sys

from repoguard.ingestion import Snapshot
from repoguard.scanner import scan
from repoguard.scoring import score


def main() -> None:
    raw = sys.stdin.buffer.read(60_000_001)
    if len(raw) > 60_000_000:
        raise ValueError("analysis_input_limit")
    payload = json.loads(raw)
    files = {
        path: base64.b64decode(content, validate=True) for path, content in payload["files"].items()
    }
    result = scan(Snapshot(payload["sha"], files))
    result["score"] = score(result)
    sys.stdout.buffer.write(json.dumps(result, sort_keys=True).encode())


if __name__ == "__main__":
    main()
