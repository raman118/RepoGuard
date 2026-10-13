"""Resolve public registry/action identities; never persist or print registry auth tokens."""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx


def main() -> None:
    images = {
        "python": "3.12-slim",
        "node": "24-alpine",
        "postgres": "17-alpine",
        "redis": "7-alpine",
    }
    result: dict = {"resolved_at": datetime.now(UTC).isoformat(), "images": {}, "actions": {}}
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        for name, tag in images.items():
            response = client.get(
                "https://auth.docker.io/token",
                params={
                    "service": "registry.docker.io",
                    "scope": f"repository:library/{name}:pull",
                },
            )
            response.raise_for_status()
            token = response.json()["token"]
            manifest = client.get(
                f"https://registry-1.docker.io/v2/library/{name}/manifests/{tag}",
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": (
                        "application/vnd.oci.image.index.v1+json, "
                        "application/vnd.docker.distribution.manifest.list.v2+json"
                    ),
                },
            )
            manifest.raise_for_status()
            digest = manifest.headers["Docker-Content-Digest"]
            if digest != "sha256:" + hashlib.sha256(manifest.content).hexdigest():
                raise ValueError("registry identity mismatch")
            result["images"][name] = f"{name}:{tag}@{digest}"
        for repository in ["actions/checkout", "actions/setup-node", "astral-sh/setup-uv"]:
            release = client.get(f"https://api.github.com/repos/{repository}/releases/latest")
            release.raise_for_status()
            tag = release.json()["tag_name"]
            commit = client.get(f"https://api.github.com/repos/{repository}/commits/{tag}")
            commit.raise_for_status()
            sha = commit.json()["sha"]
            if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                raise ValueError("action identity invalid")
            result["actions"][repository] = {"tag": tag, "sha": sha}
    Path("artifacts/hosting-pins.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
