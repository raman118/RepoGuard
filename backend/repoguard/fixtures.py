"""Allowlisted local datasets; contents are read as data, never imported."""

import hashlib
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "fixtures"
IDS = ("vulnerable", "clean")


def files(fixture_id: str) -> dict[str, bytes]:
    if fixture_id not in IDS:
        raise ValueError("fixture_unknown")
    root = ROOT / fixture_id
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def fixture_sha(fixture_id: str) -> str:
    # Fixture identity is a content digest, clearly not a GitHub commit claim.
    digest = hashlib.sha1(usedforsecurity=False)
    for path, content in sorted(files(fixture_id).items()):
        digest.update(path.encode() + b"\0" + content + b"\0")
    return digest.hexdigest()


def archive(fixture_id: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
        for path, content in files(fixture_id).items():
            target.writestr(f"snapshot/{path}", content)
    return buffer.getvalue()
