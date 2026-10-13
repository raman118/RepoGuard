"""Create ignored local Compose credentials once, without printing their values."""

import secrets
from pathlib import Path


def main() -> None:
    target = Path(".env.compose")
    with target.open("x", encoding="utf-8") as stream:
        stream.write("REPOGUARD_LOCAL_DB_PASSWORD=" + secrets.token_urlsafe(32) + "\n")
    print("Created .env.compose (ignored). Existing files are never overwritten.")


if __name__ == "__main__":
    main()
