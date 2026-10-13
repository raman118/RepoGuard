"""Required CI service checks must fail rather than silently skip."""

import argparse
import os
import shutil


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("gate", choices=["services", "sandbox", "semgrep"])
    args = parser.parse_args()
    if args.gate == "semgrep":
        from repoguard.scanner import semgrep_binary

        if semgrep_binary() is None:
            raise SystemExit("Required Semgrep gate unavailable")
        return
    names = (
        ["REPOGUARD_TEST_POSTGRES_URL", "REPOGUARD_TEST_REDIS_URL"]
        if args.gate == "services"
        else ["REPOGUARD_TEST_VALIDATOR_IMAGE"]
    )
    if any(not os.getenv(name) for name in names):
        raise SystemExit("Required gate configuration missing")
    if args.gate == "sandbox" and not shutil.which("docker"):
        raise SystemExit("Required Docker gate unavailable")


if __name__ == "__main__":
    main()
