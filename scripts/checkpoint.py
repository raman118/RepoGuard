"""Record honest harness transitions; Git commits are made separately."""

import argparse
import re
from datetime import datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("goal")
    parser.add_argument("status", choices=["IN_PROGRESS", "BLOCKED", "DONE"])
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--next", required=True)
    parser.add_argument("--commit", default="pending")
    args = parser.parse_args()
    if re.fullmatch(r"G\d{2}", args.goal) is None:
        parser.error("goal must be a canonical Gxx identifier")
    date = datetime.now().astimezone().isoformat(timespec="seconds")
    path = Path("GOALS.md")
    text = path.read_text()
    start = text.index(f"## {args.goal} ")
    end = text.find("\n## G", start + 1)
    end = len(text) if end == -1 else end
    section = text[start:end]
    if args.status == "DONE" and "[ ]" in section:
        parser.error("unmet acceptance criteria cannot be marked DONE")
    if args.status == "IN_PROGRESS":
        other_sections = text[:start] + text[end:]
        if "Status: IN_PROGRESS" in other_sections:
            parser.error("another goal is already IN_PROGRESS")
    for status in ["TODO", "IN_PROGRESS", "BLOCKED", "DONE"]:
        section = section.replace(f"Status: {status}", f"Status: {args.status}")
    if args.status == "DONE":
        section = section.replace("Completion commit: pending", f"Completion commit: {args.commit}")
    section += f"\n- Latest evidence: {args.evidence}\n"
    path.write_text(text[:start] + section + text[end:], encoding="utf-8")
    with Path("WORKLOG.md").open("a", encoding="utf-8") as stream:
        stream.write(
            f"\n## {args.goal} — {args.status} — {date}\n{args.evidence}\nNext: {args.next}\n"
        )
    state = Path("STATE.md")
    marker = "## Environment and remaining external gates\n"
    previous = state.read_text(encoding="utf-8") if state.exists() else ""
    environment = (
        previous.split(marker, 1)[1]
        if marker in previous
        else (
            "Inspect local tools and GOALS.md for remaining external gates. "
            "Follow AGENTS.md and current user constraints; no external success is implied.\n"
        )
    )
    state.write_text(
        "# Resumable state\n\n"
        f"Last checkpoint: {args.goal} {args.status}. Updated {date}.\n\n"
        f"## Current result\n{args.evidence}\n\n"
        f"## Exact next action / implementation plan\n{args.next}\n\n" + marker + environment,
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
