import argparse
import json
from pathlib import Path

from repoguard.evaluation import evaluate, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--with-semgrep", action="store_true")
    args = parser.parse_args()
    result = evaluate(args.iterations, args.with_semgrep)
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/evaluation.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    Path("docs/EVALUATION.md").write_text(report(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "latency_ms": result["latency_ms"],
                "scans_per_second": result["sequential_scans_per_second"],
                "fixes": result["fixes"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
