"""Derive metrics from explicit labels and real scans, never from expected scores."""

import json
import os
import platform
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repoguard.config import Settings
from repoguard.fixtures import archive, fixture_sha
from repoguard.ingestion import read_archive
from repoguard.remediation import SUPPORTED, apply, propose
from repoguard.scanner import RULES, scan
from repoguard.scoring import score


def locations(findings: list[dict[str, Any]], rule: str) -> set[tuple[str, int]]:
    return {(f["path"], f["line"]) for f in findings if f["rule_id"] == rule}


def metrics(labels: dict[str, Any], analyses: dict[str, Any]) -> dict[str, Any]:
    results = {}
    for rule in RULES:
        tp = fp = fn = tn = negative_repositories = false_positive_repositories = scanned = 0
        for name, analysis in analyses.items():
            if analysis["coverage"][rule]["status"] != "scanned":
                continue
            scanned += 1
            expected = locations(labels[name], rule)
            found = locations(analysis["findings"], rule)
            tp += len(expected & found)
            fp += len(found - expected)
            fn += len(expected - found)
            if not expected:
                negative_repositories += 1
                false_positive_repositories += bool(found)
                tn += not found
        results[rule] = {
            "scanned_repositories": scanned,
            "unscanned_repositories": len(analyses) - scanned,
            "true_positive_locations": tp,
            "false_positive_locations": fp,
            "false_negative_locations": fn,
            "true_negative_repositories": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": false_positive_repositories / negative_repositories
            if negative_repositories
            else None,
            "negative_repositories": negative_repositories,
        }
    return results


def evaluate(iterations: int = 30, with_semgrep: bool = False) -> dict[str, Any]:
    if not 2 <= iterations <= 100:
        raise ValueError("iterations must be 2..100")
    labels_file = Path(__file__).resolve().parents[2] / "fixtures" / "labels.json"
    labels = json.loads(labels_file.read_text())["repositories"]
    archives = {name: archive(name) for name in labels}
    analyses: dict[str, Any] = {}
    latencies = []
    digests: dict[str, set[str]] = {name: set() for name in labels}
    settings = Settings(environment="test")
    # Warm up each path; measured region includes ingestion, config scan and scoring,
    # excludes archive preparation, HTTP, DB, queue, worker startup and Semgrep.
    for name, data in archives.items():
        analysis = scan(
            read_archive(data, fixture_sha(name), settings), semgrep_enabled=with_semgrep
        )
        analysis["score"] = score(analysis)
        analyses[name] = analysis
    started = time.perf_counter()
    for _ in range(iterations):
        for name, data in archives.items():
            sha = fixture_sha(name)
            clock = time.perf_counter()
            analysis = scan(read_archive(data, sha, settings), semgrep_enabled=with_semgrep)
            result = score(analysis)
            latencies.append((time.perf_counter() - clock) * 1000)
            digests[name].add(result["digest"])
    elapsed = time.perf_counter() - started
    proposed = resolved = 0
    for name, analysis in analyses.items():
        snapshot = read_archive(archives[name], fixture_sha(name), settings)
        for finding in analysis["findings"]:
            if finding["rule_id"] not in SUPPORTED:
                continue
            patch = propose(snapshot, finding)
            proposed += 1
            changed = scan(
                apply(snapshot, patch["artifact"], patch["digest"]), semgrep_enabled=False
            )
            resolved += not any(
                f["rule_id"] == finding["rule_id"] and f["path"] == finding["path"]
                for f in changed["findings"]
            )
    return {
        "schema_version": "evaluation/1",
        "with_semgrep": with_semgrep,
        "measured_at": datetime.now(UTC).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
        },
        "method": "warm single-process ZIP + config + score; "
        + ("pinned Semgrep CLI included; " if with_semgrep else "Semgrep excluded; ")
        + "no network/DB/queue/worker startup",
        "sample": {
            "repositories": len(labels),
            "iterations_per_repository": iterations,
            "measured_scans": len(latencies),
            "compressed_bytes": {name: len(data) for name, data in archives.items()},
        },
        "per_rule": metrics(labels, analyses),
        "scores": {
            name: {
                "sha": analysis["sha"],
                "value": analysis["score"]["value"],
                "coverage_points": analysis["score"]["coverage_points"],
                "digest": analysis["score"]["digest"],
            }
            for name, analysis in analyses.items()
        },
        "determinism": {
            name: {"unique_digests": len(values), "deterministic": len(values) == 1}
            for name, values in digests.items()
        },
        "latency_ms": {
            "median": statistics.median(latencies),
            "p95": statistics.quantiles(latencies, n=100, method="inclusive")[94],
            "minimum": min(latencies),
            "maximum": max(latencies),
        },
        "sequential_scans_per_second": len(latencies) / elapsed,
        "fixes": {
            "proposed": proposed,
            "statically_resolved": resolved,
            "static_resolution_rate": resolved / proposed if proposed else None,
            "isolated_validation_attempts": 0,
            "isolated_validation_success_rate": None,
            "status": (
                "BLOCKED: Docker/validator unavailable; static resolution is not validated success"
            ),
        },
        "limitations": [
            "Two simple fixtures, one positive and one negative repository per config rule; "
            "labels and implementation were co-developed.",
            "No claim of general precision/recall, CVE detection, worker throughput, "
            "live GitHub behavior or production latency.",
            "Semgrep coverage follows actual engine outcomes; unavailable/disabled controls "
            "have null accuracy metrics. External service and isolation gates remain blocked.",
        ],
    }


def report(result: dict[str, Any]) -> str:
    lines = [
        "# Measured fixture evaluation",
        "",
        f"Measured: {result['measured_at']}",
        "",
        "Reproduce with `uv run python scripts/evaluate.py "
        f"--iterations {result['sample']['iterations_per_repository']}"
        + (" --with-semgrep" if result["with_semgrep"] else "")
        + "`. "
        + "Machine-readable evidence: `artifacts/evaluation.json`.",
        "",
        f"Method: {result['method']}. Platform: {result['environment']['platform']}; "
        f"Python {result['environment']['python']}; "
        f"{result['environment']['logical_cpus']} logical CPUs.",
        "",
        f"Sample: {result['sample']['repositories']} labeled repositories, "
        f"{result['sample']['measured_scans']} measured scans. "
        "Each config rule has one positive and one negative repository. "
        "Exact file/line locations determine TP/FP/FN; FPR is negative repositories "
        "with any false positive / negative repositories scanned.",
        "",
        "| Rule | Scanned repos | TP / FP / FN | Precision | Recall | FPR |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for rule, metric in result["per_rule"].items():
        values = [
            "unmeasured" if metric[key] is None else f"{metric[key]:.3f}"
            for key in ["precision", "recall", "false_positive_rate"]
        ]
        lines.append(
            f"| {rule} | {metric['scanned_repositories']} | "
            f"{metric['true_positive_locations']} / {metric['false_positive_locations']} / "
            f"{metric['false_negative_locations']} | {' | '.join(values)} |"
        )
    latency = result["latency_ms"]
    scores = ", ".join(
        f"{name} {item['value']}/100 (coverage {item['coverage_points']})"
        for name, item in result["scores"].items()
    )
    deterministic = all(item["deterministic"] for item in result["determinism"].values())
    lines += [
        "",
        f"Measured median {latency['median']:.3f} ms; p95 {latency['p95']:.3f} ms; "
        f"sequential throughput {result['sequential_scans_per_second']:.2f} scans/s. "
        "This excludes worker startup, scheduling, database and network costs; "
        "fixture archive preparation is excluded. Semgrep mode includes its CLI startup. "
        "Throughput elapsed time includes "
        "fixture identity reads between timed scans.",
        "",
        f"Scores: {scores}. Each repository produced one identical digest "
        f"across repeats: {deterministic}.",
        "",
        f"Deterministic proposals: {result['fixes']['proposed']}; statically resolved "
        f"targeted findings: {result['fixes']['statically_resolved']}. "
        "Isolated validation attempts: 0; validated success rate unmeasured. "
        f"{result['fixes']['status']}.",
        "",
        "Limitations:",
        "",
    ]
    lines.extend("- " + limitation for limitation in result["limitations"])
    return "\n".join(lines) + "\n"
