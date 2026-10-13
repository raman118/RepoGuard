"""Policy v1: deterministic rational coverage and capped severity deductions."""

import hashlib
from fractions import Fraction
from typing import Any

from repoguard.scanner import RULES, canonical

POLICY_VERSION = "readiness/1"
WEIGHTS = {
    "security": 35,
    "reliability": 20,
    "deployment": 20,
    "dependencies": 15,
    "maintainability": 10,
}
PENALTIES = {"critical": 25, "high": 14, "medium": 7, "low": 3}


def score(analysis: dict[str, Any]) -> dict[str, Any]:
    if set(analysis["coverage"]) != set(RULES):
        raise ValueError("scoring_coverage_contract")
    findings: dict[bytes, dict[str, Any]] = {}
    for item in analysis["findings"]:
        identity = canonical(
            {key: item[key] for key in ("rule_id", "rule_version", "path", "line")}
        )
        if identity in findings and canonical(findings[identity]) != canonical(item):
            raise ValueError("scoring_finding_conflict")
        findings[identity] = item
    for finding in findings.values():
        rule = RULES.get(finding["rule_id"])
        if (
            rule is None
            or rule.version != finding["rule_version"]
            or rule.severity != finding["severity"]
            or rule.category != finding["category"]
        ):
            raise ValueError("scoring_rule_contract")
    categories: dict[str, Any] = {}
    earned_total = Fraction(0)
    coverage_total = Fraction(0)
    for category, weight in WEIGHTS.items():
        rules = [rule.id for rule in RULES.values() if rule.category == category]
        scanned = [rule for rule in rules if analysis["coverage"][rule]["status"] == "scanned"]
        coverage = Fraction(len(scanned), len(rules))
        available = weight * coverage
        deductions = [
            {
                "rule_id": f["rule_id"],
                "path": f["path"],
                "line": f["line"],
                "points": PENALTIES[f["severity"]],
            }
            for _, f in sorted(findings.items())
            if f["category"] == category
        ]
        earned = max(Fraction(0), available - sum(d["points"] for d in deductions))
        earned_total += earned
        coverage_total += available
        categories[category] = {
            "weight": weight,
            "status": "scanned"
            if len(scanned) == len(rules)
            else "partial"
            if scanned
            else "unknown",
            "rules_scanned": len(scanned),
            "rules_total": len(rules),
            "available_points": float(available),
            "earned_points": float(earned),
            "deductions": deductions,
        }
    manifest = {
        "policy_version": POLICY_VERSION,
        "engine_version": analysis["engine_version"],
        "weights": WEIGHTS,
        "penalties": PENALTIES,
        "rule_versions": analysis["rule_versions"],
        "coverage": analysis["coverage"],
        "findings": [value for _, value in sorted(findings.items())],
        "sha": analysis["sha"],
    }
    return {
        "value": int(earned_total),
        "maximum": 100,
        "policy_version": POLICY_VERSION,
        "coverage_points": float(coverage_total),
        "categories": categories,
        "digest": hashlib.sha256(canonical(manifest)).hexdigest(),
        "limitation": (
            "Only supported versioned controls; unknown coverage earns zero. "
            "Not a production safety certification."
        ),
    }
