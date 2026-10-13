import copy
import random

import pytest

from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.scanner import RULES, finding, scan
from repoguard.scoring import score


def test_score_reproducibility_order_duplicates_and_explanation() -> None:
    analysis = scan(Snapshot(fixture_sha("vulnerable"), files("vulnerable")), semgrep_enabled=False)
    expected = score(analysis)
    assert expected["value"] == 37
    assert expected["coverage_points"] == 82.5
    assert expected["categories"]["security"]["status"] == "partial"
    assert expected["categories"]["deployment"]["earned_points"] == 6
    for seed in range(20):
        changed = copy.deepcopy(analysis)
        changed["findings"] *= 3
        random.Random(seed).shuffle(changed["findings"])
        changed["coverage"] = dict(reversed(list(changed["coverage"].items())))
        assert score(changed) == expected


def test_clean_unknown_and_saturation_boundaries() -> None:
    clean = scan(Snapshot(fixture_sha("clean"), files("clean")), semgrep_enabled=False)
    assert score(clean)["value"] == 82  # unsupported Python is not a pass
    empty = scan(Snapshot("a" * 40, {}))
    assert score(empty)["value"] == 0
    assert all(category["status"] == "unknown" for category in score(empty)["categories"].values())
    for rule in empty["coverage"]:
        empty["coverage"][rule] = {"status": "scanned", "reason": "test-supported"}
    assert score(empty)["value"] == 100
    empty["findings"] = [
        finding(rule, "file", line, "fixed evidence") for rule in RULES for line in range(1, 50)
    ]
    assert score(empty)["value"] == 0


def test_policy_rejects_unknown_or_tampered_finding() -> None:
    analysis = scan(Snapshot("a" * 40, {}))
    analysis["findings"] = [finding("RG-CI-PERMISSIONS", "ci.yml", 1, "permissions: write-all")]
    analysis["findings"][0]["severity"] = "low"
    with pytest.raises(ValueError, match="rule_contract"):
        score(analysis)
    analysis["coverage"].pop("RG-PY-SHELL")
    with pytest.raises(ValueError, match="coverage_contract"):
        score(analysis)


def test_conflicting_duplicates_rejected_in_both_orders() -> None:
    analysis = scan(Snapshot("a" * 40, {}))
    original = finding("RG-CI-TIMEOUT", "ci.yml", 1, "fixed evidence")
    changed = {**original, "severity": "high"}
    for items in [[original, changed], [changed, original]]:
        analysis["findings"] = items
        with pytest.raises(ValueError, match="finding_conflict"):
            score(analysis)
