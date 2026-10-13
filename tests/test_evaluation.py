import copy
import json
from pathlib import Path

from repoguard.evaluation import evaluate, metrics
from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.scanner import scan


def test_evaluation_derives_exact_metrics_and_distinguishes_validation() -> None:
    result = evaluate(2)
    assert result["sample"]["measured_scans"] == 4
    assert result["per_rule"]["RG-CI-TIMEOUT"]["true_positive_locations"] == 1
    assert result["per_rule"]["RG-CI-TIMEOUT"]["precision"] == 1
    assert result["per_rule"]["RG-PY-SHELL"]["recall"] is None
    assert result["fixes"]["proposed"] == 2 and result["fixes"]["statically_resolved"] == 2
    assert result["fixes"]["isolated_validation_success_rate"] is None
    assert all(row["deterministic"] for row in result["determinism"].values())


def test_wrong_location_is_false_positive_and_false_negative() -> None:
    labels = json.loads(Path("fixtures/labels.json").read_text())["repositories"]
    analysis = scan(Snapshot(fixture_sha("vulnerable"), files("vulnerable")), semgrep_enabled=False)
    changed = copy.deepcopy(analysis)
    next(f for f in changed["findings"] if f["rule_id"] == "RG-CI-TIMEOUT")["line"] = 99
    metric = metrics(labels, {"vulnerable": changed})["RG-CI-TIMEOUT"]
    assert metric["true_positive_locations"] == 0
    assert metric["false_positive_locations"] == metric["false_negative_locations"] == 1
