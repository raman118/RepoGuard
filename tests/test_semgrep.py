import pytest

from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.scanner import semgrep_binary, semgrep_scan


def test_real_semgrep_rule_against_labeled_fixtures() -> None:
    if not semgrep_binary():
        pytest.skip("BLOCKED: supported Semgrep CLI unavailable")
    findings = semgrep_scan(Snapshot(fixture_sha("vulnerable"), files("vulnerable")))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RG-PY-SHELL"
    assert findings[0]["path"] == "app.py"
    assert semgrep_scan(Snapshot(fixture_sha("clean"), files("clean"))) == []
