import pytest

from repoguard.models import Repository
from repoguard.pull_requests import checked_pull_request
from repoguard.remediation import PolicyError


@pytest.mark.parametrize(
    "change",
    [
        {"html_url": "javascript:alert('x')"},
        {"base": {"sha": "moved"}},
        {"head": {"sha": "other", "ref": "repoguard/digest"}},
    ],
)
def test_returned_pr_cannot_escape_validated_identity(change: dict) -> None:
    valid = {
        "html_url": "https://github.com/owner/repo/pull/1",
        "base": {"sha": "base"},
        "head": {"sha": "commit", "ref": "repoguard/digest"},
    }
    with pytest.raises(PolicyError):
        checked_pull_request(
            {**valid, **change},
            Repository(owner="owner", name="repo"),
            "base",
            "commit",
            "repoguard/digest",
        )
