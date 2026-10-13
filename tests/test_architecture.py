from pathlib import Path


def test_architecture_security_and_api_contracts_are_explicit() -> None:
    architecture = Path("ARCHITECTURE.md").read_text()
    for term in [
        "mermaid",
        "tenant",
        "lease",
        "SHA",
        "unknown",
        "symlink",
        "HMAC",
        "Prompt injection",
        "no merge",
        "kernel",
        "PostgreSQL",
    ]:
        assert term in architecture
    contract = Path("docs/API.md").read_text()
    assert "Authorization: Bearer" in contract
    assert "/approve" in contract and "/cancel" in contract
