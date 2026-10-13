# Isolated validation and human-approved PRs

The API never has Docker access. Run the trusted validator service only on a dedicated disposable Linux worker host; its Docker daemon is a privileged trust boundary. Configure a >=32-character shared secret, digest-pinned locally preloaded validator image and TLS internal URL. Local loopback HTTP is allowed only outside production. `uv run uvicorn repoguard.validator_service:create_validator --factory` starts the controller; do not expose it publicly or give it GitHub/database credentials.

Build `docker build -f sandbox/Dockerfile -t repoguard-validator .`, then configure its immutable local image ID (`sha256:<64 hex>`) or a preloaded registry digest (`repository@sha256:<64 hex>`). Runtime rejects mutable tags and will not pull an image. Container profile: Linux with effective cgroup memory/swap/PID/CPU support, nonroot 10001, read-only root, no network, no capabilities, no new privileges, no binds, limited tmpfs work/tmp, memory+swap 256MiB, one CPU, 64 PIDs, file/FD limits, no persisted container logs, 40-second deadline and 32KiB controller output cap. Cleanup addresses only generated container names. No API accepts commands, images or mounts.

On a dedicated local Linux-container Docker host, the real gate needs no registry or GitHub access:

```powershell
docker build -f sandbox/Dockerfile -t repoguard-validator:local .
$env:REPOGUARD_TEST_VALIDATOR_IMAGE = docker image inspect repoguard-validator:local --format '{{.Id}}'
uv run python scripts/verify.py --scope sandbox
```

The tests check actual nonroot execution, cgroup limits, blocked network/host files and infinite-test termination. A mutable build tag is used only to obtain the immutable ID; the controller receives that ID. Passing local policy tests does not replace this required runtime gate. The platform Compose stack deliberately has no Docker access; configure its validator URL/secret only after verifying this separate host. Under the current user constraint, keep all PR publication/live GitHub actions disabled.

Trusted container entrypoint parses Python AST/workflow YAML and runs fixed pytest invocation only if a tests directory exists, inside isolation. No dependency installation, repository scripts or inferred shell commands. Test dependencies must be prebuilt into a reviewed image. Test absence is `not_present`, not passing tests. Syntax/tests do not prove runtime safety or test quality. Host-side deterministic analysis verifies targeted findings resolve; controller attestation is authenticated and bound to fresh nonce, full SHA and patch digest. Unavailable/failed/mismatched isolation prevents approval.

Explicit authenticated human approval requires the exact validated digest. A separate action creates a dedicated `repoguard/<full digest>` branch/PR, with deterministic commit identity, repository-scoped write token, retry reconciliation, current-base checks and audit event. Fixture proposals cannot create remote PRs. Repository workflow fixes require additional Workflows write permission; request it only on the scoped PR token. Creating a branch/PR may trigger GitHub's configured workflows; human review must account for this. RepoGuard never calls merge/deploy APIs.

Local tests prove policy, signed-attestation handling, denial states, and mocked branch/PR retry flow. Real container validation and explicitly approved live PR remain BLOCKED here: no Docker or GitHub App credentials. `uv run pytest -m sandbox` requires `REPOGUARD_TEST_VALIDATOR_IMAGE` and a working isolated Linux daemon. Do not interpret mock attestations as Docker verification. Base checks reduce races, but GitHub does not offer atomic base-branch locking across PR creation; review the resulting PR against its displayed base before merge.
