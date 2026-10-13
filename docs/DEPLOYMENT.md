# Container development and deployment gates

No container runtime or hosted deployment has been verified on this machine. Existing image/action pin evidence is recorded in `artifacts/hosting-pins.json`; it was produced before this session and has not been refreshed. No Git commands or GitHub requests were made in this session. Identity evidence does not prove runtime functionality or security. The pin-resolution utility contacts GitHub and must not be run under the current user constraint. Review/retest dependency updates separately.

With Docker Engine/Compose on Linux or Docker Desktop Linux containers:

```powershell
uv run python scripts/local_env.py
docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose up --build -d
docker compose --env-file .env.compose run --rm api python -m repoguard.cli create-tenant demo
docker compose --env-file .env.compose ps
```

Keep the printed bearer token privately. Open `http://127.0.0.1:3000`. Compose is intentionally local fixture mode with real PostgreSQL/Redis, migrated release job, bounded worker, health checks and loopback published ports. Database and Redis use persistent named volumes and internal data network; API/worker have egress for GitHub. API/worker/frontend drop capabilities/read-only roots and have explicit memory/CPU/PID budgets. No Docker socket is mounted. `docker compose down` stops the stack and preserves data. Do not delete volumes unless you explicitly intend to delete scans/identities/history.

For production, use separate immutable API/worker deployment instances, managed PostgreSQL/Redis private endpoints, TLS ingress, secret manager and fixture_mode=false/environment=production. Supply a strong webhook secret and provision tenants/installations after ownership verification. Remove published database/cache ports; limit egress and ingress, configure workload quotas and service timeouts. Scan worker needs only required App credentials and DB access; its analysis subprocess strips credentials. Frontend `REPOGUARD_API_URL` is server-only. Settings read process environment; `uv run --env-file <ignored-file> ...` loads an explicit environment for non-container local processes.

For service acceptance without installing database binaries on the host, run this separate disposable stack. It has no published ports, host mounts, durable volumes, or network egress, and cannot access the local demo database. Tests run as a nonroot user with read-only root and bounded temporary storage. Its database password is a fixed test value confined to this ephemeral internal network, not a production credential.

```powershell
docker compose -f compose.verify.yml config --quiet
docker compose -f compose.verify.yml up --build --abort-on-container-exit --exit-code-from checks
docker compose -f compose.verify.yml down
```

The checks require migration/schema consistency, competing PostgreSQL claims, Redis wakeups, and real PostgreSQL-backed fixture -> worker -> seven findings/41 score -> deterministic proposal -> denied approval. Missing Semgrep coverage fails this service slice. Tests clean only their own records; the stack uses temporary database storage. Any skipped required test fails the gate. Container evidence is under `/tmp/verification` for the lifetime of the checks container; use `docker compose -f compose.verify.yml cp checks:/tmp/verification .runtime/container-verification` before `down` to retain it locally.

Deploy validator controller on a separate disposable Linux host, internal TLS/access secret and preloaded immutable image identity; never share platform secrets/host mounts with validation containers. See VALIDATION.md. Production should use dedicated VM/microVM workers for strong adversarial isolation and meet the public SaaS limits in SECURITY.md before exposing public access.

Before release: run all local verification scopes, disposable service gates, real sandbox resource/network/infinite-test gates, and build/run/health/scan Compose flow. CI definitions now include backend/frontend/browser, PostgreSQL/Redis/Semgrep, real isolation and packaging gates, but have only been inspected locally; no hosted run has been observed. Live App discovery/webhook/explicit digest-approved PR checks require separate external authorization and are not permitted under the current user constraint. Backup/restore testing, retention/deletion and external monitoring/export are operator release requirements, not verified outcomes here.

Rollback deploys the previous application image, retaining forward-compatible schema; review migrations before downgrade, which can drop data. Do not blindly run downgrade against production. Audit records and exact patch identities remain in DB, allowing PR retry reconciliation after process failures. No automatic merge/deployment feature exists.
