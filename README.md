# RepoGuard

**Understand repository risk. See the evidence. Review every fix.**

RepoGuard is a repository-readiness analyzer. It takes an immutable snapshot of a repository, runs a focused set of versioned static checks, and presents findings, control coverage, and an explainable readiness score. For supported findings, it can generate a small deterministic patch proposal. Validation and any remote change are separate, explicit steps.

> **Project status:** early-stage MVP. The scanner covers seven deliberately narrow controls. A score describes only those registered controls and the inputs actually scanned; it is not a security certification. PostgreSQL/Redis, real container isolation, live GitHub behavior, and hosted CI require their own environment-backed verification. See [known limits](docs/RULES.md) and [deployment gates](docs/DEPLOYMENT.md).

## Why RepoGuard exists

A single “security score” can hide important questions: Which checks ran? What evidence supports a finding? Did a tool fail, or was the input unsupported? Can a proposed fix still be applied to the same revision?

RepoGuard keeps those answers attached to each scan:

- **Findings are explainable:** each one points to a versioned rule, severity, file and line, bounded evidence, and remediation guidance.
- **Coverage is visible:** a control that was skipped, unsupported, or failed is marked unknown. It is never silently counted as passing.
- **Results are reproducible:** the snapshot identity, rule and policy versions, findings, coverage, and score contribute to a digest.
- **Changes are reviewable:** supported fixes are regenerated from deterministic recipes and tied to an exact base identity and patch digest.
- **Untrusted code stays data:** scanning parses bounded repository content; it does not execute the scanned project on the API or worker host.

## How it works

A scan moves through a durable pipeline. The dashboard submits work; a separate worker performs analysis; PostgreSQL records the source identity and results.

~~~mermaid
flowchart TD
    Human[Human reviewer] --> UI[Next.js dashboard]
    UI -->|tenant-scoped API request| API[FastAPI API]
    API -->|create scan and durable job| DB[(PostgreSQL)]
    API -->|best-effort wake-up| Redis[(Redis)]
    Redis --> Worker[Scan worker]
    DB -->|claim job with lease| Worker
    Worker -->|obtain full-SHA archive or allowlisted fixture| Ingest[Bounded snapshot ingestion]
    Ingest -->|immutable files and identity| Analysis[Static analysis subprocess]
    Analysis --> Rules[Versioned rules and parsers]
    Rules --> Findings[Findings and explicit coverage]
    Findings --> Score[Deterministic scoring policy]
    Score -->|persist results| DB
    DB --> UI
    Findings --> Proposal[Deterministic patch proposal]
    Proposal --> Human
    Human -->|explicit approval of exact digest| Validator[Dedicated isolated validator]
    Validator -->|validation result| DB
    Human -->|separate approved action| PR[GitHub PR adapter]
~~~

### Scan lifecycle

1. **Authenticate and scope the request.** API access is tenant-scoped. The server derives the tenant from an opaque bearer credential; a caller cannot choose a tenant by submitting an ID.
2. **Create durable work.** The API records the scan, job, and audit event in PostgreSQL. Redis is only a worker wake-up channel. If Redis is unavailable, workers can still recover work by polling PostgreSQL.
3. **Pin the input.** A real repository snapshot is requested using a full commit SHA. Local demos use a fixed allowlist of bundled fixtures, identified by content digests. The bounded archive reader rejects unsafe paths, links, special files, duplicates, and over-limit archives.
4. **Analyze as data.** The worker passes the snapshot to trusted analysis code. Versioned rules inspect supported Python, workflow, Dockerfile, and dependency-manifest patterns. Repository source and project tests are not run during scanning.
5. **Record findings and coverage.** The result includes rule IDs and versions, locations, redacted evidence, explanations, recommendations, and per-rule coverage. Unsupported input, parser errors, or a missing analysis engine remain unknown.
6. **Calculate the score.** The versioned policy allocates points according to which controls were actually scanned, then applies bounded severity deductions for unique findings. The UI shows coverage and deductions with the total so the score has context.
7. **Propose a constrained fix.** Only a small set of supported workflow edits can currently be proposed. The patch is regenerated from the rule recipe and checked against its base snapshot, file hashes, and exact digest.
8. **Validate and review separately.** A proposal must pass the configured isolated validator before it can be approved. If isolation is unavailable, validation fails closed. Remote PR creation requires an authenticated human to approve the exact patch digest and base SHA; RepoGuard does not merge or deploy automatically.

See [the architecture](ARCHITECTURE.md), [job lifecycle](docs/JOBS.md), [scoring policy](docs/SCORING.md), and [remediation policy](docs/REMEDIATION.md) for the detailed contracts.

## What the current scanner checks

The current rule set contains seven focused controls across GitHub Actions workflows, Python shell invocation patterns, Dockerfiles, and simple requirements files. It is not a general-purpose code auditor. In particular, it does not claim broad language coverage, runtime behavior analysis, or dependency CVE detection.

If Semgrep is installed from the separately locked analysis environment, the Python shell rule is evaluated too. If it is missing or fails, that control is shown as unknown rather than passed. Read [the rule catalog](docs/RULES.md) for supported inputs and per-rule limitations.

Bundled fixture results are useful for seeing the UI and rule behavior, but they are not production benchmarks: with Semgrep 1.180.0, the vulnerable fixture has seven findings and a 41/100 score; the clean fixture has no findings and a 100/100 score. These values describe this specific fixture and narrow rule set only. Always interpret the score together with the coverage panel, rule versions, and findings.

## Try the local demo

### Prerequisites

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- Node.js 24 and npm
- Chromium if you want to run browser verification

From the repository root, install the locked Python dependencies and initialize the local database:

~~~powershell
uv sync --frozen
uv sync --directory analysis --frozen
uv run alembic upgrade head
~~~

In terminal 1, create a local demo tenant and start the API:

~~~powershell
uv run python -m repoguard.cli create-tenant demo
uv run uvicorn repoguard.api:create_app --factory --host 127.0.0.1 --port 8000
~~~

Keep the generated bearer token private. In terminal 2, start the worker:

~~~powershell
uv run python -m repoguard.worker
~~~

In terminal 3, start the dashboard:

~~~powershell
cd frontend
npm ci
npm run dev
~~~

Open **http://127.0.0.1:3000**, enter the token, and scan the bundled vulnerable fixture. Inspect the findings, score breakdown, rule coverage, and scan history. Then scan the clean fixture for comparison.

For the full walkthrough, including a deterministic timeout-fix proposal and the expected fail-closed result when no isolated validator is configured, see [docs/DEMO.md](docs/DEMO.md).

### Run local verification

Install the frontend dependencies and Chromium, then run the local verification gate from the repository root:

~~~powershell
cd frontend
npm ci
npx playwright install chromium
cd ..
uv run python scripts/verify.py --scope local
~~~

Separate Semgrep, PostgreSQL/Redis, and sandbox gates are documented in [docs/DEMO.md](docs/DEMO.md) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Docker-backed checks require a Docker-enabled host. A local pass does not imply that those external gates passed.

## Components

| Path | Responsibility |
|---|---|
| **backend/repoguard/api.py** and **routes.py** | FastAPI application, authenticated API routes, scan submission, and result views |
| **backend/repoguard/ingestion.py** | Bounded archive and fixture ingestion into immutable snapshots |
| **backend/repoguard/jobs.py** and **worker.py** | Durable job claiming, leases, retry/recovery, and asynchronous scan execution |
| **backend/repoguard/scanner.py** and **scoring.py** | Static checks, coverage status, findings, and deterministic score policy |
| **backend/repoguard/remediation.py** and **proposal_routes.py** | Supported patch recipes, digest checks, and proposal endpoints |
| **backend/repoguard/validation.py**, **sandbox.py**, **validator_service.py** | Fail-closed validation boundary and isolated execution service |
| **backend/repoguard/models.py** and **migrations/** | Persistent data model and schema evolution |
| **frontend/** | Dashboard for scans, findings, coverage, score details, and proposals |
| **rules/** and **analysis/** | Versioned local rules and separately pinned analysis tooling |
| **fixtures/** and **tests/** | Demo inputs and automated regression/security checks |
| **docs/** | API, architecture, security, operations, deployment, and evaluation references |

## Local development and deployment

For a quick walkthrough, use the local fixture mode above. For a multi-service development stack with PostgreSQL and Redis, follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). SQLite is a local adapter and does not establish PostgreSQL behavior.

Before using this beyond a local demo, review [the security guide](docs/SECURITY.md), [operations guide](docs/OPERATIONS.md), [GitHub integration contract](docs/GITHUB.md), and [isolated validation requirements](docs/VALIDATION.md). Production needs operator-provisioned credentials, TLS, protected PostgreSQL/Redis, bounded dedicated workers, and verified isolation. Container isolation shares the host kernel; dedicated VM or microVM workers are recommended for hostile code.

## Security boundaries

- Treat repository files, archives, manifests, and model output as hostile input.
- Never install packages from a scanned manifest or run scanned source on the host.
- Keep real credentials out of fixtures, logs, and screenshots.
- Do not expose local fixture mode as production authentication.
- Keep the validator separate from API/scan-worker credentials and host files.
- Require a human to approve the exact patch digest and base before any remote PR action.

Report vulnerabilities privately to the project maintainers rather than including secrets or exploit material in public issues. See [docs/SECURITY.md](docs/SECURITY.md).

## Project documentation

- [API reference](docs/API.md)
- [Architecture and threat model](ARCHITECTURE.md)
- [Supported rules and limitations](docs/RULES.md)
- [Scoring policy](docs/SCORING.md)
- [Job lifecycle](docs/JOBS.md)
- [Remediation policy](docs/REMEDIATION.md)
- [GitHub integration](docs/GITHUB.md)
- [Validation boundary](docs/VALIDATION.md)
- [Demo walkthrough](docs/DEMO.md)
- [Deployment gates](docs/DEPLOYMENT.md)
- [Evaluation methodology](docs/EVALUATION.md)
- [Operational guidance](docs/OPERATIONS.md)
- [Design decisions](DECISIONS.md)
