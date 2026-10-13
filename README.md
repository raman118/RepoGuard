# RepoGuard

**Security-focused repository readiness analysis with immutable snapshots, explainable findings, risk scoring, and controlled remediation proposals.**

RepoGuard analyzes repository content as untrusted data. It reports supported checks with evidence, tracks which controls could not be evaluated, and proposes reviewable fixes without automatically applying or merging them.

> RepoGuard is an early-stage project. Its scanner currently covers a deliberately narrow set of controls. Scores are evidence about those controls only; they are not a general security certification. See [known limitations](docs/RULES.md) and [security notes](docs/SECURITY.md).

## What it does

- Ingests bounded repository snapshots and rejects unsafe archive entries.
- Runs versioned static checks and records findings with severity, location, bounded evidence, explanation, and remediation guidance.
- Reports score, control coverage, and unknown results when a check cannot run or input is unsupported.
- Persists scan history and job state through an authenticated API.
- Creates deterministic remediation proposals with a patch digest for human review.
- Requires isolated validation before approval; unavailable isolation fails closed.
- Provides a dashboard to inspect scans, findings, scores, and proposed changes.

RepoGuard does not execute scanned source on the host, merge changes, or deploy automatically. The current implementation and limits are described in [the architecture](ARCHITECTURE.md), [security guide](docs/SECURITY.md), and [supported rules](docs/RULES.md).

## Quick start

### Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- Node.js 24 and npm
- Chromium for browser verification

From the repository root, install the locked dependencies and initialize the local database:

```powershell
uv sync --frozen
uv sync --directory analysis --frozen
uv run alembic upgrade head
```

Start the API and create a local demo tenant in the first terminal:

```powershell
uv run python -m repoguard.cli create-tenant demo
uv run uvicorn repoguard.api:create_app --factory --host 127.0.0.1 --port 8000
```

Keep the generated bearer token private. In a second terminal, start the worker:

```powershell
uv run python -m repoguard.worker
```

In a third terminal, start the dashboard:

```powershell
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:3000`, enter the token, and scan the included vulnerable and clean fixtures. The full walkthrough is in [docs/DEMO.md](docs/DEMO.md).

The fixture identities are content digests, not GitHub commit SHAs. Local fixture mode is intended for development and is not production authentication or service evidence.

## Scanner coverage

The current version has seven focused controls for GitHub Actions workflows, Python shell usage, Dockerfiles, and simple `requirements.txt` files. It does not provide comprehensive language analysis, dependency vulnerability database checks, or proof that a repository is safe. Unsupported inputs and unavailable engines remain unknown rather than being counted as passing. See [docs/RULES.md](docs/RULES.md) for each rule and its limits.

The included fixtures demonstrate the current behavior. With the separately pinned Semgrep engine installed, the vulnerable fixture produces seven findings and a 41/100 score; the clean fixture produces no findings and a 100/100 score. These are fixture results for this narrow rule set, not benchmark or production claims.

## Verification

Install frontend dependencies and Chromium, then run the local verification suite:

```powershell
cd frontend
npm ci
npx playwright install chromium
cd ..
uv run python scripts/verify.py --scope local
```

The repository also defines separate Semgrep, PostgreSQL/Redis service, and sandbox gates. See [docs/DEMO.md](docs/DEMO.md) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for exact commands and prerequisites. Docker-backed service and isolation gates require a Docker-enabled host; a local test pass does not establish those external results.

## Project layout

- `backend/` — API, authentication, persistence, worker, scanner, scoring, and proposal logic
- `frontend/` — dashboard and browser tests
- `analysis/` and `rules/` — pinned Semgrep environment and versioned rules
- `migrations/` — database schema migrations
- `fixtures/` and `tests/` — labeled sample repositories and automated checks
- `sandbox/` — isolated validation boundary
- `docs/` — API, architecture, security, demo, deployment, and evaluation guides

## Documentation

- [Architecture and data flow](ARCHITECTURE.md)
- [API contract](docs/API.md)
- [Threat model and security controls](docs/SECURITY.md)
- [Supported rules and limitations](docs/RULES.md)
- [Local demo](docs/DEMO.md)
- [Deployment and service gates](docs/DEPLOYMENT.md)
- [Evaluation methodology and limits](docs/EVALUATION.md)
- [Design decisions](DECISIONS.md)

## Security

Treat repositories, archives, configuration, and model output as hostile input. Do not run scanned source directly on the host or use production credentials in local fixture mode. Review [docs/SECURITY.md](docs/SECURITY.md) before exposing any service. Production use requires the documented authentication, service, and isolated-worker setup; those deployment gates have not been verified by this README.
