# Reproducible demo

The local demo uses the real authenticated API, durable jobs, bounded static scanner, persisted findings/scores, dashboard and deterministic patch proposals. It reads the two allowlisted fixtures as data. No Git or GitHub operation is needed. Fixture identities are content digests, not remote commits. Real container/service verification remains blocked on this machine; isolation failure denies approval.

Install Python 3.12, uv and Node 24. From repository root:

```powershell
uv sync --frozen
uv sync --directory analysis --frozen
uv run alembic upgrade head
uv run python -m repoguard.cli create-tenant demo
uv run uvicorn repoguard.api:create_app --factory --host 127.0.0.1 --port 8000
```

Keep the printed token privately. In a second terminal run `uv run python -m repoguard.worker`. In a third run `cd frontend`, `npm ci`, `npm run dev`. Open `http://127.0.0.1:3000`, enter the token, connect the vulnerable fixture and run a scan. Inspect the score, category deductions, rule coverage, file evidence and scan history. Connect/scan clean fixture to compare. Fixture SHAs are content digests, not GitHub commits.

With the separately locked Semgrep 1.180.0 engine, the vulnerable fixture yields seven findings, score 41/100, and 100 weighted coverage points; the clean fixture yields no findings and score 100/100. Without Semgrep, configuration-only results are six/zero findings, scores 37/82, and 82.5 coverage points. The missing Python control is explicitly unknown. These scores assess seven supported controls, not general production safety.

Expand the `RG-CI-TIMEOUT` finding, click **Propose fix**, and inspect the actual diff adding `timeout-minutes: 15`, rule provenance, base identity and exact SHA-256 patch digest. Click **Validate in isolation**. With no configured validator it reports `isolation_unavailable`; approval is unavailable. This is the verified fail-closed result. To exercise real container validation, follow [VALIDATION.md](VALIDATION.md) on a dedicated Docker host. Fixtures can be validated and approved with that host configured, but cannot publish a remote PR. The remote adapter is covered by local transport mocks only; the current user instruction prohibits live GitHub operations.

To reproduce all local gates after installing the dependencies and Chromium:

```powershell
cd frontend
npm ci
npx playwright install chromium
cd ..
uv run python scripts/verify.py --scope local
```

Stop manually started demo servers first: Playwright owns ports 8000/3000 and a disposable SQLite database. The runner executes backend Ruff/format/mypy/pytest and frontend format/lint/types/unit/build/browser checks with live platform credentials removed from its child environment. Evidence is written to `.runtime/verification-local.json`; local test success permits explicit external skips and is not release proof. Browser tests use a loopback-only test credential, verify scan -> actual findings/score -> proposed diff -> isolation denial, memory-only credentials, and mobile layout. Desktop/mobile screenshots are written under `.runtime/`.

Required gates run separately and fail when their prerequisites are missing or tests skip:

```powershell
uv run python scripts/verify.py --scope semgrep
uv run python scripts/verify.py --scope services
uv run python scripts/verify.py --scope sandbox
```

Service URLs must refer to disposable PostgreSQL/Redis; sandbox requires a working Linux Docker daemon and immutable `REPOGUARD_TEST_VALIDATOR_IMAGE`. See [DEPLOYMENT.md](DEPLOYMENT.md) for an isolated service-test stack. Benchmark reproduction is in [EVALUATION.md](EVALUATION.md). No deployment, hosted CI run or remote PR is claimed.
