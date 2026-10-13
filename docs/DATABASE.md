# Database and local identity

Run `uv run alembic upgrade head` before starting the API or worker. Production uses `REPOGUARD_DATABASE_URL=postgresql+psycopg://...`. Migrations are explicit; application startup never silently creates tables.

For local development, `uv run python -m repoguard.cli create-tenant demo` creates a tenant and prints a randomly generated bearer token once. Store it securely; only its SHA-256 digest is retained. Do not paste tokens into tracked docs or logs. `revoke-token <digest>` disables an identity. `assign-installation <tenant_id> <installation_id>` is a trusted operator action after ownership has been verified externally.

Repository identities are unique within a tenant; scan request keys are unique within a repository. Creation and audit/job records share transactions. Caller tenant IDs are never accepted. Lists are bounded to 100 recent records; pagination beyond this initial limit is not implemented yet. Source artifacts are ephemeral; findings are bounded JSON. No retention/deletion policy is automated in this first slice.

`uv run pytest -m postgres` requires `REPOGUARD_TEST_POSTGRES_URL` pointing to a dedicated disposable database. It upgrades and compares schema metadata. SQLite tests check migration upgrade/downgrade/drift and authenticated API behavior; PostgreSQL service verification remains a separate gate.
