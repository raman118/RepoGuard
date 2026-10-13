# Architecture decisions

## ADR-001 — Modular monolith with an independent worker
Accepted 2026-10-12. FastAPI/SQLAlchemy API and a worker share domain modules; Next.js is a separate frontend. PostgreSQL is the durable source of truth, Redis a wakeup channel. Avoid distributed microservices until load/security boundaries justify them. SQLite supports offline test/development only; its tests cannot prove PostgreSQL locking behavior.

## ADR-002 — Local repository delivery
Accepted 2026-10-12. Preserve the requested Next.js + FastAPI + PostgreSQL stack in this workspace. Cloudflare Sites server hosting cannot run the requested PostgreSQL/Redis worker/container architecture. External hosting is deferred to explicit deployment instructions and honest environment gates.

## ADR-003 — Durable database jobs, Redis notification only
Accepted. Store attempts, lease and cancellation in PostgreSQL; workers poll as fallback. Redis Streams alone requires more complicated reconciliation with DB transactions. Notification loss must not lose work. Conditional claims fence late workers; service concurrency tests remain mandatory.

## ADR-004 — Opaque operator provisioned tokens
Accepted for bounded demo/operator deployment. Hash high-entropy bearer credentials, map to tenant, no tenant headers or self-assigned installations. OIDC/user RBAC is preferable for public SaaS but adds an external dependency unrelated to the local vertical slice. Document this limit; no claim of public SaaS readiness.

## ADR-005 — Conservative coverage-aware scoring
Accepted. Category weights sum to 100; uncovered categories earn zero, unknown explicitly displayed. Normalizing only covered categories could incorrectly show 100 for a nearly unscanned repository. Penalties cap per category; canonical rule/location deduplication prevents accidental duplicate penalties. Score versioning enables repeatability, not security certification.

## ADR-006 — Exact deterministic fixes before model integration
Accepted. Support only narrow rewrites that preserve known intent and can be verified. A provider-neutral optional protocol supplies typed patches, never commands/tools. All outputs cross the same deterministic policy. Full agent tool execution rejected because repository text may be prompt injection.

## ADR-007 — External evidence remains blocked
Accepted. Locally tested interfaces can unblock independent implementation; a missing real PostgreSQL, Redis, Semgrep, Docker or GitHub test is never marked passing. GOALS.md can remain BLOCKED after all feasible local criteria are delivered. Do not install or execute scanned repository dependencies to work around unavailable isolation.

## ADR-008 — Explicit frontend lint plugins
Accepted during G07. Current eslint-config-next pulls an unpatched braces advisory through its glob dependency. Replace that preset with explicit TypeScript, React Hooks and accessibility recommended rules, retaining full lint checks without the vulnerable package. ESLint 9 is pinned for jsx-a11y peer compatibility (ESLint 10 installation failed peer resolution; no force/legacy-peer-deps). Upgrade when supported. `npm audit` then reports zero vulnerabilities; no scanner rule claims automated CVE coverage. [Advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).
