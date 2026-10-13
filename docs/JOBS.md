# Snapshot ingestion and jobs

Snapshot SHA is exactly 40 lowercase hex. GitHub ZIP archives are pinned to it; local fixture identity is explicitly a content digest, never a claimed GitHub commit. Fixture catalog supplies these identities. Bounded ZIP reader does not extract or execute repository code. Invalid types, Windows/POSIX paths, control characters, duplicate/case collisions, size/count/depth/ratio limits and parent-file conflicts are rejected.

Job records are committed with scan/audit before Redis publish. Redis publish failure does not roll back durable work. Workers poll, atomically claim due queued or expired leased work, fence completion with token+expiry, and retry only sanitized transient error codes up to three attempts. Expired final attempts terminate. Cancellation is checked at publication. API never processes scan source synchronously.

`tests/test_ingestion_jobs.py` verifies local lease recovery/fencing, cancellation and attack archives. PostgreSQL competing-worker semantics and Redis publish/receive remain BLOCKED without services. Worker scanning entrypoint is added with G05; this checkpoint verifies ingestion/orchestration independently before analysis.
