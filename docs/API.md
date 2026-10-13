# API v1 contract

All `/v1` endpoints require `Authorization: Bearer <operator-provisioned-token>`. Identity determines tenant. Public endpoints: `/health/live`, `/health/ready`, signed `/webhooks/github`. No arbitrary host path, shell command or source URL input.

| Method / route | Input | Result / policy |
| --- | --- | --- |
| GET /v1/repositories | none | tenant repositories, bounded listing |
| POST /v1/repositories | owner, name, installation_id OR allowlisted fixture_id | verified discovery before remote identity persisted; 201/409 |
| GET /v1/installations/{id}/repositories | registered installation | paginated GitHub access, 404 foreign installation |
| POST /v1/repositories/{id}/scans | full sha, idempotency_key | durable queued scan/job; 202; replay returns same identity |
| GET /v1/scans/{id} | none | state/findings/coverage/score/job; foreign ID 404 |
| GET /v1/repositories/{id}/scans | none | bounded descending history |
| POST /v1/scans/{id}/cancel | none | cooperative cancellation; terminal conflict 409 |
| POST /v1/scans/{id}/proposals | finding_id | exact patch/diff/provenance, unsupported 422 |
| POST /v1/proposals/{id}/validate | none | isolated validation only; unavailable 503 |
| POST /v1/proposals/{id}/approve | exact digest | authenticated explicit human approval, only validated/current patch |
| POST /v1/proposals/{id}/pull-request | exact digest | approved remote PR; retry reconciliation; no merge |

Pydantic rejects extra fields and bounds strings; SHA is exactly 40 lowercase hex characters. Findings include rule ID/version, severity/category/path/line, redacted evidence, explanation/remediation. Score includes policy version, weights/deductions, coverage status and reproducibility digest. Errors expose sanitized codes, never tokens/raw exception payloads. Operator CLI owns schema migrations and tenant/installation provisioning.
