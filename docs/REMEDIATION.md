# Exact remediation policy v1

Supported fixes: workflow `permissions: write-all` -> explicit contents read, and missing literal job timeout -> timeout-minutes 15. These may need project-specific adjustments; changes remain proposals requiring isolated verification and human review. Docker user changes and dependency version selection are deliberately unsupported because they need runtime/ownership/version context.

Only small UTF-8 LF workflow files, supported rule versions, exact literal lines and safe paths qualify. Artifacts store base SHA, before/after file hashes, exact edited line/replacement, zero-context diff, rule provenance and policy version. Full source is not retained in proposals. Patch application regenerates the permitted rewrite and compares the entire digest/artifact; stale sources, modified replacements and arbitrary paths fail closed. Duplicate scan+digest is enforced by migration 0002.

Optional provider-neutral HTTP JSON recipe adapter defaults disabled. Configure `REPOGUARD_LLM_ENABLED`, HTTPS `REPOGUARD_LLM_ENDPOINT` and optional secret key only for a reviewed provider gateway. It receives bounded rule/path metadata and a strict schema, never source, tokens or commands. The model can choose only a fixed supported recipe; deterministic policy generates the actual patch. Unknown keys/tools, unrelated paths/rules/operations or excessive responses are rejected. This intentionally narrow adapter is not a general coding agent.

Proposal generation is locally verified. Isolated validation and exact human approval/PR gates are implemented in G09; pending proposals cannot currently create a remote mutation. No automatic merge or deployment capability exists.
