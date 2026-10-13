# Supported rule set v1

Seven versioned controls, not comprehensive security or vulnerability coverage. Findings contain ID/version, severity/category, file/line, fixed bounded evidence, explanation and recommendation. Raw secrets, dependency URLs and subprocess arguments are withheld. Configuration failures and missing engines remain unknown.

| Rule | Supported input / detection | Limitations |
| --- | --- | --- |
| RG-CI-PERMISSIONS | GitHub workflow top/job `permissions: write-all` | explicit individual write permissions not assessed |
| RG-PY-SHELL | Semgrep Python subprocess run/Popen/call/check_call/check_output shell=True | aliases/dynamic shell values and dataflow not covered |
| RG-CI-TIMEOUT | non-reusable workflow jobs missing integer timeout 1–360 | expressions/reusable internals unsupported |
| RG-DOCKER-ROOT | single-stage Dockerfile no USER or root/0 | multistage/variables/continuations unsupported; user existence/ownership not proven |
| RG-DOCKER-TAG | FROM missing tag/latest | tagged images remain mutable; no digest freshness or CVE claim |
| RG-DEPENDENCY-PIN | simple requirements.txt lines without exact == version | includes/options/URLs/continuations unsupported; no vulnerability DB |
| RG-CI-TEST | no explicit pytest/npm test run command in workflow | heuristic; test existence, quality or outcome not proven |

YAML anchors, aliases and custom tags are rejected, token count and bytes bounded. All scalars parsed as strings. Unsupported configuration/languages, absence of supported input and unavailable Semgrep remain unknown. Per-rule coverage is persisted. Tree-sitter, JSON/TOML-specific controls, advanced Dockerfiles, lockfile CVEs and broader language analysis are deferred until rules justify their cost.

Worker entrypoint: `uv run python -m repoguard.worker` (or `--once`). It reads immutable snapshots and runs only trusted analysis code in a subprocess with deadline. It never imports/runs the scanned repository. Deploy scan workers with process/container memory/CPU limits. Executing repository tests is a separate G09 isolated validation boundary.

Semgrep uses local pinned rules, no registry config, metrics disabled, fixed argv/timeouts, bounded output and maximum target bytes. `uv sync --directory analysis --frozen` installs the separately locked 1.180.0 tool. Native Windows execution has now been verified against both fixtures; Linux is also supported by the upstream tool. The adapter checks the exact runtime version, isolates settings/cache in a temporary directory, strips inherited credentials and checks every expected Python target actually scanned. Missing/failed/partial engines never synthesize Python findings or passing coverage. [Native Windows support](https://semgrep.dev/products/community-edition/).
