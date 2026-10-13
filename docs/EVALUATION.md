# Measured fixture evaluation

Measured: 2026-10-12T18:48:22.544392+00:00

Reproduce with `uv run python scripts/evaluate.py --iterations 3 --with-semgrep`. Machine-readable evidence: `artifacts/evaluation.json`.

Method: warm single-process ZIP + config + score; pinned Semgrep CLI included; no network/DB/queue/worker startup. Platform: Windows-11-10.0.26200-SP0; Python 3.12.13; 16 logical CPUs.

Sample: 2 labeled repositories, 6 measured scans. Each config rule has one positive and one negative repository. Exact file/line locations determine TP/FP/FN; FPR is negative repositories with any false positive / negative repositories scanned.

| Rule | Scanned repos | TP / FP / FN | Precision | Recall | FPR |
| --- | --- | --- | --- | --- | --- |
| RG-CI-PERMISSIONS | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-PY-SHELL | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-CI-TIMEOUT | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-DOCKER-ROOT | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-DOCKER-TAG | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-DEPENDENCY-PIN | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |
| RG-CI-TEST | 2 | 1 / 0 / 0 | 1.000 | 1.000 | 0.000 |

Measured median 3911.180 ms; p95 4588.760 ms; sequential throughput 0.25 scans/s. This excludes worker startup, scheduling, database and network costs; fixture archive preparation is excluded. Semgrep mode includes its CLI startup. Throughput elapsed time includes fixture identity reads between timed scans.

Scores: vulnerable 41/100 (coverage 100.0), clean 100/100 (coverage 100.0). Each repository produced one identical digest across repeats: True.

Deterministic proposals: 2; statically resolved targeted findings: 2. Isolated validation attempts: 0; validated success rate unmeasured. BLOCKED: Docker/validator unavailable; static resolution is not validated success.

Limitations:

- Two simple fixtures, one positive and one negative repository per config rule; labels and implementation were co-developed.
- No claim of general precision/recall, CVE detection, worker throughput, live GitHub behavior or production latency.
- Semgrep coverage follows actual engine outcomes; unavailable/disabled controls have null accuracy metrics. External service and isolation gates remain blocked.
