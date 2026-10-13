"""Narrow deterministic controls. Unsupported/failed analysis is explicit coverage."""

import asyncio
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.tokens import AliasToken, AnchorToken, TagToken

from repoguard.ingestion import Snapshot, safe_path
from repoguard.processes import ProcessLimitError, bounded_command


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    explanation: str
    remediation: str
    version: str = "1"


RULES = {
    rule.id: rule
    for rule in [
        Rule(
            "RG-CI-PERMISSIONS",
            "security",
            "high",
            "Workflow grants broad write permissions.",
            "Set explicit minimum read/write permissions per job.",
        ),
        Rule(
            "RG-PY-SHELL",
            "security",
            "high",
            "Python subprocess enables a command shell.",
            "Use fixed argv with shell=False and validate arguments.",
        ),
        Rule(
            "RG-CI-TIMEOUT",
            "reliability",
            "medium",
            "Workflow job has no finite execution timeout.",
            "Add a positive timeout-minutes appropriate to the job.",
        ),
        Rule(
            "RG-DOCKER-ROOT",
            "deployment",
            "medium",
            "Final Docker stage defaults to root.",
            "Create a least-privilege user and set USER after checking ownership.",
        ),
        Rule(
            "RG-DOCKER-TAG",
            "deployment",
            "medium",
            "Base image omits a tag or uses latest.",
            "Pin a reviewed version or digest and automate updates.",
        ),
        Rule(
            "RG-DEPENDENCY-PIN",
            "dependencies",
            "medium",
            "Dependency has no exact version pin.",
            "Use reviewed exact versions and a hash-locked dependency workflow.",
        ),
        Rule(
            "RG-CI-TEST",
            "maintainability",
            "low",
            "Workflow has no recognized explicit test command.",
            "Add appropriate tests; this heuristic supports pytest/npm test only.",
        ),
    ]
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def semgrep_binary() -> str | None:
    root = Path(__file__).resolve().parents[2] / "analysis" / ".venv"
    for candidate in [root / "Scripts" / "semgrep.exe", root / "bin" / "semgrep"]:
        if candidate.is_file():
            return str(candidate)
    return shutil.which("semgrep")


def finding(rule_id: str, path: str, line: int, evidence: str) -> dict[str, Any]:
    rule = RULES[rule_id]
    identity = {"rule_id": rule.id, "rule_version": rule.version, "path": path, "line": line}
    return {
        **identity,
        "fingerprint": hashlib.sha256(canonical(identity)).hexdigest(),
        "category": rule.category,
        "severity": rule.severity,
        "evidence": evidence[:300],
        "explanation": rule.explanation,
        "remediation": rule.remediation,
    }


def bounded_yaml(text: str) -> Any:
    if len(text.encode()) > 1_000_000:
        raise ValueError("yaml_size_limit")
    count = 0
    for token in yaml.scan(text):
        count += 1
        if count > 10_000 or isinstance(token, (AliasToken, AnchorToken, TagToken)):
            raise ValueError("yaml_complexity_denied")
    return yaml.load(text, Loader=NoDuplicateLoader)  # strings only; no constructors


class NoDuplicateLoader(yaml.BaseLoader):
    def construct_mapping(self, node: yaml.nodes.Node, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.nodes.MappingNode):
            raise ValueError("yaml_mapping_invalid")
        keys = set()
        for key, _ in node.value:
            if not isinstance(key, yaml.nodes.ScalarNode) or key.value in keys:
                raise ValueError("yaml_duplicate_or_complex_key")
            keys.add(key.value)
        return super().construct_mapping(node, deep=deep)


def scan(snapshot: Snapshot, semgrep_enabled: bool = True) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    coverage: dict[str, dict[str, str]] = {
        rule: {"status": "unknown", "reason": "no_supported_input"} for rule in RULES
    }
    errors: list[dict[str, str]] = []

    def covered(*rules: str) -> None:
        for rule in rules:
            if coverage[rule]["reason"] != "parse_error":
                coverage[rule] = {"status": "scanned", "reason": "supported_input"}

    for path, content in sorted(snapshot.files.items()):
        safe_path(path)
        applicable: tuple[str, ...] = ()
        if path == "Dockerfile":
            applicable = ("RG-DOCKER-ROOT", "RG-DOCKER-TAG")
        elif path == "requirements.txt":
            applicable = ("RG-DEPENDENCY-PIN",)
        elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            applicable = ("RG-CI-PERMISSIONS", "RG-CI-TIMEOUT", "RG-CI-TEST")
        if not applicable:
            continue
        try:
            text = content.decode("utf-8")
            if "\0" in text:
                raise ValueError("binary_input")
            if path == "Dockerfile":
                instructions = [
                    (i + 1, line.strip())
                    for i, line in enumerate(text.splitlines())
                    if line.strip() and not line.strip().startswith("#")
                ]
                stages = [
                    i
                    for i, (_, line) in enumerate(instructions)
                    if re.match(r"^FROM\s", line, re.I)
                ]
                if len(stages) != 1 or any("\\" in line or "$" in line for _, line in instructions):
                    raise ValueError("docker_syntax_unsupported")
                final = instructions[stages[-1] :]
                users = [
                    (line, value.split(maxsplit=1)[1])
                    for line, value in final
                    if re.match(r"^USER\s", value, re.I)
                ]
                if not users or users[-1][1].split(":")[0].lower() in {"root", "0"}:
                    findings.append(
                        finding(
                            "RG-DOCKER-ROOT",
                            path,
                            users[-1][0] if users else final[0][0],
                            "Final stage USER is root or absent.",
                        )
                    )
                for position in stages:
                    line, instruction = instructions[position]
                    parts = instruction.split()
                    image = next((part for part in parts[1:] if not part.startswith("--")), "")
                    if (
                        image.lower() != "scratch"
                        and "@sha256:" not in image
                        and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest"))
                    ):
                        findings.append(
                            finding(
                                "RG-DOCKER-TAG",
                                path,
                                line,
                                "FROM image uses latest or an omitted tag.",
                            )
                        )
            elif path == "requirements.txt":
                for line, entry in enumerate(text.splitlines(), 1):
                    entry = entry.strip()
                    if not entry or entry.startswith("#"):
                        continue
                    if entry.startswith("-") or "\\" in entry or "://" in entry or "@" in entry:
                        raise ValueError("requirements_syntax_unsupported")
                    if (
                        re.fullmatch(
                            r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+-]+(?:\s*;.*)?",
                            entry,
                        )
                        is None
                    ):
                        findings.append(
                            finding(
                                "RG-DEPENDENCY-PIN",
                                path,
                                line,
                                "Requirement has no supported exact version pin.",
                            )
                        )
            else:
                data = bounded_yaml(text)
                if (
                    not isinstance(data, dict)
                    or not isinstance(data.get("jobs"), dict)
                    or not data["jobs"]
                ):
                    raise ValueError("workflow_structure_invalid")
                lines = text.splitlines()
                permission_lines = [
                    i + 1
                    for i, line in enumerate(lines)
                    if re.match(r"^\s*permissions:\s*write-all\s*(?:#.*)?$", line)
                ]
                permissions = [
                    data.get("permissions"),
                    *(
                        job.get("permissions")
                        for job in data["jobs"].values()
                        if isinstance(job, dict)
                    ),
                ]
                if "write-all" in permissions:
                    for line in permission_lines:
                        findings.append(
                            finding("RG-CI-PERMISSIONS", path, line, "permissions: write-all")
                        )
                has_test = False
                executable_jobs = 0
                for name, job in data["jobs"].items():
                    if not isinstance(job, dict):
                        raise ValueError("workflow_job_invalid")
                    if "uses" in job:
                        # Reusable workflow internals are not inspected.
                        continue
                    executable_jobs += 1
                    job_line = next(
                        (
                            i + 1
                            for i, line in enumerate(lines)
                            if re.match(rf"^\s{{2}}{re.escape(str(name))}:\s*(?:#.*)?$", line)
                        ),
                        1,
                    )
                    timeout = str(job.get("timeout-minutes", ""))
                    if not timeout.isdecimal() or not 1 <= int(timeout) <= 360:
                        findings.append(
                            finding(
                                "RG-CI-TIMEOUT",
                                path,
                                job_line,
                                "Job timeout-minutes is absent or unsupported.",
                            )
                        )
                    steps = job.get("steps", [])
                    if not isinstance(steps, list):
                        raise ValueError("workflow_steps_invalid")
                    for step in steps:
                        command = str(step.get("run", "")) if isinstance(step, dict) else ""
                        if re.search(
                            r"(?:^|[\n;&]\s*)(?:python\s+-m\s+)?pytest\b|(?:^|[\n;&]\s*)npm\s+(?:run\s+)?test\b",
                            command,
                        ):
                            has_test = True
                if not executable_jobs:
                    raise ValueError("reusable_workflow_uninspected")
                if not has_test:
                    findings.append(
                        finding(
                            "RG-CI-TEST",
                            path,
                            1,
                            "No explicit pytest or npm test command recognized in this workflow.",
                        )
                    )
            covered(*applicable)
        except (UnicodeError, ValueError, yaml.YAMLError, RecursionError):
            for rule in applicable:
                coverage[rule] = {"status": "unknown", "reason": "parse_error"}
            errors.append({"path": path, "code": "unsupported_or_invalid_config"})
    python_files = [path for path in snapshot.files if path.endswith(".py")]
    if python_files:
        if semgrep_enabled and semgrep_binary():
            try:
                findings.extend(semgrep_scan(snapshot))
                covered("RG-PY-SHELL")
            except (ValueError, OSError, subprocess.SubprocessError, ProcessLimitError):
                coverage["RG-PY-SHELL"] = {"status": "unknown", "reason": "engine_error"}
        else:
            coverage["RG-PY-SHELL"] = {
                "status": "unknown",
                "reason": "engine_unavailable" if semgrep_enabled else "engine_disabled",
            }
    unique = {f["fingerprint"]: f for f in findings}
    return {
        "engine_version": "repoguard-config/1.1"
        + ("+semgrep/1.180.0" if coverage["RG-PY-SHELL"]["status"] == "scanned" else ""),
        "sha": snapshot.sha,
        "findings": [unique[key] for key in sorted(unique)],
        "coverage": coverage,
        "errors": errors,
        "rule_versions": {key: asdict(value) for key, value in RULES.items()},
        "files_ingested": len(snapshot.files),
    }


def semgrep_scan(snapshot: Snapshot) -> list[dict[str, Any]]:
    binary = semgrep_binary()
    if binary is None:
        raise ValueError("semgrep_unavailable")
    config = Path(__file__).resolve().parents[2] / "rules" / "python.yml"
    with tempfile.TemporaryDirectory(prefix="repoguard-analysis-") as directory:
        state_root = Path(directory) / "state"
        state_root.mkdir()
        environment = {
            "XDG_CONFIG_HOME": str(state_root),
            "XDG_CACHE_HOME": str(state_root),
            "SEMGREP_SETTINGS_FILE": str(state_root / "settings.yml"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SEND_METRICS": "off",
        }
        code, version, _ = asyncio.run(
            bounded_command(
                [binary, "--version"], timeout=15, maximum=8192, extra_environment=environment
            )
        )
        if code != 0 or version.decode().strip() != "1.180.0":
            raise ValueError("semgrep_version_mismatch")
        root = Path(directory) / "source"
        root.mkdir()
        for path, content in snapshot.files.items():
            if not path.endswith(".py"):
                continue
            target = root.joinpath(*safe_path(path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        code, output, _ = asyncio.run(
            bounded_command(
                [
                    binary,
                    "scan",
                    "--config",
                    str(config),
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--timeout",
                    "5",
                    "--max-target-bytes",
                    "1000000",
                    str(root),
                ],
                timeout=30,
                extra_environment=environment,
            )
        )
        if code != 0:
            raise ValueError("semgrep_failed")
        data = json.loads(output)
        if data.get("errors"):
            raise ValueError("semgrep_partial_failure")
        scanned_paths = {
            Path(path).resolve().relative_to(root.resolve()).as_posix()
            for path in data.get("paths", {}).get("scanned", [])
        }
        expected_paths = {path for path in snapshot.files if path.endswith(".py")}
        if scanned_paths != expected_paths:
            raise ValueError("semgrep_target_coverage_incomplete")
        findings = []
        for row in data["results"]:
            path = Path(row["path"]).resolve().relative_to(root.resolve()).as_posix()
            if not str(row["check_id"]).endswith("RG-PY-SHELL"):
                raise ValueError("semgrep_unknown_rule")
            findings.append(
                finding(
                    "RG-PY-SHELL",
                    path,
                    int(row["start"]["line"]),
                    "Python subprocess call sets shell=True; source arguments withheld.",
                )
            )
        return findings
