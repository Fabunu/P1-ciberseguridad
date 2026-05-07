from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_PATH = PROJECT_ROOT / "data" / "raw"

SYFT_RAW_PATH = RAW_PATH / "syft"
GRYPE_RAW_PATH = RAW_PATH / "grype"
CODEQL_RAW_PATH = RAW_PATH / "codeql"

NORMALIZED_PATH = PROJECT_ROOT / "data" / "normalized"

REPOSITORIES_PARQUET = NORMALIZED_PATH / "repositories.parquet"
DEPENDENCIES_PARQUET = NORMALIZED_PATH / "dependencies.parquet"
DEPENDENCY_VULNS_PARQUET = (
    NORMALIZED_PATH / "dependency_vulnerabilities.parquet"
)
CODE_VULNS_PARQUET = (
    NORMALIZED_PATH / "code_vulnerabilities.parquet"
)


if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s | %(message)s",
    )

LOGGER = logging.getLogger(__name__)


def sha1_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_syft() -> tuple[list[dict], dict[str, int]]:
    dependencies = []
    repo_dependency_count = {}

    if not SYFT_RAW_PATH.exists():
        LOGGER.warning("Syft raw path does not exist.")
        return dependencies, repo_dependency_count

    for json_file in sorted(SYFT_RAW_PATH.glob("*.json")):
        repo_name = (
            json_file.name
            .replace("-sbom", "")
            .replace(".json", "")
        )
        repository_id = sha1_hash(repo_name)

        LOGGER.info("Normalizing Syft: %s", repo_name)

        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as error:
            LOGGER.error("Failed to load %s: %s", json_file.name, error)
            continue

        artifacts = data.get("artifacts", [])

        repo_dependency_count[repo_name] = len(artifacts)

        for artifact in artifacts:
            artifact_name = artifact.get("name")
            artifact_version = artifact.get("version")

            dependency_id = sha1_hash(
                f"{repo_name}:{artifact_name}:{artifact_version}"
            )

            dependencies.append(
                {
                    "dependency_id": dependency_id,
                    "repository_id": repository_id,
                    "repository_name": repo_name,
                    "artifact_name": artifact_name,
                    "artifact_version": artifact_version,
                    "artifact_type": artifact.get("type"),
                    "package_url": artifact.get("purl"),
                    "cpe": artifact.get("cpes"),
                    "licenses": artifact.get("licenses"),
                    "locations": artifact.get("locations"),
                    "found_by": artifact.get("foundBy"),
                    "metadata": artifact.get("metadata"),
                    "sbom_source": "syft",
                    "analyzed_at": utc_now(),
                }
            )

    return dependencies, repo_dependency_count


def normalize_grype() -> tuple[list[dict], dict[str, int]]:
    vulnerabilities = []
    repo_vuln_count = {}

    if not GRYPE_RAW_PATH.exists():
        LOGGER.warning("Grype raw path does not exist.")
        return vulnerabilities, repo_vuln_count

    for json_file in sorted(GRYPE_RAW_PATH.glob("*-raw.json")):
        repo_name = json_file.name.replace("-grype", "").replace(".json", "")
        repository_id = sha1_hash(repo_name)

        LOGGER.info("Normalizing Grype: %s", repo_name)

        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as error:
            LOGGER.error("Failed to load %s: %s", json_file.name, error)
            continue

        vulns = data.get("vulnerabilities", [])

        repo_vuln_count[repo_name] = len(vulns)

        for vuln in vulns:
            package_name = vuln.get("package_name")
            package_version = vuln.get("current_version")
            vulnerability_id = vuln.get("vuln_id")

            dependency_id = sha1_hash(
                f"{repo_name}:{package_name}:{package_version}"
            )

            vulnerability_record_id = sha1_hash(
                f"{repo_name}:{package_name}:{vulnerability_id}"
            )

            vulnerabilities.append(
                {
                    "vulnerability_record_id": vulnerability_record_id,
                    "repository_id": repository_id,
                    "dependency_id": dependency_id,
                    "package_name": package_name,
                    "package_version": package_version,
                    "vulnerability_id": vulnerability_id,
                    "severity": vuln.get("vuln_severity"),
                    "cvss_score": vuln.get("cvss_score"),
                    "cwe": vuln.get("cwe"),
                    "fix_version": vuln.get("fix_version"),
                    "description": vuln.get("message"),
                    "tool": "grype",
                    "analyzed_at": utc_now(),
                }
            )

    return vulnerabilities, repo_vuln_count


def normalize_codeql() -> tuple[list[dict], dict[str, int]]:
    findings = []
    repo_finding_count = {}

    if not CODEQL_RAW_PATH.exists():
        LOGGER.warning("CodeQL raw path does not exist.")
        return findings, repo_finding_count

    for json_file in sorted(CODEQL_RAW_PATH.glob("*.json")):
        repo_name = json_file.name.replace("-codeql", "").replace(".json", "")
        repository_id = sha1_hash(repo_name)

        LOGGER.info("Normalizing CodeQL: %s", repo_name)

        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as error:
            LOGGER.error("Failed to load %s: %s", json_file.name, error)
            continue

        issues = data.get("issues", [])

        repo_finding_count[repo_name] = len(issues)

        for issue in issues:
            region = issue.get("region", {})

            rule_id = issue.get("rule_id")
            file_path = issue.get("file")

            start_line = region.get("startLine")

            finding_id = sha1_hash(
                f"{repo_name}:{rule_id}:{file_path}:{start_line}"
            )

            findings.append(
                {
                    "finding_id": finding_id,
                    "repository_id": repository_id,
                    "rule_id": rule_id,
                    "severity": issue.get("level"),
                    "message": issue.get("message"),
                    "file_path": file_path,
                    "start_line": region.get("startLine"),
                    "end_line": region.get("endLine"),
                    "start_column": region.get("startColumn"),
                    "end_column": region.get("endColumn"),
                    "kind": issue.get("kind"),
                    "tool": "codeql",
                    "analyzed_at": utc_now(),
                }
            )

    return findings, repo_finding_count


def build_repositories_dataset(
    dependency_counts: dict[str, int],
    dependency_vuln_counts: dict[str, int],
    code_vuln_counts: dict[str, int],
) -> list[dict]:
    repo_names = set()

    repo_names.update(dependency_counts.keys())
    repo_names.update(dependency_vuln_counts.keys())
    repo_names.update(code_vuln_counts.keys())

    repositories = []

    for repo_name in sorted(repo_names):
        repositories.append(
            {
                "repository_id": sha1_hash(repo_name),
                "repository_name": repo_name,
                "total_dependencies": dependency_counts.get(repo_name, 0),
                "total_dependency_vulnerabilities": (
                    dependency_vuln_counts.get(repo_name, 0)
                ),
                "total_code_vulnerabilities": (
                    code_vuln_counts.get(repo_name, 0)
                ),
                "analyzed_at": utc_now(),
                "analysis_status": "completed",
            }
        )

    return repositories


def save_parquet(data: list[dict], output_path: Path) -> None:
    df = pd.DataFrame(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    df.to_parquet(output_path, index=False)

    LOGGER.info(
        "Saved parquet: %s (%s rows)",
        output_path.relative_to(PROJECT_ROOT),
        len(df),
    )


def main() -> int:
    LOGGER.info("=" * 80)
    LOGGER.info("NORMALIZATION PIPELINE STARTED")
    LOGGER.info("=" * 80)

    dependencies, dependency_counts = normalize_syft()

    dependency_vulns, dependency_vuln_counts = normalize_grype()

    code_vulns, code_vuln_counts = normalize_codeql()

    repositories = build_repositories_dataset(
        dependency_counts=dependency_counts,
        dependency_vuln_counts=dependency_vuln_counts,
        code_vuln_counts=code_vuln_counts,
    )

    save_parquet(repositories, REPOSITORIES_PARQUET)

    save_parquet(dependencies, DEPENDENCIES_PARQUET)

    save_parquet(
        dependency_vulns,
        DEPENDENCY_VULNS_PARQUET,
    )

    save_parquet(
        code_vulns,
        CODE_VULNS_PARQUET,
    )

    LOGGER.info("=" * 80)
    LOGGER.info("NORMALIZATION PIPELINE FINISHED")
    LOGGER.info("=" * 80)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
