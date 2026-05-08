import pandas as pd


SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def normalize_severity(value: str) -> str:
    if pd.isna(value):
        return "UNKNOWN"

    value = str(value).upper().strip()

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "WARNING": "MEDIUM",
        "ERROR": "HIGH",
        "NOTE": "LOW",
    }

    return mapping.get(value, "UNKNOWN")


class MetricsBuilder:
    def __init__(self, loader):
        self.repositories = loader.repositories.copy()

        self.dependencies = loader.dependencies.copy()

        self.dep_vulns = loader.dependency_vulnerabilities.copy()

        self.code_vulns = loader.code_vulnerabilities.copy()

        self.dep_vulns["normalized_severity"] = self.dep_vulns["severity"].apply(
            normalize_severity
        )

        self.code_vulns["normalized_severity"] = self.code_vulns["severity"].apply(
            normalize_severity
        )

    # =========================================================
    # UNIFIED DATASET
    # =========================================================

    def unified_vulnerabilities(self):
        dep = self.dep_vulns[
            [
                "repository_id",
                "repository",
                "normalized_severity",
                "vulnerability_id",
            ]
        ].copy()

        dep["source"] = "dependency"

        code = self.code_vulns[
            [
                "repository_id",
                "rule_id",
                "normalized_severity",
            ]
        ].copy()

        code["repository"] = code["repository_id"]

        code = code.rename(
            columns={
                "rule_id": "vulnerability_id",
            }
        )

        code["source"] = "code"

        unified = pd.concat(
            [dep, code],
            ignore_index=True,
        )

        return unified

    # =========================================================
    # REPOSITORY SUMMARY
    # =========================================================

    def repository_summary(self):
        unified = self.unified_vulnerabilities()

        summary = (
            unified.groupby("repository")
            .agg(
                total_vulnerabilities=(
                    "vulnerability_id",
                    "count",
                ),
                unique_vulnerabilities=(
                    "vulnerability_id",
                    "nunique",
                ),
            )
            .reset_index()
        )

        return summary.sort_values(
            by="total_vulnerabilities",
            ascending=False,
        )

    # =========================================================
    # SEVERITY DISTRIBUTION
    # =========================================================

    def severity_distribution(self):
        unified = self.unified_vulnerabilities()

        severity = (
            unified.groupby(
                [
                    "repository",
                    "normalized_severity",
                ]
            )
            .size()
            .reset_index(name="count")
        )

        return severity.sort_values(
            by="count",
            ascending=False,
        )

    # =========================================================
    # REPOSITORY RISK
    # =========================================================

    def repository_risk(self):
        unified = self.unified_vulnerabilities()

        pivot = unified.pivot_table(
            index="repository",
            columns="normalized_severity",
            aggfunc="size",
            fill_value=0,
        ).reset_index()

        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
        ]:
            if severity not in pivot.columns:
                pivot[severity] = 0

        pivot["total_vulnerabilities"] = pivot[
            [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN",
            ]
        ].sum(axis=1)

        pivot["risk_score"] = (
            pivot["CRITICAL"] * 5
            + pivot["HIGH"] * 3
            + pivot["MEDIUM"] * 2
            + pivot["LOW"] * 1
        )

        pivot = pivot.rename(
            columns={
                "CRITICAL": "critical_count",
                "HIGH": "high_count",
                "MEDIUM": "medium_count",
                "LOW": "low_count",
                "UNKNOWN": "unknown_count",
            }
        )

        return pivot.sort_values(
            by="risk_score",
            ascending=False,
        )

    # =========================================================
    # TOP VULNERABLE PACKAGES
    # =========================================================

    def top_vulnerable_packages(self):
        result = (
            self.dep_vulns.groupby("package_name")
            .agg(
                affected_repositories=(
                    "repository",
                    "nunique",
                ),
                vulnerability_count=(
                    "vulnerability_id",
                    "count",
                ),
                unique_vulnerabilities=(
                    "vulnerability_id",
                    "nunique",
                ),
                critical_vulnerabilities=(
                    "normalized_severity",
                    lambda x: (x == "CRITICAL").sum(),
                ),
                high_vulnerabilities=(
                    "normalized_severity",
                    lambda x: (x == "HIGH").sum(),
                ),
                average_cvss=(
                    "cvss_score",
                    "mean",
                ),
                max_cvss=(
                    "cvss_score",
                    "max",
                ),
                average_risk=(
                    "risk",
                    "mean",
                ),
                max_risk=(
                    "risk",
                    "max",
                ),
            )
            .reset_index()
        )

        return result.sort_values(
            by="vulnerability_count",
            ascending=False,
        )

    # =========================================================
    # TOP CWES
    # =========================================================

    def top_cwes(self):
        dep = self.dep_vulns.copy()

        dep = dep.explode("cwe")

        dep = dep[dep["cwe"].notna()]

        cwes = (
            dep.groupby("cwe")
            .agg(
                frequency=(
                    "vulnerability_id",
                    "count",
                ),
                repositories_affected=(
                    "repository",
                    "nunique",
                ),
                average_cvss=(
                    "cvss_score",
                    "mean",
                ),
                max_cvss=(
                    "cvss_score",
                    "max",
                ),
                description=(
                    "description",
                    "first",
                ),
            )
            .reset_index()
        )

        return cwes.sort_values(
            by="frequency",
            ascending=False,
        )

    # =========================================================
    # LANGUAGE RISK
    # =========================================================

    def language_risk(self):
        result = (
            self.dep_vulns.groupby("language")
            .agg(
                total_vulnerabilities=(
                    "vulnerability_id",
                    "count",
                ),
                affected_repositories=(
                    "repository",
                    "nunique",
                ),
                critical_count=(
                    "normalized_severity",
                    lambda x: (x == "CRITICAL").sum(),
                ),
                high_count=(
                    "normalized_severity",
                    lambda x: (x == "HIGH").sum(),
                ),
                average_cvss=(
                    "cvss_score",
                    "mean",
                ),
                max_cvss=(
                    "cvss_score",
                    "max",
                ),
            )
            .reset_index()
        )

        return result.sort_values(
            by="total_vulnerabilities",
            ascending=False,
        )

    # =========================================================
    # REPOSITORY DEPENDENCY STATS
    # =========================================================

    def repository_dependency_stats(self):
        stats = (
            self.dep_vulns.groupby("repository")
            .agg(
                total_dependency_vulnerabilities=(
                    "vulnerability_id",
                    "count",
                ),
                unique_dependencies=(
                    "package_name",
                    "nunique",
                ),
                unique_vulnerabilities=(
                    "vulnerability_id",
                    "nunique",
                ),
                critical_dependency_vulnerabilities=(
                    "normalized_severity",
                    lambda x: (x == "CRITICAL").sum(),
                ),
                average_cvss=(
                    "cvss_score",
                    "mean",
                ),
            )
            .reset_index()
        )

        return stats.sort_values(
            by="total_dependency_vulnerabilities",
            ascending=False,
        )

    # =========================================================
    # REPOSITORY CODEQL STATS
    # =========================================================

    def repository_codeql_stats(self):
        stats = (
            self.code_vulns.groupby("repository_id")
            .agg(
                total_code_vulnerabilities=(
                    "finding_id",
                    "count",
                ),
                unique_rules=(
                    "rule_id",
                    "nunique",
                ),
                high_severity_findings=(
                    "normalized_severity",
                    lambda x: (x == "HIGH").sum(),
                ),
                medium_severity_findings=(
                    "normalized_severity",
                    lambda x: (x == "MEDIUM").sum(),
                ),
            )
            .reset_index()
        )

        return stats.sort_values(
            by="total_code_vulnerabilities",
            ascending=False,
        )

    # =========================================================
    # CROSS REPOSITORY PATTERNS
    # =========================================================

    def cross_repository_patterns(self):
        patterns = (
            self.dep_vulns.groupby("vulnerability_id")
            .agg(
                affected_repositories=(
                    "repository",
                    "nunique",
                ),
                total_occurrences=(
                    "repository",
                    "count",
                ),
                affected_packages=(
                    "package_name",
                    "nunique",
                ),
                average_cvss=(
                    "cvss_score",
                    "mean",
                ),
                description=(
                    "description",
                    "first",
                ),
            )
            .reset_index()
        )

        return patterns.sort_values(
            by="affected_repositories",
            ascending=False,
        )
