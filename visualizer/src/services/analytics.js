import { getConnection } from "./duckdb";
import { normalizeTable } from "../utils/normalizeRows";

async function query(sql) {
  const conn = await getConnection();
  const result = await conn.query(sql);

  return normalizeTable(result);
}

async function safeQuery(label, sql, fallback = []) {
  try {
    const data = await query(sql);

    console.log(`[OK] ${label}`);

    return {
      data,
      error: null,
    };
  } catch (error) {
    console.error(`[FAILED] ${label}`, error);

    return {
      data: fallback,
      error:
        error instanceof Error
          ? error.message
          : "Unknown query error",
    };
  }
}

export async function getDashboardData() {
  const [
    repositoryRisk,
    languageRisk,
    topPackages,
    topCwes,
    crossRepoPatterns,
    severityDistribution,
    dependencyStats,
    codeqlStats,
    repositorySummary,
  ] = await Promise.all([
    safeQuery(
      "repositoryRisk",
      `
      SELECT *
      FROM 'repository_risk.parquet'
      ORDER BY risk_score DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "languageRisk",
      `
      SELECT *
      FROM 'language_risk.parquet'
      ORDER BY total_vulnerabilities DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "topPackages",
      `
      SELECT *
      FROM 'top_vulnerable_packages.parquet'
      ORDER BY vulnerability_count DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "topCwes",
      `
      SELECT *
      FROM 'top_cwes.parquet'
      ORDER BY frequency DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "crossRepoPatterns",
      `
      SELECT *
      FROM 'cross_repository_patterns.parquet'
      ORDER BY affected_repositories DESC,
               total_occurrences DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "severityDistribution",
      `
      SELECT
        normalized_severity,
        SUM(count) AS count
      FROM 'severity_distribution.parquet'
      GROUP BY normalized_severity
      ORDER BY count DESC
      `
    ),

    safeQuery(
      "dependencyStats",
      `
      SELECT *
      FROM 'repository_dependency_stats.parquet'
      ORDER BY total_dependency_vulnerabilities DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "codeqlStats",
      `
      SELECT *
      FROM 'repository_codeql_stats.parquet'
      ORDER BY total_code_vulnerabilities DESC
      LIMIT 10
      `
    ),

    safeQuery(
      "repositorySummary",
      `
      SELECT *
      FROM 'repository_summary.parquet'
      ORDER BY total_vulnerabilities DESC
      LIMIT 10
      `
    ),
  ]);

  return {
    repositoryRisk,
    languageRisk,
    topPackages,
    topCwes,
    crossRepoPatterns,
    severityDistribution,
    dependencyStats,
    codeqlStats,
    repositorySummary,
  };
}