import { getConnection } from "./duckdb";
import { normalizeTable } from "../utils/normalizeRows";

async function query(sql) {
  const conn = await getConnection();
  const result = await conn.query(sql);

  return normalizeTable(result);
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
  ] = await Promise.all([
    query(`
      SELECT *
      FROM 'repository_risk.parquet'
      ORDER BY risk_score DESC
      LIMIT 10
    `),

    query(`
      SELECT *
      FROM 'language_risk.parquet'
      ORDER BY total_vulnerabilities DESC
      LIMIT 10
    `),

    query(`
      SELECT *
      FROM 'top_vulnerable_packages.parquet'
      ORDER BY vulnerability_count DESC
      LIMIT 10
    `),

    query(`
      SELECT *
      FROM 'top_cwes.parquet'
      ORDER BY frequency DESC
      LIMIT 10
    `),

    query(`
      SELECT *
      FROM 'cross_repository_patterns.parquet'
      ORDER BY affected_repositories DESC, total_occurrences DESC
      LIMIT 10
    `),

    query(`
      SELECT
        normalized_severity,
        SUM(count) AS count
      FROM 'severity_distribution.parquet'
      GROUP BY normalized_severity
      ORDER BY count DESC
    `),

    query(`
      SELECT *
      FROM 'repository_dependency_stats.parquet'
      ORDER BY total_dependency_vulnerabilities DESC
      LIMIT 10
    `),
  ]);

  return {
    repositoryRisk,
    languageRisk,
    topPackages,
    topCwes,
    crossRepoPatterns,
    severityDistribution,
    dependencyStats,
  };
}