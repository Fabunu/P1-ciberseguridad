function formatNumber(value) {
  return Number(value ?? 0).toLocaleString("es-CL");
}

function formatDecimal(value, decimals = 2) {
  return Number(value ?? 0).toFixed(decimals);
}

export function buildInsights(data) {
  const topRepo = data.repositoryRisk?.[0];
  const topLanguage = data.languageRisk?.[0];
  const topPackage = data.topPackages?.[0];
  const topCwe = data.topCwes?.[0];
  const topCrossRepo = data.crossRepoPatterns?.[0];

  const insights = [];

  if (topRepo) {
    insights.push({
      title: "Repositorio con mayor riesgo",
      metric: formatDecimal(topRepo.risk_score),
      label: "puntaje de riesgo",
      text: `${topRepo.repository} tiene el puntaje de riesgo más alto, con ${formatNumber(
        topRepo.total_vulnerabilities
      )} vulnerabilidades, incluyendo ${formatNumber(
        topRepo.critical_count
      )} críticas y ${formatNumber(topRepo.high_count)} de severidad alta.`,
    });
  }

  if (topLanguage) {
    insights.push({
      title: "Lenguaje más expuesto",
      metric: topLanguage.language,
      label: "lenguaje",
      text: `${topLanguage.language} concentra ${formatNumber(
        topLanguage.total_vulnerabilities
      )} vulnerabilidades en ${formatNumber(
        topLanguage.affected_repositories
      )} repositorios.`,
    });
  }

  if (topPackage) {
    insights.push({
      title: "Paquete más vulnerable",
      metric: topPackage.package_name,
      label: "paquete",
      text: `${topPackage.package_name} aparece con ${formatNumber(
        topPackage.vulnerability_count
      )} vulnerabilidades que afectan a ${formatNumber(
        topPackage.affected_repositories
      )} repositorios. Su CVSS promedio es ${formatDecimal(
        topPackage.average_cvss
      )}.`,
    });
  }

  if (topCwe) {
    insights.push({
      title: "Debilidad más común",
      metric: topCwe.cwe,
      label: "CWE",
      text: `${topCwe.cwe} es la categoría de debilidad más frecuente, con ${formatNumber(
        topCwe.frequency
      )} ocurrencias en ${formatNumber(
        topCwe.repositories_affected
      )} repositorios.`,
    });
  }

  if (topCrossRepo) {
    insights.push({
      title: "Mayor exposición entre repositorios",
      metric: topCrossRepo.vulnerability_id,
      label: "vulnerabilidad",
      text: `${topCrossRepo.vulnerability_id} afecta a ${formatNumber(
        topCrossRepo.affected_repositories
      )} repositorios y aparece ${formatNumber(
        topCrossRepo.total_occurrences
      )} veces. Es una candidata fuerte para remediación centralizada.`,
    });
  }

  return insights;
}