import { useEffect, useMemo, useState } from "react";

import { getDashboardData } from "./services/analytics";
import { buildInsights } from "./utils/buildInsights";

import KPIGrid from "./components/KPIGrid";
import InsightList from "./components/InsightList";
import RepositoryTable from "./components/RepositoryTable";
import SectionCard from "./components/SectionCard";

import RiskBarChart from "./components/charts/RiskBarChart";
import SeverityPieChart from "./components/charts/SeverityPieChart";
import LanguageRiskChart from "./components/charts/LanguageRiskChart";
import PackagesChart from "./components/charts/PackagesChart";
import CweChart from "./components/charts/CweChart";
import CrossRepoTable from "./components/CrossRepoTable";

export default function App() {
  const [data, setData] = useState({
    repositoryRisk: [],
    languageRisk: [],
    topPackages: [],
    topCwes: [],
    crossRepoPatterns: [],
    severityDistribution: [],
    dependencyStats: [],
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        const dashboardData = await getDashboardData();
        console.log("dashBD", dashboardData);
        setData(dashboardData);
      } catch (err) {
        console.error("Failed to load dashboard data", err);
        setError("No se pudieron cargar los datos del dashboard.");
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  const kpis = useMemo(() => {
    const repos = data.repositoryRisk;

    const totalRepos = repos.length;

    const totalVulnerabilities = repos.reduce(
      (acc, repo) => acc + Number(repo.total_vulnerabilities ?? 0),
      0
    );

    const criticalVulnerabilities = repos.reduce(
      (acc, repo) => acc + Number(repo.critical_count ?? 0),
      0
    );

    const avgRisk =
      repos.length > 0
        ? repos.reduce((acc, repo) => acc + Number(repo.risk_score ?? 0), 0) /
        repos.length
        : 0;

    return {
      totalRepos,
      totalVulnerabilities,
      criticalVulnerabilities,
      avgRisk: Number(avgRisk.toFixed(2)),
      riskyPackages: data.topPackages.length,
      repeatedPatterns: data.crossRepoPatterns.length,
    };
  }, [data]);

  const insights = useMemo(() => buildInsights(data), [data]);

  if (loading) {
    return (
      <div
        style={{
          padding: "2rem",
          background: "#f5f5f5",
          minHeight: "100vh",
        }}
      >
        Cargando analítica de seguridad...
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          padding: "2rem",
          background: "#f5f5f5",
          minHeight: "100vh",
          color: "#991b1b",
        }}
      >
        {error}
      </div>
    );
  }

  return (
    <div
      style={{
        padding: "2rem",
        background: "#f5f5f5",
        minHeight: "100vh",
      }}
    >
      <header
        style={{
          marginBottom: "2rem",
        }}
      >
        <h1
          style={{
            fontSize: "2.5rem",
            margin: 0,
          }}
        >
          Dashboard de analítica de seguridad
        </h1>

        <p
          style={{
            color: "#666",
            marginTop: "0.5rem",
            maxWidth: "900px",
          }}
        >
          Vista ejecutiva del riesgo por repositorio, severidad de
          vulnerabilidades, dependencias vulnerables, CWE recurrentes y
          exposición entre múltiples repositorios.
        </p>
      </header>

      <KPIGrid {...kpis} />

      <InsightList insights={insights} />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
          gap: "1.5rem",
          marginBottom: "1.5rem",
        }}
      >
        <SectionCard
          title="Repositorios con mayor riesgo"
          description="Repositorios ordenados por puntaje de riesgo calculado."
        >
          <RiskBarChart data={data.repositoryRisk} />
        </SectionCard>

        <SectionCard
          title="Distribución por severidad"
          description="Total de vulnerabilidades agrupadas por severidad normalizada."
        >
          <SeverityPieChart data={data.severityDistribution} />
        </SectionCard>

        <SectionCard
          title="Riesgo por lenguaje"
          description="Lenguajes con mayor concentración de vulnerabilidades."
        >
          <LanguageRiskChart data={data.languageRisk} />
        </SectionCard>

        <SectionCard
          title="Paquetes más vulnerables"
          description="Dependencias con mayor cantidad de vulnerabilidades."
        >
          <PackagesChart data={data.topPackages} />
        </SectionCard>
      </div>

      <SectionCard
        title="CWE más frecuentes"
        description="Categorías de debilidad que aparecen con mayor frecuencia en los repositorios analizados."
      >
        <CweChart data={data.topCwes} />
      </SectionCard>

      <div style={{ height: "1.5rem" }} />

      <SectionCard
        title="Patrones de vulnerabilidad entre repositorios"
        description="Vulnerabilidades que afectan a múltiples repositorios. Son candidatas fuertes para remediación centralizada."
      >
        <CrossRepoTable data={data.crossRepoPatterns} />
      </SectionCard>

      <div style={{ height: "1.5rem" }} />

      <RepositoryTable data={data.repositoryRisk} />
    </div>
  );
}