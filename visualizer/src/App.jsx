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
import TopCwesTable from "./components/TopCwesTable";
import TopPackagesTable from "./components/TopPackagesTable";
import ConclusionsSection from "./components/ConclusionsSection";

function ErrorBanner({ error }) {
  if (!error) return null;

  return (
    <div
      style={{
        background: "#fef2f2",
        border: "1px solid #fecaca",
        color: "#991b1b",
        padding: "0.75rem 1rem",
        borderRadius: "10px",
        marginBottom: "1rem",
        fontSize: "0.95rem",
      }}
    >
      {error}
    </div>
  );
}

export default function App() {
  const [data, setData] = useState({
    repositoryRisk: {
      data: [],
      error: null,
    },

    languageRisk: {
      data: [],
      error: null,
    },

    topPackages: {
      data: [],
      error: null,
    },

    topCwes: {
      data: [],
      error: null,
    },

    crossRepoPatterns: {
      data: [],
      error: null,
    },

    severityDistribution: {
      data: [],
      error: null,
    },

    dependencyStats: {
      data: [],
      error: null,
    },

    codeqlStats: {
      data: [],
      error: null,
    },

    repositorySummary: {
      data: [],
      error: null,
    },
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboard() {
      try {
        const dashboardData =
          await getDashboardData();

        console.log(
          "dashboardData",
          dashboardData
        );

        setData(dashboardData);
      } catch (err) {
        console.error(
          "Unexpected dashboard error",
          err
        );
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  const kpis = useMemo(() => {
    const repos =
      data.repositoryRisk.data;

    const totalRepos = repos.length;

    const totalVulnerabilities =
      repos.reduce(
        (acc, repo) =>
          acc +
          Number(
            repo.total_vulnerabilities ??
            0
          ),
        0
      );

    const criticalVulnerabilities =
      repos.reduce(
        (acc, repo) =>
          acc +
          Number(
            repo.critical_count ?? 0
          ),
        0
      );

    const avgRisk =
      repos.length > 0
        ? repos.reduce(
          (acc, repo) =>
            acc +
            Number(
              repo.risk_score ?? 0
            ),
          0
        ) / repos.length
        : 0;

    return {
      totalRepos,

      totalVulnerabilities,

      criticalVulnerabilities,

      avgRisk: Number(
        avgRisk.toFixed(2)
      ),

      riskyPackages:
        data.topPackages.data.length,

      repeatedPatterns:
        data.crossRepoPatterns.data
          .length,
    };
  }, [data]);

  const insights = useMemo(
    () =>
      buildInsights({
        repositoryRisk:
          data.repositoryRisk.data,

        languageRisk:
          data.languageRisk.data,

        topPackages:
          data.topPackages.data,

        topCwes:
          data.topCwes.data,

        crossRepoPatterns:
          data.crossRepoPatterns
            .data,

        severityDistribution:
          data.severityDistribution
            .data,

        dependencyStats:
          data.dependencyStats
            .data,

        codeqlStats:
          data.codeqlStats.data,

        repositorySummary:
          data.repositorySummary
            .data,
      }),
    [data]
  );

  if (loading) {
    return (
      <div
        style={{
          padding: "2rem",
          background: "#f5f5f5",
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          gap: "1rem",
          fontFamily: "sans-serif",
          color: "#444",
        }}
      >
        <div
          style={{
            width: "60px",
            height: "60px",
            border:
              "6px solid #ddd",
            borderTop:
              "6px solid #007bff",
            borderRadius: "50%",
            animation:
              "spin 1s linear infinite",
          }}
        />

        <div
          style={{
            textAlign: "center",
            fontSize: "1.1rem",
          }}
        >
          Cargando analítica de
          seguridad...
          <br />
          Esto puede tomar algunos
          minutos...
          <br />
          Espere por favor...
        </div>

        <style>
          {`
            @keyframes spin {
              0% {
                transform: rotate(0deg);
              }

              100% {
                transform: rotate(360deg);
              }
            }
          `}
        </style>
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
          Dashboard de analítica de
          seguridad - Trinodb
        </h1>

        <p
          style={{
            color: "#666",
            marginTop: "0.5rem",
            maxWidth: "900px",
          }}
        >
          Vista ejecutiva del riesgo
          por repositorio,
          severidad de
          vulnerabilidades,
          dependencias vulnerables,
          CWE recurrentes y
          exposición entre múltiples
          repositorios.
        </p>
      </header>

      <KPIGrid {...kpis} />

      <div
        style={{
          marginTop: "1.5rem",
        }}
      >
        <ErrorBanner
          error={
            data.repositoryRisk.error
          }
        />

        <ErrorBanner
          error={
            data.languageRisk.error
          }
        />

        <ErrorBanner
          error={
            data.topPackages.error
          }
        />

        <ErrorBanner
          error={data.topCwes.error}
        />

        <ErrorBanner
          error={
            data.crossRepoPatterns
              .error
          }
        />

        <ErrorBanner
          error={
            data.severityDistribution
              .error
          }
        />

        <ErrorBanner
          error={
            data.dependencyStats
              .error
          }
        />

        <ErrorBanner
          error={
            data.codeqlStats.error
          }
        />

        <ErrorBanner
          error={
            data.repositorySummary
              .error
          }
        />
      </div>

      <InsightList
        insights={insights}
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(2, minmax(0, 1fr))",
          gap: "1.5rem",
          marginBottom: "1.5rem",
        }}
      >
        <SectionCard
          title="Repositorios con mayor riesgo"
          description="Repositorios ordenados por puntaje de riesgo calculado."
        >
          <RiskBarChart
            data={
              data.repositoryRisk
                .data
            }
          />
        </SectionCard>

        <SectionCard
          title="Distribución por severidad"
          description="Total de vulnerabilidades agrupadas por severidad normalizada."
        >
          <SeverityPieChart
            data={
              data
                .severityDistribution
                .data
            }
          />
        </SectionCard>

        <SectionCard
          title="Riesgo por lenguaje"
          description="Lenguajes con mayor concentración de vulnerabilidades."
        >
          <LanguageRiskChart
            data={
              data.languageRisk.data
            }
          />
        </SectionCard>

        <SectionCard
          title="Paquetes más vulnerables"
          description="Dependencias con mayor cantidad de vulnerabilidades."
        >
          <PackagesChart
            data={
              data.topPackages.data
            }
          />
        </SectionCard>
      </div>

      <SectionCard
        title="CWE más frecuentes"
        description="Categorías de debilidad que aparecen con mayor frecuencia en los repositorios analizados."
      >
        <CweChart
          data={data.topCwes.data}
        />
      </SectionCard>

      <div
        style={{
          height: "1.5rem",
        }}
      />

      <SectionCard
        title="Detalle de CWE"
        description="Resumen tabular de las debilidades más frecuentes."
      >
        <TopCwesTable
          data={data.topCwes.data}
        />
      </SectionCard>

      <div
        style={{
          height: "1.5rem",
        }}
      />

      <SectionCard
        title="Paquetes más vulnerables — detalle"
        description="Dependencias ordenadas por cantidad de vulnerabilidades."
      >
        <TopPackagesTable
          data={
            data.topPackages.data
          }
        />
      </SectionCard>

      <div
        style={{
          height: "1.5rem",
        }}
      />

      <SectionCard
        title="Patrones de vulnerabilidad entre repositorios"
        description="Vulnerabilidades que afectan a múltiples repositorios."
      >
        <CrossRepoTable
          data={
            data
              .crossRepoPatterns
              .data
          }
        />
      </SectionCard>

      <div
        style={{
          height: "1.5rem",
        }}
      />

      <RepositoryTable
        data={
          data.repositoryRisk.data
        }
      />

      <div
        style={{
          height: "2rem",
        }}
      />

      <ConclusionsSection
        data={{
          repositoryRisk:
            data.repositoryRisk.data,
          topPackages:
            data.topPackages.data,
          topCwes: data.topCwes.data,
          crossRepoPatterns:
            data.crossRepoPatterns
              .data,
          languageRisk:
            data.languageRisk.data,
          dependencyStats:
            data.dependencyStats.data,
          codeqlStats:
            data.codeqlStats.data,
        }}
      />
    </div>
  );
}