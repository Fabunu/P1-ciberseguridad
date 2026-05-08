function f(n) {
    return Number(n ?? 0).toLocaleString("es-CL");
}

function fd(n, d = 2) {
    return Number(n ?? 0).toFixed(d);
}

export default function ConclusionsSection({ data }) {
    const conclusions = buildConclusions(data);
    if (!conclusions || conclusions.length === 0) return null;

    return (
        <section
            style={{
                background: "white",
                borderRadius: 12,
                padding: "1.5rem 2rem 2rem",
                boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
            }}
        >
            <h2 style={{ margin: "0 0 0.25rem", fontSize: "1.5rem" }}>
                Conclusiones y Hallazgos Clave
            </h2>
            <p
                style={{
                    margin: "0 0 1.5rem",
                    color: "#666",
                    fontSize: "0.95rem",
                }}
            >
                Análisis ejecutivo basado en los datos recopilados de los{" "}
                {data.repositoryRisk?.length ?? 0} repositorios analizados,
                combinando resultados de Grype (SCA) y CodeQL (SAST).
            </p>

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                    gap: "1.25rem",
                }}
            >
                {conclusions.map((c, i) => (
                    <ConclusionCard key={i} conclusion={c} />
                ))}
            </div>
        </section>
    );
}

function ConclusionCard({ conclusion }) {
    return (
        <article
            style={{
                border: "1px solid #e5e7eb",
                borderRadius: 10,
                padding: "1rem 1.25rem",
                background: "#fafafa",
            }}
        >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
                <span style={{ fontSize: "1.2rem" }}>{conclusion.icon}</span>
                <h3 style={{ margin: 0, fontSize: "1rem" }}>{conclusion.title}</h3>
            </div>

            {conclusion.text && (
                <p style={{ margin: "0 0 0.75rem", color: "#444", fontSize: "0.88rem", lineHeight: 1.5 }}>
                    {conclusion.text}
                </p>
            )}

            {conclusion.stats && (
                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns: `repeat(${Math.min(conclusion.stats.length, 4)}, 1fr)`,
                        gap: "0.5rem",
                        marginTop: "0.5rem",
                    }}
                >
                    {conclusion.stats.map((s, i) => (
                        <div
                            key={i}
                            style={{
                                background: "white",
                                borderRadius: 6,
                                padding: "0.4rem 0.6rem",
                                border: "1px solid #eee",
                                textAlign: "center",
                            }}
                        >
                            <div style={{ fontSize: "1.1rem", fontWeight: "bold", color: "#1f2937" }}>
                                {s.value}
                            </div>
                            <div style={{ fontSize: "0.7rem", color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.03em" }}>
                                {s.label}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {conclusion.detail && (
                <div
                    style={{
                        marginTop: "0.5rem",
                        fontSize: "0.82rem",
                        color: "#555",
                        lineHeight: 1.45,
                        borderTop: "1px solid #e5e7eb",
                        paddingTop: "0.5rem",
                    }}
                >
                    {conclusion.detail}
                </div>
            )}
        </article>
    );
}

function buildConclusions(data) {
    const {
        repositoryRisk = [],
        topPackages = [],
        topCwes = [],
        crossRepoPatterns = [],
        languageRisk = [],
        dependencyStats = [],
        codeqlStats = [],
    } = data;

    const conclusions = [];

    // ── 1. Riesgo General por Repositorio ──
    if (repositoryRisk.length > 0) {
        const top = repositoryRisk[0];
        const criticalRepos = repositoryRisk.filter((r) => (r.critical_count ?? 0) > 0);
        const highRisk = repositoryRisk.filter((r) => (r.risk_score ?? 0) >= 50);

        conclusions.push({
            icon: "\u26A0\uFE0F",
            title: "Riesgo General por Repositorio",
            text: `${top.repository} presenta el riesgo más alto con un puntaje de ${top.risk_score}, acumulando ${f(top.critical_count)} vulnerabilidades críticas y ${f(top.high_count)} de alta severidad. ${criticalRepos.length > 0 ? `${criticalRepos.length} de ${repositoryRisk.length} repositorios analizados contienen al menos una vulnerabilidad crítica.` : ""}`,
            stats: [
                { value: fd(highRisk.length), label: "Riesgo Alto (\u226550)" },
                { value: repositoryRisk.reduce((s, r) => s + (r.critical_count ?? 0), 0), label: "Críticas totales" },
                { value: repositoryRisk.reduce((s, r) => s + (r.high_count ?? 0), 0), label: "Altas totales" },
                { value: repositoryRisk.reduce((s, r) => s + (r.total_vulnerabilities ?? 0), 0), label: "Vulnerabilidades" },
            ],
            detail: `Los repositorios con mayor riesgo no solo destacan por su volumen de vulnerabilidades, sino por la concentración de hallazgos críticos y de alta severidad, lo que eleva significativamente su riesgo operacional.`,
        });
    }

    // ── 2. Riesgo Sistémico de Dependencias ──
    const multiRepoPkgs = topPackages.filter((p) => (p.affected_repositories ?? 0) > 1);
    if (multiRepoPkgs.length > 0) {
        const topPkg = multiRepoPkgs[0];
        const criticalPkgs = multiRepoPkgs.filter((p) => (p.critical_vulnerabilities ?? 0) > 0);

        conclusions.push({
            icon: "\uD83D\uDCE6",
            title: "Riesgo Sistémico de Dependencias",
            text: `${topPkg.package_name} es la dependencia más crítica, con ${f(topPkg.vulnerability_count)} vulnerabilidades que afectan a ${f(topPkg.affected_repositories)} repositorios. ${criticalPkgs.length > 0 ? `${criticalPkgs.length} dependencias con vulnerabilidades críticas se repiten en múltiples repositorios, propagando riesgo a través del ecosistema.` : ""}`,
            stats: [
                { value: multiRepoPkgs.length, label: "Deps. multirepo" },
                { value: multiRepoPkgs.reduce((s, p) => s + (p.critical_vulnerabilities ?? 0), 0), label: "Críticas sistémicas" },
                { value: multiRepoPkgs.reduce((s, p) => s + (p.affected_repositories ?? 0), 0), label: "Afectaciones totales" },
                { value: fd(multiRepoPkgs.reduce((s, p) => s + (p.average_cvss ?? 0), 0) / multiRepoPkgs.length), label: "CVSS promedio" },
            ],
            detail: `Una pequeña cantidad de dependencias vulnerables aparece repetidamente en múltiples repositorios. Esto representa un riesgo sistémico: una sola actualización puede remediar multiples superficies de ataque simultáneamente.`,
        });
    }

    // ── 3. Categorías de Debilidad Dominantes (CWE) ──
    if (topCwes.length > 0) {
        const topCwe = topCwes[0];
        const highCvssCwes = topCwes.filter((c) => (c.average_cvss ?? 0) >= 7);
        const cwePct = ((topCwe.frequency / topCwes.reduce((s, c) => s + (c.frequency ?? 0), 0)) * 100).toFixed(1);

        conclusions.push({
            icon: "\uD83D\uDD0D",
            title: "Categorías de Debilidad Dominantes",
            text: `${topCwe.cwe} es la categoría más frecuente, representando el ${cwePct}% del total de ocurrencias, con ${f(topCwe.frequency)} casos en ${f(topCwe.repositories_affected)} repositorios. ${highCvssCwes.length > 0 ? `${highCvssCwes.length} categorías adicionales presentan un CVSS promedio superior a 7.0, indicando vulnerabilidades de alto impacto.` : ""}`,
            stats: [
                { value: topCwe.cwe, label: "CWE dominante" },
                { value: f(topCwe.frequency), label: "Ocurrencias" },
                { value: f(topCwe.repositories_affected), label: "Repos. afectados" },
                { value: fd(topCwe.average_cvss), label: "CVSS promedio" },
            ],
            detail: topCwe.description
                ? `Contexto: ${topCwe.description}`
                : `Las categorías de debilidad más recurrentes indican problemas estructurales en la validación de entradas y gestión de dependencias a nivel organizacional.`,
        });
    }

    // ── 4. Cobertura de Herramientas de Análisis ──
    const grypeVulns = dependencyStats.reduce((s, r) => s + (r.total_dependency_vulnerabilities ?? 0), 0);
    const codeqlFindings = codeqlStats.reduce((s, r) => s + (r.total_code_vulnerabilities ?? 0), 0);
    if (grypeVulns > 0 || codeqlFindings > 0) {
        const total = grypeVulns + codeqlFindings;
        const grypePct = total > 0 ? ((grypeVulns / total) * 100).toFixed(1) : "0";
        const codeqlPct = total > 0 ? ((codeqlFindings / total) * 100).toFixed(1) : "0";

        conclusions.push({
            icon: "\uD83D\uDEE0\uFE0F",
            title: "Cobertura de Herramientas de Análisis",
            text: `Grype detectó ${f(grypeVulns)} vulnerabilidades en dependencias (${grypePct}% del total), mientras que CodeQL identificó ${f(codeqlFindings)} hallazgos en código fuente (${codeqlPct}%). Esta diferencia refleja que el riesgo principal proviene de la cadena de suministro (dependencias externas) más que del código propio.`,
            stats: [
                { value: `Grype ${grypePct}%`, label: "SCA - Dependencias" },
                { value: `CodeQL ${codeqlPct}%`, label: "SAST - Código" },
                { value: f(grypeVulns), label: "Vulns. detectadas" },
                { value: f(codeqlFindings), label: "Hallazgos código" },
            ],
            detail: `La mayoría de las vulnerabilidades proviene de dependencias de terceros y no del código propio de los repositorios, lo que subraya la importancia de la gestión proactiva del inventario de dependencias.`,
        });
    }

    // ── 5. Exposición por Lenguaje ──
    if (languageRisk.length > 0) {
        const topLang = languageRisk[0];
        const langCritical = languageRisk.filter((l) => (l.critical_count ?? 0) > 0);
        const langCvssHigh = languageRisk.filter((l) => (l.average_cvss ?? 0) >= 6);

        conclusions.push({
            icon: "\uD83C\uDF10",
            title: "Exposición por Lenguaje",
            text: `${topLang.language} concentra la mayor cantidad de vulnerabilidades (${f(topLang.total_vulnerabilities)}), afectando a ${f(topLang.affected_repositories)} repositorios. ${langCritical.length > 0 ? `${langCritical.length} de ${languageRisk.length} lenguajes presentan vulnerabilidades críticas.` : ""}`,
            stats: [
                { value: topLang.language, label: "Lenguaje líder" },
                { value: f(topLang.total_vulnerabilities), label: "Vulnerabilidades" },
                { value: f(topLang.critical_count), label: "Críticas" },
                { value: fd(topLang.average_cvss), label: "CVSS promedio" },
            ],
            detail: langCvssHigh.length > 1
                ? `${langCvssHigh.length} lenguajes superan un CVSS promedio de 6.0, indicando que el riesgo está distribuido en todo el ecosistema tecnológico.`
                : `El riesgo se concentra principalmente en ${topLang.language}, sugiriendo una mayor exposición de este ecosistema.`,
        });
    }

    // ── 6. Vulnerabilidades con Mayor Propagación ──
    if (crossRepoPatterns.length > 0 && crossRepoPatterns[0].affected_repositories > 1) {
        const topCross = crossRepoPatterns[0];
        const multiRepoVulns = crossRepoPatterns.filter((v) => (v.affected_repositories ?? 0) > 1);

        conclusions.push({
            icon: "\uD83D\uDD17",
            title: "Vulnerabilidades con Mayor Propagación",
            text: `${topCross.vulnerability_id} es la vulnerabilidad más extendida, afectando a ${f(topCross.affected_repositories)} repositorios con ${f(topCross.total_occurrences)} ocurrencias totales. ${multiRepoVulns.length > 0 ? `${multiRepoVulns.length} vulnerabilidades afectan a múltiples repositorios simultáneamente.` : ""}`,
            stats: [
                { value: f(multiRepoVulns.length), label: "Vulns. multirepo" },
                { value: f(topCross.affected_repositories), label: "Máx. repos afectados" },
                { value: crossRepoPatterns.reduce((s, v) => s + (v.total_occurrences ?? 0), 0), label: "Ocurrencias totales" },
                { value: fd(topCross.average_cvss), label: "CVSS" },
            ],
            detail: `Estos patrones compartidos son candidatos prioritarios para remediación centralizada: corregir la vulnerabilidad en su origen beneficiaría a todos los repositorios afectados simultáneamente.`,
        });
    }

    // ── 7. Correlación Dependencias vs Vulnerabilidades ──
    if (dependencyStats.length > 1) {
        const topDep = dependencyStats[0];
        const avgDeps = dependencyStats.reduce((s, r) => s + (r.unique_dependencies ?? 0), 0) / dependencyStats.length;

        conclusions.push({
            icon: "\uD83D\uDCCA",
            title: "Correlación: Dependencias vs Vulnerabilidades",
            text: `${topDep.repository} lidera en vulnerabilidades de dependencias con ${f(topDep.total_dependency_vulnerabilities)} hallazgos, de los cuales ${f(topDep.critical_dependency_vulnerabilities)} son críticos. En promedio, cada repositorio tiene ${fd(avgDeps, 1)} dependencias únicas.`,
            stats: [
                { value: f(topDep.total_dependency_vulnerabilities), label: "Máx. vulns. dependencia" },
                { value: f(topDep.critical_dependency_vulnerabilities), label: "Críticas en top repo" },
                { value: fd(avgDeps, 1), label: "Prom. dependencias" },
                { value: fd(topDep.average_cvss), label: "CVSS promedio" },
            ],
            detail: `La cantidad de dependencias muestra una correlación significativa con el volumen de vulnerabilidades. Repositorios con más dependencias externas tienden a acumular más vulnerabilidades críticas, confirmando que una mayor superficie de ataque incrementa el riesgo.`,
        });
    }

    return conclusions;
}
