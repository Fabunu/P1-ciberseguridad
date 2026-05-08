export default function KPIGrid({
    totalRepos,
    totalVulnerabilities,
    criticalVulnerabilities,
    avgRisk,
    riskyPackages,
    repeatedPatterns,
}) {
    const items = [
        {
            title: "Top Repositories",
            value: totalRepos,
        },
        {
            title: "Vulnerabilities",
            value: totalVulnerabilities,
        },
        {
            title: "Critical",
            value: criticalVulnerabilities,
        },
        {
            title: "Avg Risk",
            value: avgRisk,
        },
        {
            title: "Risky Packages",
            value: riskyPackages,
        },
        {
            title: "Repeated Patterns",
            value: repeatedPatterns,
        },
    ];

    return (
        <div
            style={{
                display: "grid",
                gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
                gap: "1rem",
                marginBottom: "2rem",
            }}
        >
            {items.map((item) => (
                <div
                    key={item.title}
                    style={{
                        background: "white",
                        padding: "1.5rem",
                        borderRadius: "12px",
                        boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
                    }}
                >
                    <div
                        style={{
                            fontSize: "0.85rem",
                            color: "#666",
                        }}
                    >
                        {item.title}
                    </div>

                    <div
                        style={{
                            fontSize: "2rem",
                            fontWeight: "bold",
                            marginTop: "0.5rem",
                        }}
                    >
                        {item.value}
                    </div>
                </div>
            ))}
        </div>
    );
}