export default function InsightList({ insights }) {
    if (!insights || insights.length === 0) {
        return null;
    }

    return (
        <section
            style={{
                marginBottom: "2rem",
            }}
        >
            <div
                style={{
                    marginBottom: "1rem",
                }}
            >
                <h2
                    style={{
                        margin: 0,
                        fontSize: "1.5rem",
                    }}
                >
                    Insights ejecutivos
                </h2>

                <p
                    style={{
                        marginTop: "0.35rem",
                        color: "#666",
                        fontSize: "0.95rem",
                    }}
                >
                    Hallazgos clave extraídos desde datos de repositorios,
                    dependencias, lenguajes, CWE y vulnerabilidades presentes en
                    múltiples repositorios.
                </p>
            </div>

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                    gap: "1rem",
                }}
            >
                {insights.map((insight) => (
                    <article
                        key={insight.title}
                        style={{
                            background: "white",
                            padding: "1rem",
                            borderRadius: "12px",
                            boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
                            border: "1px solid #eee",
                        }}
                    >
                        <div
                            style={{
                                fontSize: "0.8rem",
                                color: "#666",
                                marginBottom: "0.5rem",
                            }}
                        >
                            {insight.title}
                        </div>

                        <div
                            style={{
                                fontSize: "1.35rem",
                                fontWeight: "bold",
                                marginBottom: "0.15rem",
                                wordBreak: "break-word",
                            }}
                        >
                            {insight.metric}
                        </div>

                        <div
                            style={{
                                fontSize: "0.75rem",
                                color: "#777",
                                textTransform: "uppercase",
                                letterSpacing: "0.04em",
                                marginBottom: "0.75rem",
                            }}
                        >
                            {insight.label}
                        </div>

                        <p
                            style={{
                                color: "#555",
                                fontSize: "0.9rem",
                                lineHeight: 1.45,
                                margin: 0,
                            }}
                        >
                            {insight.text}
                        </p>
                    </article>
                ))}
            </div>
        </section>
    );
}