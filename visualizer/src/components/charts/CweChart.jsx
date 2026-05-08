import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

const PALETTE = [
    "#0891b2", "#7c3aed", "#ea580c", "#16a34a", "#dc2626",
    "#2563eb", "#d946ef", "#ca8a04", "#64748b", "#0d9488",
];

function CweTooltip({ active, payload }) {
    if (!active || !payload || !payload.length) return null;
    const item = payload[0].payload;
    return (
        <div
            style={{
                background: "white",
                border: "1px solid #ddd",
                borderRadius: 8,
                padding: "0.75rem 1rem",
                maxWidth: 360,
                boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
                fontSize: "0.85rem",
                lineHeight: 1.4,
            }}
        >
            <div style={{ fontWeight: "bold", marginBottom: 4 }}>
                {item.cwe}
            </div>
            <div style={{ color: "#555", marginBottom: 4 }}>
                Frecuencia: <b>{item.frequency}</b> &middot;
                Repositorios: <b>{item.repositories_affected}</b>
            </div>
            {item.average_cvss != null && (
                <div style={{ color: "#555", marginBottom: 4 }}>
                    CVSS promedio: <b>{Number(item.average_cvss).toFixed(2)}</b>
                </div>
            )}
            {item.description && (
                <div
                    style={{
                        color: "#666",
                        fontSize: "0.8rem",
                        borderTop: "1px solid #eee",
                        paddingTop: 6,
                        marginTop: 4,
                    }}
                >
                    {item.description}
                </div>
            )}
        </div>
    );
}

export default function CweChart({ data }) {
    return (
        <div style={{ width: "100%", height: 360 }}>
            <ResponsiveContainer>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />

                    <XAxis
                        dataKey="cwe"
                        tick={{ fontSize: 11 }}
                        interval={0}
                        angle={-25}
                        textAnchor="end"
                        height={90}
                    />

                    <YAxis />

                    <Tooltip content={<CweTooltip />} />

                    <Bar dataKey="frequency" name="Frequency">
                        {data.map((_, index) => (
                            <Cell
                                key={index}
                                fill={PALETTE[index % PALETTE.length]}
                            />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}