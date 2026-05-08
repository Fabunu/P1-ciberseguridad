import {
    Cell,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    Legend,
} from "recharts";

const COLORS = {
    critical: "#7f1d1d",
    high: "#dc2626",
    medium: "#f59e0b",
    low: "#16a34a",
    unknown: "#6b7280",
};

const SEVERITY_LABELS = {
    critical: "Crítica",
    high: "Alta",
    medium: "Media",
    low: "Baja",
    unknown: "Desconocida",
};

function normalizeSeverity(value) {
    return String(value ?? "unknown").toLowerCase();
}

function formatSeverity(value) {
    const key = normalizeSeverity(value);

    return SEVERITY_LABELS[key] ?? value;
}

export default function SeverityPieChart({ data }) {
    const chartData = data
        .map((item) => {
            const severityKey = normalizeSeverity(item.normalized_severity);

            return {
                ...item,
                severityKey,
                severityLabel: formatSeverity(item.normalized_severity),
                count: Number(item.count ?? 0),
            };
        })
        .filter((item) => item.count > 0);

    if (chartData.length === 0) {
        return (
            <div
                style={{
                    width: "100%",
                    height: 320,
                    display: "grid",
                    placeItems: "center",
                    color: "#666",
                }}
            >
                No hay datos de severidad disponibles.
            </div>
        );
    }

    return (
        <div style={{ width: "100%", height: 320 }}>
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={chartData}
                        dataKey="count"
                        nameKey="severityLabel"
                        outerRadius={100}
                        label={({ severityLabel, count }) =>
                            `${severityLabel}: ${count}`
                        }
                    >
                        {chartData.map((entry) => (
                            <Cell
                                key={entry.severityKey}
                                fill={COLORS[entry.severityKey] ?? "#999"}
                            />
                        ))}
                    </Pie>

                    <Tooltip
                        formatter={(value) => [
                            Number(value).toLocaleString("es-CL"),
                            "Vulnerabilidades",
                        ]}
                    />

                    <Legend />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}