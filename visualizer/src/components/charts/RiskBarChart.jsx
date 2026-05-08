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

function riskColor(score) {
    if (score >= 80) return "#7f1d1d";
    if (score >= 60) return "#dc2626";
    if (score >= 40) return "#f59e0b";
    if (score >= 20) return "#ca8a04";
    return "#16a34a";
}

export default function RiskBarChart({ data }) {
    return (
        <div style={{ width: "100%", height: 320 }}>
            <ResponsiveContainer>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />

                    <XAxis
                        dataKey="repository"
                        tick={{ fontSize: 11 }}
                        interval={0}
                        angle={-25}
                        textAnchor="end"
                        height={90}
                    />

                    <YAxis />

                    <Tooltip />

                    <Bar dataKey="risk_score" name="Risk Score">
                        {data.map((entry, index) => (
                            <Cell
                                key={index}
                                fill={riskColor(entry.risk_score)}
                            />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}