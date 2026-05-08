import {
    Bar,
    BarChart,
    CartesianGrid,
    Legend,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

export default function LanguageRiskChart({ data }) {
    return (
        <div style={{ width: "100%", height: 320 }}>
            <ResponsiveContainer>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />

                    <XAxis
                        dataKey="language"
                        tick={{ fontSize: 12 }}
                        interval={0}
                        angle={-20}
                        textAnchor="end"
                        height={70}
                    />

                    <YAxis />

                    <Tooltip />

                    <Legend />

                    <Bar
                        dataKey="critical_count"
                        name="Critical"
                        stackId="severity"
                    />

                    <Bar
                        dataKey="high_count"
                        name="High"
                        stackId="severity"
                    />

                    <Bar
                        dataKey="total_vulnerabilities"
                        name="Total"
                    />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}