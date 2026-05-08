import {
    Bar,
    BarChart,
    CartesianGrid,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

export default function PackagesChart({ data }) {
    return (
        <div style={{ width: "100%", height: 320 }}>
            <ResponsiveContainer>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" />

                    <XAxis
                        dataKey="package_name"
                        tick={{ fontSize: 11 }}
                        interval={0}
                        angle={-25}
                        textAnchor="end"
                        height={90}
                    />

                    <YAxis />

                    <Tooltip />

                    <Bar
                        dataKey="vulnerability_count"
                        name="Vulnerabilities"
                    />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}