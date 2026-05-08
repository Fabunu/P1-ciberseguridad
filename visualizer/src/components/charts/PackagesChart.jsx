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
    "#ea580c", "#d97706", "#ca8a04", "#65a30d", "#16a34a",
    "#0d9488", "#0891b2", "#2563eb", "#7c3aed", "#a21caf",
];

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
                    >
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