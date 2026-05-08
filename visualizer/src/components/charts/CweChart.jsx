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

                    <Tooltip />

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