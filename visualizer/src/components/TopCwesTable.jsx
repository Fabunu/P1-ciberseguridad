const CELL = {
    padding: "0.5rem 0.75rem",
    borderBottom: "1px solid #eee",
    verticalAlign: "top",
    fontSize: "0.85rem",
};

export default function TopCwesTable({ data }) {
    if (!data || data.length === 0) return null;

    return (
        <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                    <tr>
                        <th align="left" style={CELL}>CWE</th>
                        <th align="left" style={CELL}>Frecuencia</th>
                        <th align="left" style={CELL}>Repositorios afectados</th>
                        <th align="left" style={CELL}>CVSS promedio</th>
                        <th align="left" style={CELL}>CVSS máximo</th>
                        <th align="left" style={CELL}>Descripción</th>
                    </tr>
                </thead>
                <tbody>
                    {data.map((item) => (
                        <tr key={item.cwe}>
                            <td style={CELL}><code>{item.cwe}</code></td>
                            <td style={CELL}>{item.frequency}</td>
                            <td style={CELL}>{item.repositories_affected}</td>
                            <td style={CELL}>{Number(item.average_cvss ?? 0).toFixed(2)}</td>
                            <td style={CELL}>{Number(item.max_cvss ?? 0).toFixed(2)}</td>
                            <td style={{ ...CELL, maxWidth: 320, color: "#555" }}>
                                {item.description || "—"}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}