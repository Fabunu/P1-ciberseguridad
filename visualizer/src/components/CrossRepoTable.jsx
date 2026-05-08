const CELL_STYLE = {
    padding: "0.5rem 0.75rem",
    borderBottom: "1px solid #eee",
    verticalAlign: "top",
    fontSize: "0.85rem",
};

export default function CrossRepoTable({ data }) {
    return (
        <div style={{ overflowX: "auto" }}>
            <table
                style={{
                    width: "100%",
                    borderCollapse: "collapse",
                }}
            >
                <thead>
                    <tr>
                        <th align="left" style={CELL_STYLE}>Vulnerabilidad</th>
                        <th align="left" style={CELL_STYLE}>Repositorios afectados</th>
                        <th align="left" style={CELL_STYLE}>Ocurrencias</th>
                        <th align="left" style={CELL_STYLE}>Paquetes afectados</th>
                        <th align="left" style={CELL_STYLE}>CVSS promedio</th>
                        <th align="left" style={CELL_STYLE}>Descripción</th>
                    </tr>
                </thead>

                <tbody>
                    {data.map((item) => (
                        <tr key={item.vulnerability_id}>
                            <td style={CELL_STYLE}>
                                <code>{item.vulnerability_id}</code>
                            </td>
                            <td style={CELL_STYLE}>{item.affected_repositories}</td>
                            <td style={CELL_STYLE}>{item.total_occurrences}</td>
                            <td style={CELL_STYLE}>{item.affected_packages}</td>
                            <td style={CELL_STYLE}>{Number(item.average_cvss ?? 0).toFixed(2)}</td>
                            <td style={{ ...CELL_STYLE, maxWidth: 300, color: "#555" }}>
                                {item.description || "—"}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}