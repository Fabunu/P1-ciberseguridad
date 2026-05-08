const CELL = {
    padding: "0.5rem 0.75rem",
    borderBottom: "1px solid #eee",
    verticalAlign: "top",
    fontSize: "0.85rem",
};

export default function TopPackagesTable({ data }) {
    if (!data || data.length === 0) return null;

    return (
        <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                    <tr>
                        <th align="left" style={CELL}>Paquete</th>
                        <th align="left" style={CELL}>Vulnerabilidades</th>
                        <th align="left" style={CELL}>Vulnerabilidades únicas</th>
                        <th align="left" style={CELL}>Repositorios afectados</th>
                        <th align="left" style={CELL}>Críticas</th>
                        <th align="left" style={CELL}>Altas</th>
                        <th align="left" style={CELL}>CVSS promedio</th>
                    </tr>
                </thead>
                <tbody>
                    {data.map((item) => (
                        <tr key={item.package_name}>
                            <td style={CELL}><code>{item.package_name}</code></td>
                            <td style={CELL}>{item.vulnerability_count}</td>
                            <td style={CELL}>{item.unique_vulnerabilities}</td>
                            <td style={CELL}>{item.affected_repositories}</td>
                            <td style={CELL}>{item.critical_vulnerabilities}</td>
                            <td style={CELL}>{item.high_vulnerabilities}</td>
                            <td style={CELL}>{Number(item.average_cvss ?? 0).toFixed(2)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}