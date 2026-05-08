export default function CrossRepoTable({ data }) {
    return (
        <table
            style={{
                width: "100%",
                borderCollapse: "collapse",
            }}
        >
            <thead>
                <tr>
                    <th align="left">Vulnerabilidad</th>
                    <th align="left">Repositorios afectados</th>
                    <th align="left">Ocurrencias</th>
                    <th align="left">Paquetes afectados</th>
                    <th align="left">CVSS promedio</th>
                </tr>
            </thead>

            <tbody>
                {data.map((item) => (
                    <tr key={item.vulnerability_id}>
                        <td>{item.vulnerability_id}</td>
                        <td>{item.affected_repositories}</td>
                        <td>{item.total_occurrences}</td>
                        <td>{item.affected_packages}</td>
                        <td>{Number(item.average_cvss ?? 0).toFixed(2)}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}