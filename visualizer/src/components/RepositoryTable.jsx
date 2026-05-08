export default function RepositoryTable({
    data,
}) {
    return (
        <div
            style={{
                background: "white",
                padding: "1rem",
                borderRadius: "12px",
                boxShadow:
                    "0 2px 6px rgba(0,0,0,0.08)",
            }}
        >
            <h2>
                Top Risky Repositories
            </h2>

            <table
                style={{
                    width: "100%",
                    borderCollapse:
                        "collapse",
                }}
            >
                <thead>
                    <tr>
                        <th align="left">
                            Repository
                        </th>

                        <th align="left">
                            Risk Score
                        </th>

                        <th align="left">
                            Critical
                        </th>

                        <th align="left">
                            High
                        </th>

                        <th align="left">
                            Total
                        </th>
                    </tr>
                </thead>

                <tbody>
                    {data.map((repo) => (
                        <tr
                            key={
                                repo.repository
                            }
                        >
                            <td>
                                {
                                    repo.repository
                                }
                            </td>

                            <td>
                                {
                                    repo.risk_score
                                }
                            </td>

                            <td>
                                {
                                    repo.critical_count
                                }
                            </td>

                            <td>
                                {repo.high_count}
                            </td>

                            <td>
                                {
                                    repo.total_vulnerabilities
                                }
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}