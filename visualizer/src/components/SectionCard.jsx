export default function SectionCard({ title, description, children }) {
    return (
        <section
            style={{
                background: "white",
                padding: "1.25rem",
                borderRadius: "12px",
                boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
            }}
        >
            <h2
                style={{
                    marginTop: 0,
                    marginBottom: "0.25rem",
                }}
            >
                {title}
            </h2>

            {description ? (
                <p
                    style={{
                        marginTop: 0,
                        marginBottom: "1rem",
                        color: "#666",
                        fontSize: "0.95rem",
                    }}
                >
                    {description}
                </p>
            ) : null}

            {children}
        </section>
    );
}