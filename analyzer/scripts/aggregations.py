from metrics import MetricsBuilder


class AggregationPipeline:

    def __init__(self, loader):
        self.metrics = MetricsBuilder(loader)

    def run(self):

        return {
            "repository_summary": (
                self.metrics.repository_summary()
            ),

            "severity_distribution": (
                self.metrics.severity_distribution()
            ),

            "repository_risk": (
                self.metrics.repository_risk()
            ),

            "top_vulnerable_packages": (
                self.metrics.top_vulnerable_packages()
            ),

            "top_cwes": (
                self.metrics.top_cwes()
            ),

            "language_risk": (
                self.metrics.language_risk()
            ),

            "repository_dependency_stats": (
                self.metrics.repository_dependency_stats()
            ),

            "repository_codeql_stats": (
                self.metrics.repository_codeql_stats()
            ),

            "cross_repository_patterns": (
                self.metrics.cross_repository_patterns()
            ),
        }
