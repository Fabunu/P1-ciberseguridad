from pathlib import Path

import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[2]

NORMALIZED_DIR = ROOT_DIR / "data" / "normalized"


class DataLoader:
    def __init__(self):
        self.repositories = None
        self.dependencies = None
        self.dependency_vulnerabilities = None
        self.code_vulnerabilities = None

    def load_all(self):
        self.repositories = pd.read_parquet(
            NORMALIZED_DIR / "repositories.parquet"
        )

        self.dependencies = pd.read_parquet(
            NORMALIZED_DIR / "dependencies.parquet"
        )

        self.dependency_vulnerabilities = pd.read_parquet(
            NORMALIZED_DIR / "dependency_vulnerabilities.parquet"
        )

        self.code_vulnerabilities = pd.read_parquet(
            NORMALIZED_DIR / "code_vulnerabilities.parquet"
        )

        return self
