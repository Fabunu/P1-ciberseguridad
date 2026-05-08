from pathlib import Path

from load_data import DataLoader
from aggregations import AggregationPipeline


ROOT_DIR = Path(__file__).resolve().parents[2]

OUTPUT_DIR = (
    ROOT_DIR
    / "analyzer"
    / "outputs"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def export_dataset(df, filename):

    output_path = (
        OUTPUT_DIR / filename
    )

    df.to_parquet(
        output_path,
        index=False,
    )

    print(
        f"[EXPORTED] {filename}"
    )


def main():

    print(
        "[INFO] Loading normalized datasets..."
    )

    loader = (
        DataLoader()
        .load_all()
    )

    print(
        "[INFO] Running analytical pipeline..."
    )

    pipeline = (
        AggregationPipeline(loader)
    )

    results = pipeline.run()

    print(
        "[INFO] Exporting gold datasets..."
    )

    for dataset_name, df in results.items():

        export_dataset(
            df,
            f"{dataset_name}.parquet",
        )

    print(
        "[DONE] Gold datasets generated successfully."
    )


if __name__ == "__main__":
    main()
