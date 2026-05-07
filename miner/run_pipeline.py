from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RUN_EXTRACTION_SCRIPT = (
    PROJECT_ROOT / "miner" / "run_extraction.py"
)

RUN_NORMALIZATION_SCRIPT = (
    PROJECT_ROOT / "miner" / "run_normalization.py"
)


if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s | %(message)s",
    )

LOGGER = logging.getLogger(__name__)


def run_step(name: str, script_path: Path, dry_run: bool = False) -> None:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    command = [sys.executable, str(script_path)]

    if dry_run:
        command.append("--dry-run")

    LOGGER.info("=" * 80)
    LOGGER.info("Running step: %s", name)
    LOGGER.info("=" * 80)

    result = subprocess.run(command)

    if result.returncode != 0:
        raise RuntimeError(
            f"{name} failed with exit code {result.returncode}"
        )

    LOGGER.info("%s completed successfully", name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run complete mining pipeline."
    )

    parser.add_argument(
        "--skip-extraction",
        action="store_true",
        help="Skip raw extraction step.",
    )

    parser.add_argument(
        "--skip-normalization",
        action="store_true",
        help="Skip normalization step.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run extraction in dry-run mode.",
    )

    args = parser.parse_args()

    try:
        if not args.skip_extraction:
            run_step(
                name="Extraction",
                script_path=RUN_EXTRACTION_SCRIPT,
                dry_run=args.dry_run,
            )

        if not args.skip_normalization:
            run_step(
                name="Normalization",
                script_path=RUN_NORMALIZATION_SCRIPT,
            )

    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    LOGGER.info("Pipeline completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
