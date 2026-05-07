from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SCRIPTS = [
    ("Syft", PROJECT_ROOT / "miner" / "adapters" / "generate_sboms.py"),
    ("Grype", PROJECT_ROOT / "miner" / "adapters" / "generate_grype.py"),
    ("CodeQL", PROJECT_ROOT / "miner" / "adapters" / "generate_codeql.py"),
]


if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s | %(message)s",
    )

LOGGER = logging.getLogger(__name__)


def run_script(script_name: str, script_path: Path, dry_run: bool = False) -> None:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    command = [sys.executable, str(script_path)]

    if dry_run:
        command.append("--dry-run")

    LOGGER.info("=" * 80)
    LOGGER.info("Running %s", script_name)
    LOGGER.info("Command: %s", " ".join(command))
    LOGGER.info("=" * 80)

    result = subprocess.run(command)

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} extraction failed with exit code {result.returncode}"
        )

    LOGGER.info("%s extraction completed successfully", script_name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run all raw extraction tools."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run all extractors in dry-run mode.",
    )

    args = parser.parse_args()

    try:
        for script_name, script_path in SCRIPTS:
            run_script(
                script_name=script_name,
                script_path=script_path,
                dry_run=args.dry_run,
            )

    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    LOGGER.info("All extraction steps completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
