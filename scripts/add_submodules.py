import json
import shutil
import subprocess
import sys
from pathlib import Path


def _run_git_command(args, cwd, error_msg):
    """Helper to run git commands"""
    try:
        result = subprocess.run(
            args,
            check=True,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        return result

    except subprocess.CalledProcessError as e:
        print(f"{error_msg}")
        print(f"Command: {' '.join(args)}")

        if e.stdout:
            print("\nSTDOUT:")
            print(e.stdout)

        if e.stderr:
            print("\nSTDERR:")
            print(e.stderr)

        return None

    except FileNotFoundError:
        print("Error: 'git' command not found. Is Git installed and in PATH?")
        sys.exit(1)


def _load_repositories(repos_file):
    """Load repositories from repos.json"""

    if not repos_file.exists():
        print(f"Error: repositories file not found at {repos_file}")
        sys.exit(1)

    with open(repos_file, "r") as f:
        data = json.load(f)

    return data.get("repositories", [])


def _repo_name_from_url(url):
    """Extract repo name from GitHub URL"""

    return url.rstrip("/").split("/")[-1]


def clone_repositories(repo_root, repositories):
    """
    Clone repositories into data/repos using normal git clone.

    This replaces the previous git submodule approach.
    """

    repos_dir = repo_root / "data" / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)

    for repo in repositories:
        url = repo.get("url")
        ref = repo.get("ref")

        if not url:
            print(f"Skipping invalid repository entry: {repo}")
            continue

        repo_name = _repo_name_from_url(url)
        repo_path = repos_dir / repo_name

        # Skip if already cloned
        if repo_path.exists():
            print(f"Repository '{repo_name}' already exists. Skipping clone.")
            continue

        print(f"\nCloning: {url}")
        print(f"Destination: {repo_path}")

        result = _run_git_command(
            [
                "git",
                "clone",
                "--depth",
                "1",
                url,
                str(repo_path),
            ],
            repo_root,
            f"Failed to clone repository {url}",
        )

        if not result:
            continue

        print(f"✓ Cloned {repo_name}")

        # Checkout ref if provided
        if ref:
            print(f"Checking out ref '{ref}' in {repo_name}")

            checkout_result = _run_git_command(
                ["git", "checkout", ref],
                repo_path,
                f"Failed to checkout ref '{ref}' in {repo_name}",
            )

            if checkout_result:
                print(f"✓ Checked out {ref}")


def remove_repositories_not_in_config(repo_root, repositories):
    """
    Remove repositories in data/repos that are not listed in repos.json
    """

    repos_dir = repo_root / "data" / "repos"

    if not repos_dir.exists():
        return

    desired_repo_names = {
        _repo_name_from_url(repo["url"])
        for repo in repositories
        if repo.get("url")
    }

    for existing_repo in repos_dir.iterdir():

        if not existing_repo.is_dir():
            continue

        if existing_repo.name not in desired_repo_names:
            print(f"\nRemoving repository not in config: {existing_repo.name}")

            shutil.rmtree(existing_repo)

            print(f"✓ Removed {existing_repo.name}")


def sync_repositories():
    """
    Sync repositories from repos.json using normal git clones.

    Behavior:
    - clones missing repositories
    - removes repositories not present in repos.json
    - supports optional ref checkout
    """

    repo_root = Path(__file__).resolve().parents[1]

    repos_file = repo_root / "data" / "repos.json"

    repositories = _load_repositories(repos_file)

    print("Syncing repositories...\n")

    # Remove old repositories not present in config
    remove_repositories_not_in_config(repo_root, repositories)

    # Clone missing repositories
    clone_repositories(repo_root, repositories)

    print("\n✓ Repository sync complete!")


if __name__ == "__main__":
    sync_repositories()
