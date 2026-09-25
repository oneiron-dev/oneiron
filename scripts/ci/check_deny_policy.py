"""Check that accepted RustSec ignores still name exact locked packages.

Uses cargo-deny's local advisory DB; no network or dependency resolution.
"""

from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def advisory_package(db_root: Path, advisory_id: str) -> str:
    """Read the package from the RustSec Markdown file's TOML front matter."""
    candidates = list(db_root.glob(f"crates/*/{advisory_id}.md"))
    candidates += list(db_root.glob(f"advisory-db-*/crates/*/{advisory_id}.md"))
    if len(candidates) != 1:
        raise ValueError(
            f"{advisory_id}: expected one advisory in {db_root}, found {len(candidates)}"
        )
    _, marker, tail = candidates[0].read_text().partition("```toml\n")
    if not marker or "\n```" not in tail:
        raise ValueError(f"{advisory_id}: missing TOML advisory front matter")
    record = tomllib.loads(tail.split("\n```", 1)[0])
    if record["advisory"]["id"] != advisory_id:
        raise ValueError(f"{advisory_id}: advisory file has a different id")
    return record["advisory"]["package"]


def find_stale_ignores(
    deny_path: Path, lock_path: Path, db_root: Path | None = None
) -> list[str]:
    """Return IDs whose reason's advisory package@version is not in Cargo.lock."""
    config = tomllib.loads(deny_path.read_text())
    lock = tomllib.loads(lock_path.read_text())
    locked = {(pkg["name"], pkg["version"]) for pkg in lock["package"]}
    db_root = db_root or Path(config["advisories"]["db-path"]).expanduser()
    stale = []
    for entry in config["advisories"]["ignore"]:
        advisory_id = entry["id"]
        package = advisory_package(db_root, advisory_id)
        # The first reason token names the exact reviewed crate and version.
        # Requiring it prevents an old acceptance from surviving a lock update.
        first_token = entry["reason"].split(maxsplit=1)[0]
        prefix = f"{package}@"
        if not first_token.startswith(prefix) or (
            package, first_token[len(prefix) :]
        ) not in locked:
            stale.append(advisory_id)
    return stale


if __name__ == "__main__":
    try:
        stale = find_stale_ignores(ROOT / "deny.toml", ROOT / "Cargo.lock")
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"deny policy check failed: {exc}")
    if stale:
        sys.exit("stale advisory ignores: " + ", ".join(stale))
    print("All advisory ignores name locked crate versions.")
