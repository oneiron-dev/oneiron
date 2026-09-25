"""Check that RustSec ignores still name affected locked crate versions.

Uses cargo-deny's local advisory DB; no network or dependency resolution.
"""

from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
_VERSION = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")
_COMPARATOR = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(.+)")


def version_parts(text: str) -> tuple[tuple[int, int, int], tuple[tuple[int, object], ...], int]:
    """Parse a SemVer (or partial requirement) without its irrelevant build metadata."""
    match = _VERSION.fullmatch(text)
    if match is None:
        raise ValueError(f"unsupported advisory version: {text}")
    nums = tuple(int(part or 0) for part in match.group(1, 2, 3))
    prerelease = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in (match.group(4) or "").split(".") if part
    )
    return nums, prerelease, sum(part is not None for part in match.group(1, 2, 3))


def version_key(parts: tuple[tuple[int, int, int], tuple[tuple[int, object], ...], int]) -> tuple:
    nums, prerelease, _ = parts
    # A release sorts after all its prereleases; numeric identifiers sort first.
    return (*nums, 0 if prerelease else 1, prerelease)


def requirement_matches(version: str, requirement: str) -> bool:
    """Match RustSec's comma-AND SemVer requirements; reject unknown syntax."""
    candidate = version_parts(version)
    clauses = []
    for clause in requirement.split(","):
        match = _COMPARATOR.fullmatch(clause.strip())
        if match is None:
            raise ValueError(f"unsupported advisory requirement: {requirement}")
        op, text = match.groups()
        target = version_parts(text)
        clauses.append((op or "^", target))
    if candidate[1] and not any(
        target[1] and candidate[0] == target[0] for _, target in clauses
    ):
        # Cargo SemVer does not match a prerelease unless the requirement
        # explicitly names a prerelease of this same major.minor.patch.
        return False
    key = version_key(candidate)
    for op, target in clauses:
        bound = version_key(target)
        if op in (">", ">=", "<", "<="):
            # For partial requirements compare only the components supplied.
            left = key if target[2] == 3 or target[1] else candidate[0][:target[2]]
            right = bound if target[2] == 3 or target[1] else target[0][:target[2]]
            matches = {">": left > right, ">=": left >= right,
                       "<": left < right, "<=": left <= right}[op]
        elif op == "=":
            matches = (key == bound if target[2] == 3 or target[1] else
                       candidate[0][:target[2]] == target[0][:target[2]])
        elif op in ("^", "~"):
            major, minor, patch = target[0]
            if op == "~":
                upper = (major + 1, 0, 0) if target[2] == 1 else (major, minor + 1, 0)
            elif major:
                upper = (major + 1, 0, 0)
            elif target[2] == 1 or minor:
                upper = (0, minor + 1, 0)
            elif target[2] == 2:
                upper = (0, 1, 0)
            else:
                upper = (0, 0, patch + 1)
            matches = key >= bound and candidate[0] < upper
        else:
            raise ValueError(f"unsupported advisory requirement: {requirement}")
        if not matches:
            return False
    return True


def advisory_record(db_root: Path, advisory_id: str) -> dict:
    """Read identity, package and version ranges from RustSec TOML front matter."""
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
    return record


def find_stale_ignores(
    deny_path: Path, lock_path: Path, db_root: Path | None = None
) -> list[str]:
    """Return IDs without a matching affected package@version in Cargo.lock."""
    config = tomllib.loads(deny_path.read_text())
    lock = tomllib.loads(lock_path.read_text())
    locked = {(pkg["name"], pkg["version"]) for pkg in lock["package"]}
    db_root = db_root or Path(config["advisories"]["db-path"]).expanduser()
    stale = []
    for entry in config["advisories"]["ignore"]:
        advisory_id = entry["id"]
        advisory = advisory_record(db_root, advisory_id)
        package = advisory["advisory"]["package"]
        versions = advisory["versions"]
        # The first reason token names the exact reviewed crate and version.
        # Requiring it prevents an old acceptance from surviving a lock update.
        first_token = entry["reason"].split(maxsplit=1)[0]
        prefix = f"{package}@"
        if not first_token.startswith(prefix):
            stale.append(advisory_id)
            continue
        version = first_token[len(prefix) :]
        if (package, version) not in locked or any(
            requirement_matches(version, rule)
            for rule in (*versions["patched"], *versions.get("unaffected", []))
        ):
            stale.append(advisory_id)
    return stale


if __name__ == "__main__":
    try:
        stale = find_stale_ignores(ROOT / "deny.toml", ROOT / "Cargo.lock")
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"deny policy check failed: {exc}")
    if stale:
        sys.exit("stale advisory ignores: " + ", ".join(stale))
    print("All advisory ignores name affected locked crate versions.")
