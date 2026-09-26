"""Require every ignored RustSec advisory to affect a locked crate version.

Cargo-deny 0.19.4 decides advisory version ranges using its local database.
The separate lock/reason check pins the reviewed crate and version exactly.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
ADVISORY_ID = re.compile(r"RUSTSEC-\d{4}-\d+")


def advisory_package(db_root: Path, advisory_id: str) -> str:
    """Read a package from the local RustSec advisory front matter."""
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


def deny_unmatched_ignores(
    deny_path: Path, manifest_path: Path, metadata_path: Path | None = None
) -> set[str]:
    """Read advisory-not-detected IDs from the pinned cargo-deny JSON stream."""
    home = Path.home()
    binary = Path(os.environ.get("CARGO_DENY_BIN", home / "ci/tools/bin/cargo-deny"))
    if not binary.is_file() and "CARGO_DENY_BIN" not in os.environ:
        binary = home / ".cargo/bin/cargo-deny"
    # Put the host's real Cargo before factory wrappers; CI also uses this path.
    env = os.environ | {"PATH": f"{home / '.cargo/bin'}:{os.environ.get('PATH', '')}"}
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, env=env)
    if version.returncode or version.stdout.strip() != "cargo-deny 0.19.4":
        raise ValueError(f"expected cargo-deny 0.19.4 at {binary}: {version.stdout}{version.stderr}")
    command = [
        str(binary), "--format", "json", "--locked", "--offline",
        "--manifest-path", str(manifest_path), "check", "advisories",
        "--config", str(deny_path),
    ]
    if metadata_path is not None:
        command.extend(["--metadata-path", str(metadata_path)])
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    if result.returncode:
        raise ValueError(f"cargo-deny advisories failed ({result.returncode}): "
                         f"{(result.stderr or result.stdout)[-1000:]}")
    unmatched = set()
    summaries = 0
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        if not line.strip():
            continue
        record = json.loads(line)  # Unexpected output fails closed.
        if record["type"] == "summary":
            summaries += 1
        if record["type"] != "diagnostic" or record["fields"].get("code") != "advisory-not-detected":
            continue
        fields = record["fields"]
        if fields.get("message") != "advisory was not encountered":
            raise ValueError(f"unexpected advisory-not-detected diagnostic: {fields}")
        ids = [label.get("span") for label in fields.get("labels", [])
               if ADVISORY_ID.fullmatch(label.get("span", ""))]
        if len(ids) != 1:
            raise ValueError(f"advisory-not-detected has no unique ID: {fields}")
        unmatched.add(ids[0])
    if summaries != 1:
        raise ValueError(f"expected one cargo-deny summary, got {summaries}")
    return unmatched


def find_stale_ignores(
    deny_path: Path, lock_path: Path, metadata_path: Path | None = None,
    manifest_path: Path = ROOT / "Cargo.toml",
) -> list[str]:
    """Return IDs without an affected, reviewed package@version in Cargo.lock."""
    config = tomllib.loads(deny_path.read_text())
    lock = tomllib.loads(lock_path.read_text())
    locked = {(pkg["name"], pkg["version"]) for pkg in lock["package"]}
    db_root = Path(config["advisories"]["db-path"]).expanduser()
    unmatched = deny_unmatched_ignores(deny_path, manifest_path, metadata_path)
    stale = []
    for entry in config["advisories"]["ignore"]:
        advisory_id = entry["id"]
        package = advisory_package(db_root, advisory_id)
        # Reasons pin one exact reviewed version; cargo-deny checks affectedness.
        first_token = entry["reason"].split(maxsplit=1)[0]
        prefix = f"{package}@"
        if not first_token.startswith(prefix) or (
            package, first_token[len(prefix) :]
        ) not in locked or advisory_id in unmatched:
            stale.append(advisory_id)
    return stale


if __name__ == "__main__":
    try:
        stale = find_stale_ignores(ROOT / "deny.toml", ROOT / "Cargo.lock")
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"deny policy check failed: {exc}")
    if stale:
        sys.exit("stale advisory ignores: " + ", ".join(stale))
    print("All advisory ignores name affected locked crate versions.")
