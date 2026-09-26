"""Require every ignored RustSec advisory to affect a locked crate version.

Cargo-deny 0.19.4 decides advisory version ranges using its local database.
Match cargo-deny's affected package versions to each reviewed reason exactly.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]


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


def deny_affected_versions(
    deny_path: Path, manifest_path: Path, metadata_path: Path | None = None
) -> set[tuple[str, str, str]]:
    """Ask pinned cargo-deny which exact advisory/package/version triples are affected.

    Remove ignores only for this check: an ignored ID suppresses the affected
    diagnostic, and an ID-only not-detected result cannot distinguish versions.
    """
    policy = tomllib.loads(deny_path.read_text())
    config = policy["advisories"]
    home = Path.home()
    binary = Path(os.environ.get("CARGO_DENY_BIN", home / "ci/tools/bin/cargo-deny"))
    if not binary.is_file() and "CARGO_DENY_BIN" not in os.environ:
        binary = home / ".cargo/bin/cargo-deny"
    env = os.environ | {"PATH": f"{home / '.cargo/bin'}:{os.environ.get('PATH', '')}"}
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, env=env)
    if version.returncode or version.stdout.strip() != "cargo-deny 0.19.4":
        raise ValueError(f"expected cargo-deny 0.19.4 at {binary}: {version.stdout}{version.stderr}")
    with tempfile.TemporaryDirectory() as directory:
        # Preserve the local advisory database; do not fetch or implement ranges
        # independently. No-ignore diagnostics contain the exact affected crates.
        unignored = Path(directory) / "deny.toml"
        db_path = str(Path(config["db-path"]).expanduser())
        graph = policy.get("graph", {})
        graph_settings = "".join(
            f"{key} = {str(graph[key]).lower()}\n"
            for key in ("all-features", "no-default-features") if key in graph
        )
        unignored.write_text(
            f"[graph]\n{graph_settings}[advisories]\n"
            f"db-path = {json.dumps(db_path)}\nyanked = 'allow'\n"
        )
        command = [
            str(binary), "--format", "json", "--locked", "--offline",
            "--manifest-path", str(manifest_path), "check", "advisories",
            "--config", str(unignored),
        ]
        if metadata_path is not None:
            command.extend(["--metadata-path", str(metadata_path)])
        result = subprocess.run(command, capture_output=True, text=True, env=env)
    affected = set()
    summaries = 0
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        if not line.strip():
            continue
        record = json.loads(line)  # Unexpected output fails closed.
        if record["type"] == "summary":
            summaries += 1
        if record["type"] != "diagnostic":
            continue
        fields = record["fields"]
        advisory = fields.get("advisory")
        if advisory is None:
            continue  # e.g. a yanked version is not a RustSec advisory.
        advisory_id = advisory["id"]
        package = advisory["package"]
        graphs = fields["graphs"]
        if not graphs:
            raise ValueError(f"{advisory_id}: advisory diagnostic has no affected graph")
        for graph in graphs:
            crate = graph["Krate"]
            if crate["name"] != package:
                raise ValueError(f"{advisory_id}: advisory graph names another package")
            affected.add((advisory_id, crate["name"], crate["version"]))
    # Cargo-deny exits nonzero for unignored vulnerabilities, as expected.
    # The JSON summary is required even when no advisory is present.
    if summaries != 1 or result.returncode not in (0, 1):
        raise ValueError(f"cargo-deny advisories failed ({result.returncode}); summaries={summaries}: "
                         f"{(result.stderr or result.stdout)[-1000:]}")
    return affected


def find_stale_ignores(
    deny_path: Path, lock_path: Path, metadata_path: Path | None = None,
    manifest_path: Path = ROOT / "Cargo.toml",
) -> list[str]:
    """Return IDs without an affected, reviewed package@version in Cargo.lock."""
    config = tomllib.loads(deny_path.read_text())
    lock = tomllib.loads(lock_path.read_text())
    locked = {(pkg["name"], pkg["version"]) for pkg in lock["package"]}
    db_root = Path(config["advisories"]["db-path"]).expanduser()
    affected = deny_affected_versions(deny_path, manifest_path, metadata_path)
    stale = []
    for entry in config["advisories"]["ignore"]:
        advisory_id = entry["id"]
        package = advisory_package(db_root, advisory_id)
        # A graph-wide advisory ID is not proof for this reviewed version.
        first_token = entry["reason"].split(maxsplit=1)[0]
        prefix = f"{package}@"
        if not first_token.startswith(prefix) or (
            package, first_token[len(prefix) :]
        ) not in locked or (advisory_id, package, first_token[len(prefix) :]) not in affected:
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
