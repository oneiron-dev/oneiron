#!/usr/bin/env bash
# Untangle 6.9 (S69-RUN = A): a job in the oneiron-dreamer crate reaches the
# vault only through the client its host binds to one admitted attempt, never
# a `&Vault`. So the crate's normal and build dependencies are exactly
# oneiron-remote, serde and serde_json; dev-dependencies are exempt.
#
# Fails CLOSED: a missing or unreadable manifest, or any other dependency
# (renamed through `package =`, optional or target-specific included), fails
# the check. Reads the manifest only, so it needs no cargo and no network.
#
# Usage: scripts/ci/check_dreamer_crate_deps.sh [repository root]
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
manifest="${root}/crates/oneiron-dreamer/Cargo.toml"
if [ ! -f "${manifest}" ]; then
  echo "ERROR: ${manifest} not found" >&2
  exit 1
fi

python3 - "${manifest}" <<'PY'
import sys

try:
    import tomllib
except ModuleNotFoundError:
    print("ERROR: check_dreamer_crate_deps.sh needs Python 3.11 or later (tomllib)", file=sys.stderr)
    sys.exit(1)

ALLOWED = ("oneiron-remote", "serde", "serde_json")
TABLES = ("dependencies", "build-dependencies", "build_dependencies")

with open(sys.argv[1], "rb") as handle:
    manifest = tomllib.load(handle)


def dependency_tables(manifest):
    for key in TABLES:
        yield key, manifest.get(key, {})
    for target, spec in manifest.get("target", {}).items():
        for key in TABLES:
            yield f"target.{target}.{key}", spec.get(key, {})


refused = []
for where, table in dependency_tables(manifest):
    for name, spec in table.items():
        package = spec.get("package", name) if isinstance(spec, dict) else name
        if package not in ALLOWED:
            renamed = f" (package {package})" if package != name else ""
            refused.append(f"{where}: {name}{renamed}")

if refused:
    print(f"ERROR: oneiron-dreamer may depend only on {', '.join(ALLOWED)}; it names:", file=sys.stderr)
    for line in refused:
        print(f"  {line}", file=sys.stderr)
    sys.exit(1)
print(f"oneiron-dreamer dependencies: only {', '.join(ALLOWED)}")
PY
