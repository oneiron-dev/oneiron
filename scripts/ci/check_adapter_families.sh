#!/usr/bin/env bash
# ARCH-0036 #adapters (owner card MED-1 = A): a crate exists only for a real
# boundary, and each wire protocol is a module inside one family crate.
# `oneiron-llm` holds the text model wires, so no `oneiron-llm-*` crate stands
# apart from it. `oneiron-gen` holds the image, video and music job wires, so
# no `oneiron-image-*` adapter crate stands apart from it, and the Gemini media
# wire is no longer in `oneiron-llm`. The `oneiron-image` organ is not a wire
# adapter and stays its own crate.
#
# Fails CLOSED: a missing or unreadable manifest fails the check. Reads the
# manifests and the directory tree only, so it needs no cargo and no network.
#
# Usage: scripts/ci/check_adapter_families.sh [repository root]
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 - "${root}" <<'PY'
import pathlib
import sys

try:
    import tomllib
except ModuleNotFoundError:
    print("ERROR: check_adapter_families.sh needs Python 3.11 or later (tomllib)", file=sys.stderr)
    sys.exit(1)

root = pathlib.Path(sys.argv[1])
crates = root / "crates"
refused = []


def package_name(manifest):
    with open(manifest, "rb") as handle:
        return tomllib.load(handle).get("package", {}).get("name")


# The family crates: each must exist under its own name.
FAMILIES = ("oneiron-llm", "oneiron-gen")
for family in FAMILIES:
    manifest = crates / family / "Cargo.toml"
    if not manifest.is_file():
        refused.append(f"{manifest.relative_to(root)} is missing")
    elif package_name(manifest) != family:
        refused.append(f"{manifest.relative_to(root)} names package {package_name(manifest)!r}, not {family!r}")

# No crate dir and no package outside a family may hold a wire that belongs to one.
SPLIT_PREFIXES = ("oneiron-llm-", "oneiron-image-")
for directory in sorted(path for path in crates.iterdir() if path.is_dir()):
    if directory.name.startswith(SPLIT_PREFIXES):
        refused.append(f"crates/{directory.name} stands apart from its family crate")
    manifest = directory / "Cargo.toml"
    if manifest.is_file():
        name = package_name(manifest)
        if name and name.startswith(SPLIT_PREFIXES):
            refused.append(f"{manifest.relative_to(root)} names package {name!r}")

# A wire that belongs to another family stays out of this one.
FOREIGN_PATHS = (
    ("crates/oneiron-llm/src/gemini/media.rs", "the Gemini media wire belongs to oneiron-gen"),
    ("crates/oneiron-llm/src/gemini/media", "the Gemini media wire belongs to oneiron-gen"),
)
for path, reason in FOREIGN_PATHS:
    if (root / path).exists():
        refused.append(f"{path} exists: {reason}")

# The image organ is a process boundary, not an adapter: it stays.
organ = crates / "oneiron-image" / "Cargo.toml"
if not organ.is_file() or package_name(organ) != "oneiron-image":
    refused.append("crates/oneiron-image/Cargo.toml (the image organ) is missing")

if refused:
    print("ERROR: the adapter family layout (ARCH-0036 #adapters) does not hold:", file=sys.stderr)
    for line in refused:
        print(f"  {line}", file=sys.stderr)
    sys.exit(1)
print(f"adapter families: {', '.join(FAMILIES)}; no split adapter crate")
PY
