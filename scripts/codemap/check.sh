#!/usr/bin/env bash
# Code-map pin: docs/CODEMAP.md, docs/codemap/<crate>.md,
# docs/codemap/codemap.json, docs/codemap/BY-SPEC.md and
# docs/codemap/BY-CAPABILITY.md are generated; this check regenerates them in
# memory and byte-compares. Any drift is CODEMAP-STALE (exit 1) with the
# regenerate hint (including missing artifacts); a path in
# scripts/codemap/capability_aliases.md that names no file is
# CODEMAP-ALIAS-MISSING (exit 1); an unreadable file, a malformed alias file
# or an empty scan is CODEMAP-ERROR (exit 1). Never a silent pass.
#
# Only main writes the map: .github/workflows/codemap.yml regenerates and
# commits it after every push to main, and PRs never touch it. scripts/verify.sh
# runs this check only with CODEMAP_CHECK=1. Run the generator locally only to
# read a fresh map, never to commit it.
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "CODEMAP-ERROR: cannot cd to repo root"; exit 1; }
exec python3 scripts/codemap/codemap.py --check
