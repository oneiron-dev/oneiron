#!/usr/bin/env bash
# Code-map pin: docs/CODEMAP.md, docs/codemap/<crate>.md and
# docs/codemap/codemap.json are generated; this check regenerates them in
# memory and byte-compares. Any drift is CODEMAP-STALE (exit 1) with the
# regenerate hint; a missing artifact, unreadable file, or empty scan is
# CODEMAP-ERROR (exit 1). Never a silent pass.
#
# To move the pin: run `python3 scripts/codemap/codemap.py` in the same PR
# that adds, moves, or deletes a Rust file, and commit the regenerated files.
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "CODEMAP-ERROR: cannot cd to repo root"; exit 1; }
exec python3 scripts/codemap/codemap.py --check
