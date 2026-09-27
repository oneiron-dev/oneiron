#!/usr/bin/env bash
# Code-map pin: docs/CODEMAP.md, docs/codemap/<crate>.md and
# docs/codemap/codemap.json are generated; this check regenerates them in
# memory and byte-compares. Any drift is CODEMAP-STALE (exit 1) with the
# regenerate hint (including missing artifacts); an unreadable file or empty
# scan is CODEMAP-ERROR (exit 1). Never a silent pass.
#
# Only main writes the map: .github/workflows/codemap.yml regenerates and
# commits it after every push to main, and PRs never touch it. scripts/verify.sh
# runs this check only with CODEMAP_CHECK=1. Run the generator locally only to
# read a fresh map, never to commit it.
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "CODEMAP-ERROR: cannot cd to repo root"; exit 1; }
exec python3 scripts/codemap/codemap.py --check
