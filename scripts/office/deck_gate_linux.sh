#!/usr/bin/env bash
# The engine half of the OF-510 deck gate on a Linux fleet host.
# usage: bash deck_gate_linux.sh <full 40-char sha> <run id>
#
# Clones oneiron at <sha>, acquires the pinned PPTArena originals and the
# pinned ECMA-376 transitional schemas beside the synced tree (both kept
# across runs), builds and runs deck-gate-engine (the runner with the
# engine's Loro body, so step 4's two-peer case runs; step 5 validates every
# candidate when the schemas are ready), and prints the run directory to
# pull, first at the start: every case the runner finished is in its
# results.jsonl even when the run is cut short.
# docs/ops/deck-gate.md has the whole procedure.
set -u
sha=$1
run=$2
here=$(pwd)
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
corpus=${DECK_GATE_CORPUS:-$here/../deck-gate-corpus}
schemas=${DECK_GATE_SCHEMAS:-$here/../deck-gate-schemas}
out=$here/out/$run
if [ -e "$out" ]; then echo "## DECK-GATE-ENGINE rc=out-exists out=$out"; exit 8; fi
echo "## DECK-GATE-ENGINE start host=$(uname -n) sha=$sha out=$out"
journaled() { wc -l < "$out/results.jsonl" 2>/dev/null | tr -d ' ' || echo 0; }
trap 'echo "## DECK-GATE-ENGINE rc=stopped out=$out journal_lines=$(journaled)"; exit 143' TERM INT HUP
rm -rf src
mkdir src && cd src || exit 9
if ! { git init -q && git remote add origin https://github.com/oneiron-dev/oneiron \
  && git fetch -q --depth 1 origin "$sha" && git checkout -q FETCH_HEAD; }; then
  echo "## DECK-GATE-ENGINE rc=clone-failed sha=$sha"; exit 9
fi
cd "$here" || exit 9
mkdir -p "$here/out" "$corpus"
python3 -B src/scripts/office/deck_gate.py acquire src "$corpus"
acquired=$?
# Without the schema set step 5 stays inconclusive; the run still goes on.
python3 -B src/scripts/office/deck_schema.py fetch "$schemas"
fetched=$?
validate=()
if [ "$fetched" -eq 0 ]; then validate=(--schemas "$schemas"); fi
cargo run --locked --release --manifest-path src/Cargo.toml -p oneiron --bin deck-gate-engine -- \
  --repo src --out "$out" --corpus "$corpus" --source "$sha" "${validate[@]}"
rc=$?
echo "## DECK-GATE-ENGINE rc=$rc acquire=$acquired schemas=$fetched host=$(uname -n) out=$out journal_lines=$(journaled) bytes=$(du -sb "$out" 2>/dev/null | cut -f1)"
exit "$rc"
