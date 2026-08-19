#!/usr/bin/env bash
# Ratchet: recompute 3 metrics and fail if any exceeds baseline.json. No jq
# dependency — baseline's 3 "count" fields are the only ones at that depth,
# extracted in fixed order: giant_files, allow_attrs, print_macros.
#
# Fails CLOSED: a missing/corrupt baseline, a missing/broken `rg`, or a file
# scan that yields nothing is RATCHET-ERROR (exit 1), never a silent pass.
#
# To move the baseline on a real, reviewed increase: rerun this file's find/rg
# commands by hand, write the new counts into baseline.json's "count" fields,
# bump computed_at_commit/computed_date, and say why in the PR description —
# never bump silently just to make check.sh pass.
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "RATCHET-ERROR: cannot cd to repo root"; exit 1; }
BASE="scripts/ratchet/baseline.json"
GLOBS=(--glob '!**/tests/**' --glob '!**/tests.rs' --glob '!**/*_tests.rs')

die() { echo "RATCHET-ERROR: $1"; exit 1; }
is_num() { [[ ${1:-} =~ ^[0-9]+$ ]]; }

# rg exit 0 = matches, 1 = no matches (a legitimate 0), >=2 = real error
# (bad pattern, unreadable path, or 127 for a missing binary) -> hard fail.
count_rg() {
  local out st
  out=$(rg -c "$1" "${GLOBS[@]}" crates/*/src 2>&1); st=$?
  if [ "$st" -ge 2 ]; then
    echo "rg failed (exit $st) for pattern $1: $out" >&2
    return 1
  fi
  [ "$st" -eq 0 ] || out=""
  printf '%s\n' "$out" | awk -F: '{s+=$2} END{print s+0}'
}

# Runs in the main shell (not a subshell) so `die` can actually exit; result
# lands in RG_COUNT.
RG_COUNT=0
count_into() {
  local n st
  n=$(count_rg "$1"); st=$?
  [ "$st" -eq 0 ] || die "metric collection failed for pattern $1"
  is_num "$n" || die "non-numeric count '$n' for pattern $1"
  RG_COUNT=$n
}

rs_files=$(find . -type f -name '*.rs' -not -path '*/target/*' -not -path '*/vendor/*' -print0 \
  | xargs -0 wc -l) || die "source file scan failed"
[ -n "$rs_files" ] || die "source file scan produced no output"
giants=$(printf '%s\n' "$rs_files" | grep -v ' total$' | awk '{print $1, $2}' \
  | grep -vE '/tests/' | grep -vE '(^|/)tests\.rs$|_tests\.rs$' | awk '$1 >= 800' | wc -l | tr -d ' ')
is_num "$giants" || die "non-numeric giant_files count '$giants'"

count_into '#\[allow\('; allows=$RG_COUNT
count_into '\bprintln!';  p1=$RG_COUNT
count_into '\beprintln!'; p2=$RG_COUNT
count_into '\bdbg!';      p3=$RG_COUNT
prints=$((p1 + p2 + p3))

for v in "$giants" "$allows" "$prints"; do
  is_num "$v" || die "computed metric is not numeric: '$v'"
done

[ -f "$BASE" ] && [ -r "$BASE" ] || die "baseline unreadable/invalid"
read -r base_giants base_allows base_prints <<<"$(grep -oE '"count": [0-9]+' "$BASE" | awk '{print $2}' | tr '\n' ' ')"
for v in "${base_giants:-}" "${base_allows:-}" "${base_prints:-}"; do
  is_num "$v" || die "baseline unreadable/invalid"
done

fail=0
check() { local name=$1 now=$2 base=$3
  if [ "$now" -gt "$base" ]; then echo "RATCHET-FAIL $name: $now > baseline $base (+$((now-base)))"; fail=1
  else echo "ratchet ok $name: $now <= baseline $base"; fi; }
check giant_files "$giants" "$base_giants"
check allow_attrs "$allows" "$base_allows"
check print_macros "$prints" "$base_prints"

[ "$fail" -eq 0 ] && echo "RATCHET-OK" || exit 1
