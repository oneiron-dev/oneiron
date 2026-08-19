#!/usr/bin/env bash
# Ratchet: recompute 3 metrics and fail if any exceeds baseline.json. No jq
# dependency — baseline's 3 "count" fields are the only ones at that depth,
# extracted in fixed order: giant_files, allow_attrs, print_macros.
#
# To move the baseline on a real, reviewed increase: rerun this file's find/rg
# commands by hand, write the new counts into baseline.json's "count" fields,
# bump computed_at_commit/computed_date, and say why in the PR description —
# never bump silently just to make check.sh pass.
set -uo pipefail
cd "$(dirname "$0")/../.."
BASE="scripts/ratchet/baseline.json"
GLOBS=(--glob '!**/tests/**' --glob '!**/tests.rs' --glob '!**/*_tests.rs')

count_rg() { rg -c "$1" "${GLOBS[@]}" crates/*/src 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'; }

giants=$(find . -type f -name '*.rs' -not -path '*/target/*' -not -path '*/vendor/*' -print0 \
  | xargs -0 wc -l | grep -v ' total$' | awk '{print $1, $2}' \
  | grep -vE '/tests/' | grep -vE '(^|/)tests\.rs$|_tests\.rs$' | awk '$1 >= 800' | wc -l | tr -d ' ')
allows=$(count_rg '#\[allow\(')
prints=$(( $(count_rg '\bprintln!') + $(count_rg '\beprintln!') + $(count_rg '\bdbg!') ))
giants=${giants:-0}; allows=${allows:-0}; prints=${prints:-0}

read -r base_giants base_allows base_prints <<<"$(grep -oE '"count": [0-9]+' "$BASE" | awk '{print $2}' | tr '\n' ' ')"

fail=0
check() { local name=$1 now=$2 base=$3
  if [ "$now" -gt "$base" ]; then echo "RATCHET-FAIL $name: $now > baseline $base (+$((now-base)))"; fail=1
  else echo "ratchet ok $name: $now <= baseline $base"; fi; }
check giant_files "$giants" "$base_giants"
check allow_attrs "$allows" "$base_allows"
check print_macros "$prints" "$base_prints"

[ "$fail" -eq 0 ] && echo "RATCHET-OK" || exit 1
