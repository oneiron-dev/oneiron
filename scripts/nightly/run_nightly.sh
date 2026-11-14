#!/usr/bin/env bash
# The nightly test job (Fable's test verdict 2026-11-09, sections 3 and 6; PR 10a).
#
# Runs the workspace's tests once, at the checked-out commit, under
# `--cfg oneiron_test_support` (the test doors), and writes the night's verdict.
# One booked fleet job runs it each night; no PR's CI runs it. Every step prints
# a `## NIGHTLY <step> rc=<code>` line.
#
# The plan (scripts/nightly/nightly_report.py plan) is a list of selections,
# each built and run in turn:
#   libs        every lib test and bin test, plus the pending-door tool's own
#               test, so cargo builds oneiron-testkit-pending-door
#   tests-NN    the integration tests by name: all at once, or with
#               --shard-files N in shards of N names whose test binaries are
#               deleted after the shard has run (about 600 MB each on the
#               fleet: the whole set does not fit one host's disk)
# oneiron-bench is left out, as CI's full tier leaves it out.
#
# For each selection:
#   build       `cargo nextest run --no-run`. A unit that does not compile is
#               left out (nightly_report.py prune) and the build retried, at
#               most three rounds; a failed lib or build script drops the
#               selection. Any unit left out makes the night red.
#   pending     (after the libs build) oneiron-testkit-pending-door <date>:
#               the NO-DOOR register (ONEIRON_TESTKIT_NO_DOOR_REGISTER) gives
#               the pending filter P and the expired filter X. An expired test
#               fails the night: door or delete.
#   verdict     `--profile nightly -E 'not (P | X) & not (<lib report>)'`. The
#               profile's default filter keeps the quarantined tests out.
#   libtest     (libs only) the lib tests of oneiron and oneiron-server under
#               the nightly profile, report only: their results per quarantined
#               module (Engine ruling 13 Nov 16:20, ASK PR10-NIGHTLY-OVERLAP).
#   quarantine  `--profile quarantine`, report only.
#   pending-door `--profile pending-door -E 'P'`, report only.
# Then the summary: one line (`## NIGHTLY SUMMARY NIGHTLY <date> ...`) and
# summary.json, summary.txt, results.json (the next night's --previous) and
# flake-row.json in --out.
#
# ONEIRON_TESTKIT_TODAY is the night's date, so the testkit lint test fails an
# expired quarantine entry. NIGHTLY_LIB_JOBS, when set, is the build's job
# count for the libs selection only (the core's lib and lib test peak above
# 23 GiB each in codegen: one job on a 36G host).
#
# Usage: scripts/nightly/run_nightly.sh --out DIR [--date YYYY-MM-DD]
#          [--shard-files N] [--rotation I/K]
#          [--previous RESULTS_JSON] [--history SUMMARY_LINES_FILE]
# Exit: 0 green night, 1 red night, 2 the job could not start.
# Plain bash 3.2 (macOS /bin/bash) runs it too.
set -u -o pipefail

out='' night='' shard_files=0 rotation='' previous='' history=''
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=$2; shift 2 ;;
    --date) night=$2; shift 2 ;;
    --shard-files) shard_files=$2; shift 2 ;;
    --rotation) rotation=$2; shift 2 ;;
    --previous) previous=$2; shift 2 ;;
    --history) history=$2; shift 2 ;;
    *) echo "run_nightly.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$out" ] || { echo "usage: run_nightly.sh --out DIR [--date YYYY-MM-DD] [--shard-files N] [--rotation I/K] [--previous FILE] [--history FILE]" >&2; exit 2; }
night=${night:-$(TZ=Asia/Tokyo date +%F)}
[[ $night =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "run_nightly.sh: --date $night is not YYYY-MM-DD" >&2; exit 2; }
[[ $shard_files =~ ^[0-9]+$ ]] || { echo "run_nightly.sh: --shard-files $shard_files is not a number" >&2; exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$out" && out=$(cd "$out" && pwd)
cd "$root" || exit 2
report() { python3 "$root/scripts/nightly/nightly_report.py" "$@"; }
step() { echo "## NIGHTLY $1 rc=$2${3:+ $3}"; }

export CARGO_TERM_COLOR=never ONEIRON_TESTKIT_TODAY=$night
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg oneiron_test_support"
commit=$(git rev-parse HEAD) || exit 2
rm -f "$out"/junit-*.xml "$out/pending-door.json"   # a reused --out dir must not lend an older night's results
echo "## NIGHTLY head=${commit:0:12} date=$night shard_files=$shard_files rotation=${rotation:-none} jobs=${CARGO_BUILD_JOBS:-default} lib_jobs=${NIGHTLY_LIB_JOBS:-default}"
if ! cargo nextest --version > "$out/nextest-version.txt" 2>&1; then
  step nextest missing; exit 2
fi
echo "## NIGHTLY nextest $(head -1 "$out/nextest-version.txt")"
cargo metadata --locked --format-version 1 --no-deps > "$out/metadata.json" 2> "$out/metadata.err" || { step metadata $?; exit 2; }
target=$(report field "$out/metadata.json" target_directory)
plan=$out/plan.json
plan_args=(--shard-files "$shard_files")
[ -n "$rotation" ] && plan_args+=(--rotation "$rotation")
report plan "$out/metadata.json" "${plan_args[@]}" > "$plan" || { step plan $?; exit 2; }
echo "## NIGHTLY plan target=$target selections=$(report args "$plan" | cut -d' ' -f1 | tr '\n' ' ')"

build_selection() {  # name -> 0 once its units build (failed units left out), 1 when it is dropped
  local name=$1 round=0 rc log jobs=${CARGO_BUILD_JOBS:-}
  local -a args
  [ "$name" = libs ] && [ -n "${NIGHTLY_LIB_JOBS:-}" ] && jobs=$NIGHTLY_LIB_JOBS
  while :; do
    round=$((round + 1))
    log=$out/build-$name-$round.log
    read -r -a args <<< "$(report args "$plan" --name "$name")"
    local start=$SECONDS
    if [ -n "$jobs" ]; then
      CARGO_BUILD_JOBS=$jobs cargo nextest run --no-run --locked --all-features "${args[@]}" > "$log" 2>&1
    else
      cargo nextest run --no-run --locked --all-features "${args[@]}" > "$log" 2>&1
    fi
    rc=$?
    step "build-$name" $rc "round=$round seconds=$((SECONDS - start))"
    [ $rc -eq 0 ] && return 0
    sed -n 's/^error: could not compile /## NIGHTLY failed-unit /p' "$log" | sort -u | head -40
    report failed-units "$out/build-$name-"*.log > "$out/failed-units-$name.json"
    if [ $round -ge 3 ]; then
      report drop "$plan" "$name" "the build failed in $round rounds"
      return 1
    fi
    report prune "$plan" "$name" "$out/failed-units-$name.json" "$out/metadata.json" || return 1
  done
}

run_stage() {  # stage profile filter selection-name -- selection args
  local stage=$1 profile=$2 filter=$3 name=$4; shift 5
  local junit=$target/nextest/$profile/junit.xml start=$SECONDS
  rm -f "$junit"
  cargo nextest run --locked --all-features "$@" --profile "$profile" --no-tests=pass -E "$filter" \
    > "$out/$stage-$name.log" 2>&1
  local rc=$?
  [ -f "$junit" ] && cp "$junit" "$out/junit-$stage-$name.xml"
  step "$stage-$name" $rc "seconds=$((SECONDS - start))$([ -f "$junit" ] || echo ' (no JUnit)')"
}

delete_test_binaries() {  # selection name: its integration test binaries in the target's deps dir
  local test_name
  while read -r test_name; do
    [ -n "$test_name" ] || continue
    find "$target/debug/deps" -maxdepth 1 -type f -name "${test_name//-/_}-????????????????" -delete
  done < <(report tests "$plan" "$1")
}

pending_filter='none()' expired_filter='none()' pending=0
lib_report='kind(lib) & (package(oneiron) | package(oneiron-server))'
for name in $(report args "$plan" | cut -d' ' -f1); do
  if ! build_selection "$name"; then
    step "build-$name" dropped
    continue
  fi
  if [ "$name" = libs ]; then
    door_bin=$target/debug/oneiron-testkit-pending-door
    if [ -x "$door_bin" ]; then
      "$door_bin" "$night" > "$out/pending-door.json" 2> "$out/pending-door.err"
      step pending-door $?
      pending_filter=$(report field "$out/pending-door.json" pending_filter)
      expired_filter=$(report field "$out/pending-door.json" expired_filter)
      pending=$(report field "$out/pending-door.json" pending)
    else
      step pending-door no-binary "($door_bin was not built)"
    fi
  fi
  read -r -a sel_args <<< "$(report args "$plan" --name "$name")"
  run_stage verdict nightly "not ($pending_filter | $expired_filter) & not ($lib_report)" "$name" -- "${sel_args[@]}"
  if [ "$name" = libs ]; then
    run_stage libtest nightly "($lib_report) & not ($pending_filter | $expired_filter)" "$name" -- "${sel_args[@]}"
  fi
  run_stage quarantine quarantine "all()" "$name" -- "${sel_args[@]}"
  if [ "${pending:-0}" != 0 ]; then
    run_stage pending pending-door "$pending_filter" "$name" -- "${sel_args[@]}"
  fi
  if [ "$shard_files" -gt 0 ] && [ "$name" != libs ]; then
    delete_test_binaries "$name"
  fi
  echo "## NIGHTLY disk after=$name avail_kb=$(df -Pk "$target" | awk 'NR == 2 {print $4}')"
done

summary_args=(--out "$out" --date "$night" --head "$commit" --plan "$plan"
  --pending-door "$out/pending-door.json" --baseline "$root/scripts/nightly/libtest-quarantine-baseline.tsv"
  --census-root "$root")
[ -n "$previous" ] && summary_args+=(--previous "$previous")
[ -n "$history" ] && summary_args+=(--history "$history")
line=$(report summary "${summary_args[@]}")
verdict=$?
step summary $verdict
[ -n "$line" ] || { echo "## NIGHTLY SUMMARY none (nightly_report.py summary failed)"; exit 2; }
echo "## NIGHTLY SUMMARY $line"
exit $(( verdict == 0 ? 0 : 1 ))
