#!/usr/bin/env bash
# The nightly test job (Fable's test verdict 2026-11-09, sections 3 and 6; PR 10a).
#
# Runs the workspace's tests under `--cfg oneiron_test_support` (the test
# doors) at the checked-out commit, and writes the night's verdict. One booked
# fleet job runs it each night; no PR's CI runs it. Every step prints a
# `## NIGHTLY <step> rc=<code>` line.
#
# A resumable sharded night (Engine RULING NIGHTLY-SCALE, 14 Nov 10:42):
#   libs        every lib test and bin test, plus the pending-door tool's own
#               test (so cargo builds oneiron-testkit-pending-door), every
#               night, first. NIGHTLY_LIB_JOBS, when set, is its build's job
#               count (the core's lib and lib test peak above 23 GiB each in
#               codegen: one job on a 36G host).
#   tests-NN    the integration tests by name in sorted order, in shards of
#               --shard-files names (about 600 MB of test binary per name on the
#               fleet), from the cursor on, wrapping past the end of the list:
#               build, run, delete the shard's test binaries, move the cursor.
#               The night stops before a shard when --max-shards shards have
#               run, or when the longest shard so far would end past the
#               deadline (--stop-at HH:MM Japan time, or --deadline-epoch), and
#               at a selection whose build fails beyond pruning (the cursor
#               stays on it, so the next night retries it).
#               The next night resumes at the cursor; a full cycle runs every
#               file once.
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
#   measure     minutes, the target dir's size, the free disk and the job's
#               memory peak (cgroup v2 memory.peak), before the shard's binaries
#               are deleted.
# Then the summary: one line (`## NIGHTLY SUMMARY NIGHTLY <date> ...`) and
# summary.json, summary.txt, results-store.json (each test's last outcome: the
# next night's --previous, so a flip compares a test with its own last run)
# and flake-row.json in --out. The cursor file is rewritten after each shard.
#
# ONEIRON_TESTKIT_TODAY is the night's date, so the testkit lint test fails an
# expired quarantine entry. Plain bash 3.2 (macOS /bin/bash) runs it too.
#
# Usage: scripts/nightly/run_nightly.sh --out DIR [--date YYYY-MM-DD]
#          [--shard-files N] [--cursor FILE] [--max-shards K]
#          [--stop-at HH:MM | --deadline-epoch SECONDS]
#          [--previous RESULTS_STORE_JSON] [--history SUMMARY_LINES_FILE]
# Exit: 0 green night, 1 red night, 2 the job could not start.
set -u -o pipefail

out='' night='' shard_files=0 cursor='' max_shards='' stop_at='' deadline='' previous='' history=''
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=$2; shift 2 ;;
    --date) night=$2; shift 2 ;;
    --shard-files) shard_files=$2; shift 2 ;;
    --cursor) cursor=$2; shift 2 ;;
    --max-shards) max_shards=$2; shift 2 ;;
    --stop-at) stop_at=$2; shift 2 ;;
    --deadline-epoch) deadline=$2; shift 2 ;;
    --previous) previous=$2; shift 2 ;;
    --history) history=$2; shift 2 ;;
    *) echo "run_nightly.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
usage="usage: run_nightly.sh --out DIR [--date YYYY-MM-DD] [--shard-files N] [--cursor FILE] [--max-shards K] [--stop-at HH:MM | --deadline-epoch S] [--previous FILE] [--history FILE]"
[ -n "$out" ] || { echo "$usage" >&2; exit 2; }
night=${night:-$(TZ=Asia/Tokyo date +%F)}
[[ $night =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "run_nightly.sh: --date $night is not YYYY-MM-DD" >&2; exit 2; }
for number in "$shard_files" "${max_shards:-0}" "${deadline:-0}"; do
  [[ $number =~ ^[0-9]+$ ]] || { echo "run_nightly.sh: $number is not a number" >&2; exit 2; }
done

root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$out" && out=$(cd "$out" && pwd)
cursor=${cursor:-$out/cursor.json}
cd "$root" || exit 2
report() { python3 "$root/scripts/nightly/nightly_report.py" "$@"; }
step() { echo "## NIGHTLY $1 rc=$2${3:+ $3}"; }
if [ -n "$stop_at" ]; then
  deadline=$(report deadline "$stop_at") || exit 2
fi

export CARGO_TERM_COLOR=never ONEIRON_TESTKIT_TODAY=$night
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg oneiron_test_support"
commit=$(git rev-parse HEAD) || exit 2
rm -f "$out"/junit-*.xml "$out/pending-door.json"   # a reused --out dir must not lend an older night's results
echo "## NIGHTLY head=${commit:0:12} date=$night shard_files=$shard_files max_shards=${max_shards:-none} deadline=${deadline:-none} jobs=${CARGO_BUILD_JOBS:-default} lib_jobs=${NIGHTLY_LIB_JOBS:-default}"
if ! cargo nextest --version > "$out/nextest-version.txt" 2>&1; then
  step nextest missing; exit 2
fi
echo "## NIGHTLY nextest $(head -1 "$out/nextest-version.txt")"
cargo metadata --locked --format-version 1 --no-deps > "$out/metadata.json" 2> "$out/metadata.err" || { step metadata $?; exit 2; }
target=$(report field "$out/metadata.json" target_directory)
plan=$out/plan.json
report plan "$out/metadata.json" --shard-files "$shard_files" --cursor "$cursor" > "$plan" || { step plan $?; exit 2; }
echo "## NIGHTLY plan target=$target cursor=$(tr -d '\n' 2>/dev/null < "$cursor" || echo none) selections=$(report args "$plan" | cut -d' ' -f1 | tr '\n' ' ')"

build_selection() {  # name -> 0 once its units build (failed units left out), 1 when it is dropped
  local name=$1 round=0 rc log start jobs=${CARGO_BUILD_JOBS:-}
  local -a args
  [ "$name" = libs ] && [ -n "${NIGHTLY_LIB_JOBS:-}" ] && jobs=$NIGHTLY_LIB_JOBS
  while :; do
    round=$((round + 1))
    log=$out/build-$name-$round.log
    read -r -a args <<< "$(report args "$plan" --name "$name")"
    start=$SECONDS
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
  # nextest's store dir is target/nextest under the workspace root unless the config moves it; look under the
  # target dir too
  local candidate junit='' start=$SECONDS
  for candidate in "$root/target/nextest/$profile/junit.xml" "$target/nextest/$profile/junit.xml"; do rm -f "$candidate"; done
  cargo nextest run --locked --all-features "$@" --profile "$profile" --no-tests=pass -E "$filter" \
    > "$out/$stage-$name.log" 2>&1
  local rc=$?
  for candidate in "$root/target/nextest/$profile/junit.xml" "$target/nextest/$profile/junit.xml"; do
    [ -f "$candidate" ] && { junit=$candidate; break; }
  done
  [ -n "$junit" ] && cp "$junit" "$out/junit-$stage-$name.xml"
  step "$stage-$name" $rc "seconds=$((SECONDS - start))${junit:+ junit=$junit}$([ -n "$junit" ] || echo ' (no JUnit)')"
}

delete_test_binaries() {  # selection name: its integration test binaries in the target's deps dir
  local test_name
  while read -r test_name; do
    [ -n "$test_name" ] || continue
    find "$target/debug/deps" -maxdepth 1 -type f -name "${test_name//-/_}-????????????????" -delete
  done < <(report tests "$plan" "$1")
}

memory_peak_kb() {  # the job's cgroup v2 memory peak, or n/a
  local group file
  group=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)
  file=/sys/fs/cgroup$group/memory.peak
  if [ -n "$group" ] && [ -r "$file" ]; then echo $(( $(cat "$file") / 1024 )); else echo n/a; fi
}

target_peak_kb=0
measure() {  # selection name, its seconds
  local size
  size=$(du -sk "$target" 2>/dev/null | cut -f1)
  [ "${size:-0}" -gt "$target_peak_kb" ] && target_peak_kb=$size
  echo "## NIGHTLY measure after=$1 minutes=$(( ($2 + 30) / 60 )) target_kb=${size:-n/a} avail_kb=$(df -Pk "$target" | awk 'NR == 2 {print $4}') memory_peak_kb=$(memory_peak_kb)"
}

pending_filter='none()' expired_filter='none()' pending=0
lib_report='kind(lib) & (package(oneiron) | package(oneiron-server))'
shards_done=0 shard_seconds=0 longest=0
for name in $(report args "$plan" | cut -d' ' -f1); do
  if [ "$name" != libs ]; then
    if [ -n "$max_shards" ] && [ "$shards_done" -ge "$max_shards" ]; then
      echo "## NIGHTLY stop reason=max-shards next=$name"; break
    fi
    if [ -n "$deadline" ] && [ $(( $(date +%s) + longest )) -gt "$deadline" ]; then
      echo "## NIGHTLY stop reason=deadline next=$name longest_shard_seconds=$longest"; break
    fi
  fi
  started=$SECONDS
  if ! build_selection "$name"; then
    # A selection whose build fails beyond pruning (a setup error, a lib or build script, an OOM) stops the night and
    # leaves the cursor on it: the next night retries it, so no shard is skipped, and the red names it.
    step "build-$name" dropped
    echo "## NIGHTLY stop reason=build-dropped next=$name"
    break
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
  measure "$name" $((SECONDS - started))
  if [ "$name" != libs ]; then
    [ "$shard_files" -gt 0 ] && delete_test_binaries "$name"
    report advance "$plan" "$name" "$cursor"
    took=$((SECONDS - started))
    shards_done=$((shards_done + 1)) shard_seconds=$((shard_seconds + took))
    [ "$took" -gt "$longest" ] && longest=$took
  fi
done
echo "## NIGHTLY measured shards=$shards_done minutes_per_shard=$(( shards_done > 0 ? (shard_seconds / shards_done + 30) / 60 : 0 )) longest_shard_minutes=$(( (longest + 30) / 60 )) target_peak_kb=$target_peak_kb memory_peak_kb=$(memory_peak_kb) cursor=$(tr -d '\n' 2>/dev/null < "$cursor" || echo none)"

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
