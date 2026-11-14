#!/usr/bin/env bash
# The nightly test job (Fable's test verdict 2026-11-09, sections 3 and 6; PRs 10a and 10b).
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
#   budget      every night, after libs: the integration tests that hold a
#               row of scripts/nightly/budget-set.tsv, built with a shard's
#               args; its verdict runs only the budget tests, so each host
#               gets one time a night per budget test. Every other verdict
#               leaves the budget tests out, so none runs twice; a lib row
#               runs where the lib tests run. Like the libs, a budget verdict
#               that did not run makes the night red but does not stop it.
#   bench       every night, after budget (PR 10b2): oneiron-bench, which every
#               other selection leaves out as CI's full tier does. Its bin's
#               unit tests and its integration tests, built with --workspace
#               kept (no package the other selections build changes features
#               that way; `-p oneiron-bench` alone would rebuild the core).
#               Then the bench jobs: offline runs of the bench bin it built
#               (nightly_bench.py BENCH_JOBS), one `## NIGHTLY bench-<job>`
#               line each, their output in --out/bench-<job>.out. A job's
#               metrics are timed in the budget band; a job that ends
#               otherwise than expected, or output that breaks a promise of
#               the retired bench tests, makes the night red.
#   tests-NN    the integration tests by name in sorted order, in shards of
#               --shard-files names (about 600 MB of test binary per name on the
#               fleet), from the cursor on, wrapping past the end of the list:
#               build, run, delete the shard's test binaries, move the cursor.
#               The night stops before a shard when --max-shards shards have
#               run, or when the longest shard so far would end past the
#               deadline (--stop-at HH:MM Japan time, or --deadline-epoch), at
#               a selection whose build fails beyond pruning, and at a shard
#               whose verdict stage did not run (the cursor stays on it, so the
#               next night retries it).
#               The next night resumes at the cursor; a full cycle runs every
#               file once.
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
#   verdict     `--profile nightly -E 'not (P | X) & not (<lib report>)'`
#               (bench: `package(=oneiron-bench) & not (P | X)`). The
#               profile's default filter keeps the quarantined tests out. A
#               stage ran when nextest exits 0 (passed) or 100 (tests failed)
#               and wrote its JUnit; any other end (a test list nextest could
#               not make, a setup error) is a stage that did not run. Each
#               stage's end is a row of stages.tsv in --out; a verdict stage
#               that did not run makes the night red, and on a shard it stops
#               the night with the cursor kept on that shard.
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
# next night's --previous, so a flip compares a test with its own last run),
# flake-row.json, budget-samples.json (the next night's --budget-samples: each
# host's budget test times, from which its baseline comes until a PR commits
# scripts/nightly/budget-baseline.tsv), budget-row.json and bench-row.json (the
# bench jobs' exits, metrics and promise states) in --out. The budget band is
# report only. The cursor file is rewritten after each shard.
#
# ONEIRON_TESTKIT_TODAY is the night's date, so the testkit lint test fails an
# expired quarantine entry. Plain bash 3.2 (macOS /bin/bash) runs it too.
#
# Usage: scripts/nightly/run_nightly.sh --out DIR [--date YYYY-MM-DD]
#          [--shard-files N] [--cursor FILE] [--max-shards K]
#          [--stop-at HH:MM | --deadline-epoch SECONDS]
#          [--previous RESULTS_STORE_JSON] [--history SUMMARY_LINES_FILE]
#          [--budget-samples BUDGET_SAMPLES_JSON]
# Exit: 0 green night, 1 red night, 2 the job could not start.
set -u -o pipefail

out='' night='' shard_files=0 cursor='' max_shards='' stop_at='' deadline='' previous='' history='' budget_samples=''
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
    --budget-samples) budget_samples=$2; shift 2 ;;
    *) echo "run_nightly.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
usage="usage: run_nightly.sh --out DIR [--date YYYY-MM-DD] [--shard-files N] [--cursor FILE] [--max-shards K] [--stop-at HH:MM | --deadline-epoch S] [--previous FILE] [--history FILE] [--budget-samples FILE]"
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
# a reused --out dir must not lend an older night's results or build errors
rm -f "$out"/junit-*.xml "$out/pending-door.json" "$out/stages.tsv" "$out"/build-*.log "$out"/failed-units-*.json \
  "$out/budget-baseline-proposal.tsv" "$out/bench-jobs.tsv" "$out"/bench-*.out "$out"/bench-*.err
echo "## NIGHTLY head=${commit:0:12} date=$night shard_files=$shard_files max_shards=${max_shards:-none} deadline=${deadline:-none} jobs=${CARGO_BUILD_JOBS:-default} lib_jobs=${NIGHTLY_LIB_JOBS:-default}"
if ! cargo nextest --version > "$out/nextest-version.txt" 2>&1; then
  step nextest missing; exit 2
fi
echo "## NIGHTLY nextest $(head -1 "$out/nextest-version.txt")"
cargo metadata --locked --format-version 1 --no-deps > "$out/metadata.json" 2> "$out/metadata.err" || { step metadata $?; exit 2; }
target=$(report field "$out/metadata.json" target_directory)
plan=$out/plan.json
budget_set=$root/scripts/nightly/budget-set.tsv budget_baseline=$root/scripts/nightly/budget-baseline.tsv
plan_args=(--shard-files "$shard_files" --cursor "$cursor" --bench)
budget_filter='none()'
if [ -f "$budget_set" ]; then
  plan_args+=(--budget-set "$budget_set")
  budget_filter=$(report budget-filter "$budget_set" --metadata "$out/metadata.json") || { step budget-filter $?; exit 2; }
fi
report plan "$out/metadata.json" "${plan_args[@]}" > "$plan" || { step plan $?; exit 2; }
echo "## NIGHTLY plan target=$target cursor=$(tr -d '\n' 2>/dev/null < "$cursor" || echo none) selections=$(report args "$plan" | cut -d' ' -f1 | tr '\n' ' ')"

build_selection() {  # name -> 0 once its units build (failed units left out), 1 when it is dropped
  local name=$1 round=0 rc log start jobs=${CARGO_BUILD_JOBS:-}
  local -a args logs
  logs=()
  [ "$name" = libs ] && [ -n "${NIGHTLY_LIB_JOBS:-}" ] && jobs=$NIGHTLY_LIB_JOBS
  while :; do
    round=$((round + 1))
    log=$out/build-$name-$round.log
    logs+=("$log")
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
    report failed-units "${logs[@]}" > "$out/failed-units-$name.json"   # this build's rounds only
    if [ $round -ge 3 ]; then
      report drop "$plan" "$name" "the build failed in $round rounds"
      return 1
    fi
    report prune "$plan" "$name" "$out/failed-units-$name.json" "$out/metadata.json" || return 1
  done
}

run_stage() {  # stage profile filter selection-name -- selection args; 0 when the stage ran (exit 0 or 100, JUnit)
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
  local ran=no
  if [ -n "$junit" ] && { [ $rc -eq 0 ] || [ $rc -eq 100 ]; }; then ran=yes; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$stage" "$name" "$rc" "$([ -n "$junit" ] && echo yes || echo no)" "$ran" \
    >> "$out/stages.tsv"
  step "$stage-$name" $rc "seconds=$((SECONDS - start))${junit:+ junit=$junit}$([ -n "$junit" ] || echo ' (no JUnit)')"
  [ "$ran" = yes ]
}

delete_test_binaries() {  # selection name: its test binaries in the target's deps dir, and a bin's own copy
  local binary
  while read -r binary; do
    [ -n "$binary" ] || continue
    find "$target/debug/deps" -maxdepth 1 -type f -name "${binary//-/_}-????????????????" -delete
    rm -f "$target/debug/$binary"
  done < <(report binaries "$plan" "$1")
}

bench_jobs() {  # the bench jobs, from the bin the bench selection built: one bench-jobs.tsv row each (job, exit, seconds)
  local bin=$target/debug/oneiron-bench work=$out/bench-work name expected rc start  # the bench bin is its package's
  local -a job_command
  rm -rf "$work"
  if [ ! -x "$bin" ]; then
    step bench-jobs not-run "($bin was not built)"
    return
  fi
  report bench-inputs "$root" "$work" "$night" "$commit" || { step bench-jobs not-run "(no inputs)"; return; }
  while IFS=$'\t' read -r -a job_command; do
    name=${job_command[0]} expected=${job_command[1]}
    job_command=("${job_command[@]:2}")
    start=$SECONDS
    (cd "$work" && "${job_command[@]}") > "$out/bench-$name.out" 2> "$out/bench-$name.err" < /dev/null
    rc=$?
    printf '%s\t%s\t%s\n' "$name" "$rc" "$((SECONDS - start))" >> "$out/bench-jobs.tsv"
    step "bench-$name" $rc "expected=$expected seconds=$((SECONDS - start))"
  done < <(report bench-jobs "$bin" "$work")
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
every_night() { [ "$1" = libs ] || [ "$1" = budget ] || [ "$1" = bench ]; }  # selections outside the cursor's shards
for name in $(report args "$plan" | cut -d' ' -f1); do
  if ! every_night "$name"; then
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
  if [ "$name" = budget ]; then
    verdict_filter="($budget_filter) & not ($pending_filter | $expired_filter)"
  elif [ "$name" = bench ]; then
    # --workspace without the exclude puts every package's binaries in scope, so P and X stay valid filters here
    verdict_filter="package(=oneiron-bench) & not ($pending_filter | $expired_filter)"
  else
    verdict_filter="not ($pending_filter | $expired_filter) & not ($lib_report) & not ($budget_filter)"
  fi
  if ! run_stage verdict nightly "$verdict_filter" "$name" -- "${sel_args[@]}" && ! every_night "$name"; then
    # The shard's tests did not run (stages.tsv makes the night red): stop with the cursor on it, as for a dropped
    # build, so the next night retries it and no shard is skipped. The libs and the budget tests run every night, so
    # theirs goes on.
    measure "$name" $((SECONDS - started))
    [ "$shard_files" -gt 0 ] && delete_test_binaries "$name"
    echo "## NIGHTLY stop reason=verdict-not-run next=$name"
    break
  fi
  if [ "$name" = budget ]; then
    # its binaries' other tests, quarantined and pending ones included, run in their shards
    measure "$name" $((SECONDS - started))
    [ "$shard_files" -gt 0 ] && delete_test_binaries "$name"
    continue
  fi
  if [ "$name" = libs ]; then
    run_stage libtest nightly "($lib_report) & not ($pending_filter | $expired_filter)" "$name" -- "${sel_args[@]}"
  fi
  run_stage quarantine quarantine "all()" "$name" -- "${sel_args[@]}"
  if [ "${pending:-0}" != 0 ]; then
    run_stage pending pending-door "$pending_filter" "$name" -- "${sel_args[@]}"
  fi
  [ "$name" = bench ] && bench_jobs
  measure "$name" $((SECONDS - started))
  case $name in
    libs) ;;
    bench) [ "$shard_files" -gt 0 ] && delete_test_binaries "$name" ;;
    *)
      [ "$shard_files" -gt 0 ] && delete_test_binaries "$name"
      report advance "$plan" "$name" "$cursor"
      took=$((SECONDS - started))
      shards_done=$((shards_done + 1)) shard_seconds=$((shard_seconds + took))
      [ "$took" -gt "$longest" ] && longest=$took
      ;;
  esac
done
echo "## NIGHTLY measured shards=$shards_done minutes_per_shard=$(( shards_done > 0 ? (shard_seconds / shards_done + 30) / 60 : 0 )) longest_shard_minutes=$(( (longest + 30) / 60 )) target_peak_kb=$target_peak_kb memory_peak_kb=$(memory_peak_kb) cursor=$(tr -d '\n' 2>/dev/null < "$cursor" || echo none)"

summary_args=(--out "$out" --date "$night" --head "$commit" --plan "$plan"
  --pending-door "$out/pending-door.json" --baseline "$root/scripts/nightly/libtest-quarantine-baseline.tsv"
  --census-root "$root")
[ -n "$previous" ] && summary_args+=(--previous "$previous")
[ -n "$history" ] && summary_args+=(--history "$history")
[ -f "$budget_set" ] && summary_args+=(--budget-set "$budget_set")
[ -f "$budget_baseline" ] && summary_args+=(--budget-baseline "$budget_baseline")
[ -n "$budget_samples" ] && summary_args+=(--budget-samples "$budget_samples")
line=$(report summary "${summary_args[@]}")
verdict=$?
step summary $verdict
[ -n "$line" ] || { echo "## NIGHTLY SUMMARY none (nightly_report.py summary failed)"; exit 2; }
echo "## NIGHTLY SUMMARY $line"
exit $(( verdict == 0 ? 0 : 1 ))
