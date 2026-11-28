#!/usr/bin/env bash
# Qualification of the Linux job unit: pass 33 (33-exec-node/DESIGN.md) sections 7.6 and 7.8, tests T17 to T23d, as
# pass 34 (34-compute-general/DESIGN.md) sections 2.2 and 9.2 amend them (T23 is replaced; T18b runs at the attempt's
# own maximum, first case 1,800 s; the minimum contract is G1's and R3b's).
#
# It needs root and systemd as process 1 on a SCRATCH machine: it installs the job unit, makes accounts and fake
# device nodes, and starts job units. Run it in a container with systemd as process 1 (qualify_in_container.sh), or
# on a node before its first job (row R6). No engine and no issuer run while it does: every job is started the way
# the engine starts one (launch.json in the key's control directory, then `oneiron execution-node unit-control start`
# as the engine's account, through the job control socket install wrote; the engine's account has no polkit grant).
#
# usage: qualify_systemd_scope.sh --oneiron <binary> [--maximum-secs <n>] [--only <test name>]...
# Prints `## TEST <name> PASS|FAIL|UNPROVEN <why>` per test and, last, `## QUALIFY rc=<n> pass=<p> fail=<f> unproven=<u>`.
# UNPROVEN: the machine cannot show the bound at all (pass 34: an unrequired bound it lacks is recorded, not failed).
set -u
BIN_SRC=; MAXIMUM=1800; ONLY=()
while [ $# -gt 0 ]; do
  case $1 in
    --oneiron) BIN_SRC=$2; shift 2;;
    --maximum-secs) MAXIMUM=$2; shift 2;;
    --only) ONLY+=("$2"); shift 2;;
    *) echo "unknown argument $1" >&2; exit 64;;
  esac
done
[ -n "$BIN_SRC" ] || { echo "usage: $0 --oneiron <binary> [--maximum-secs <n>] [--only <test>]..." >&2; exit 64; }
[ "$(id -u)" = 0 ] || { echo "## QUALIFY rc=77 why=not-root"; exit 77; }
[ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] || { echo "## QUALIFY rc=77 why=process-1-is-not-systemd"; exit 77; }
# Every tool a case reads its verdict with, checked once here, so a missing one never reads as a failed bound (cmp was
# missing from the Arch container and failed the log case in run q5: FIX EXEC-UNIT-QUALIFY-LOG-CASE-NO-CMP; review r7
# R7-06).
for tool in jq socat runuser timeout journalctl systemctl sha256sum stat awk fallocate; do
  command -v "$tool" > /dev/null || { echo "## QUALIFY rc=77 why=no-$tool"; exit 77; }
done

BIN=/usr/local/bin/oneiron
ENGINE=oneiron-qual-engine
ENGINE_HOME=/var/lib/oneiron-qual-engine
VAULT=$ENGINE_HOME/vault
KEYSTORE=/var/lib/oneiron-qual-keystore
JOB=oneiron-job
NODE_FILE=/etc/oneiron/execution-node.toml
STATE=/var/lib/oneiron-qual/jobs
WORK=/srv/oneiron-qual-jobs
PASS=0; FAIL=0; UNPROVEN=0

result() { # <name> <PASS|FAIL|UNPROVEN> <why>
  echo "## TEST $1 $2 $3"
  case $2 in PASS) PASS=$((PASS + 1));; FAIL) FAIL=$((FAIL + 1));; *) UNPROVEN=$((UNPROVEN + 1));; esac
}
wanted() { [ ${#ONLY[@]} -eq 0 ] && return 0; local t; for t in "${ONLY[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }
as_engine() { runuser -u "$ENGINE" -- "$@"; }
# The boot clock in nanoseconds, in bash's 64-bit arithmetic (review r3 R3-11: mawk's %d clamps at 2^31); /proc/uptime
# has two decimals, so the value is good to 10 ms.
boot_ns() { local up; read -r up _ < /proc/uptime; echo $(( ${up%.*} * 1000000000 + 10#${up#*.} * 10000000 )); }

node_file() { # [device_files toml lines]
  mkdir -p /etc/oneiron && chmod 0755 /etc/oneiron
  cat > "$NODE_FILE" <<EOF
[execution_node]
enabled = false
state_dir = "$STATE"
work_dir = "$WORK"
disk_reserve_gib = 0
state_floor_mib = 0
job_account = "$JOB"

[execution_node.device_files]
${1:-}

[execution_node.templates.qual]
repo = "/srv/git/qual.git"
entries = ["units/*.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = $((MAXIMUM + 600))
memory_gib = 2
disk_gib = 1
write_mib_per_sec = 20

[execution_node.templates.qualstrict]
repo = "/srv/git/qual.git"
entries = ["units/*.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 600
memory_gib = 2
disk_gib = 1
require = ["file_wall", "network_closed", "processes_hidden"]
EOF
  chmod 0644 "$NODE_FILE"
}

digest_of() { "$BIN" execution-node install --file "$NODE_FILE" --engine-account "$ENGINE" --protect "$KEYSTORE" --dry-run | awk -v t="$1" '$1 == "template" && $2 == t { print $4 }'; }

# launch <test> <template> <maximum_secs> <memory_mib> <device_id> < workload script
# Sets KEY UNIT ID P (payload) C (control). The workload is the entry units/<test>.sh.
launch() {
  local t=$1 template=$2 max=$3 mem=$4 dev=$5 digest
  KEY="qual-$t-$(date +%s%N)"
  UNIT=$("$BIN" execution-node unit-name "$KEY"); ID=${UNIT#oneiron-job@}; ID=${ID%.service}
  P=$WORK/$ID; C=$STATE/control/$ID
  digest=$(digest_of "$template")
  as_engine mkdir -p "$P/checkout/units" "$C"
  as_engine chmod 0755 "$P" "$P/checkout" "$P/checkout/units"
  as_engine tee "$P/checkout/units/$t.sh" > /dev/null
  as_engine chmod 0644 "$P/checkout/units/$t.sh"
  launch_file "$KEY" "$template" "$digest" "units/$t.sh" "$max" "$mem" "$dev" "$(boot_ns)" | as_engine tee "$C/launch.json" > /dev/null
}

# launch_file <key> <template> <digest> <entry> <maximum> <memory_mib> <device_id> <launch_boot_ns>: R3a's LaunchFile
# on G1's general request: one exclusive device claim and its lease when <device_id> is given, none when it is empty.
launch_file() {
  jq -n --arg key "$1" --arg template "$2" --arg digest "$3" --arg entry "$4" --argjson max "$5" --argjson mem "$6" \
    --arg dev "$7" --argjson at "$8" --arg boot "$(cat /proc/sys/kernel/random/boot_id)" '{
    key: $key,
    pin: { template: $template, template_digest: $digest, commit: ("0" * 40), contract_sha256: ("0" * 64),
           contract_path: "units/contract.json", entry: $entry, args: [],
           request: { cpu_threads: 0, memory_mib: $mem, disk_mib: 512, maximum_secs: $max,
                      devices: (if $dev == "" then [] else
                        [{ kind: "gpu", count: 1, memory_mib: 0, features: [], sharing: "exclusive" }] end) },
           scope: "host", network: "none", outputs: [] },
    devices: (if $dev == "" then [] else [{ claim: 0, device_id: $dev, sharing: "exclusive" }] end),
    host_memory_mib: $mem, maximum_secs: $max, boot_id: $boot, launch_boot_ns: $at }'
}

start() { as_engine "$BIN" execution-node unit-control start "$KEY"; }

wait_ended() { # [seconds]
  local i
  for ((i = 0; i < ${1:-120} * 5; i++)); do
    [ -f "$C/ended.json" ] && [ "$(systemctl show -P ActiveState "$UNIT")" != deactivating ] && return 0
    sleep 0.2
  done
  return 1
}
ended() { jq -r "$1" "$C/ended.json"; }
gone() { [ "$(systemctl show -P ActiveState "$UNIT")" != active ] && [ "$(ended .cgroup_empty)" = true ]; }

setup() {
  install -d -m 0755 -o root -g root /usr/local/bin
  install -m 0755 -o root -g root "$BIN_SRC" "$BIN"
  id "$ENGINE" > /dev/null 2>&1 || useradd --system --create-home --home-dir "$ENGINE_HOME" --shell /bin/bash "$ENGINE"
  install -d -m 0700 -o "$ENGINE" -g "$ENGINE" "$VAULT"
  printf 'vault-secret\n' > "$VAULT/secret"; chown "$ENGINE:" "$VAULT/secret"; chmod 0600 "$VAULT/secret"
  install -d -m 0755 -o root -g root "$KEYSTORE"
  printf 'keystore-secret\n' > "$KEYSTORE/key"; chmod 0644 "$KEYSTORE/key"
  mkdir -p /srv/git/qual.git
  node_file ""
}

do_install() {
  INSTALL_OUT=$("$BIN" execution-node install --file "$NODE_FILE" --engine-account "$ENGINE" --protect "$KEYSTORE" 2>&1)
  local rc=$?
  echo "$INSTALL_OUT" | sed 's/^/## INSTALL /'
  [ $rc -eq 0 ] && id "$JOB" > /dev/null 2>&1
}

# Two device nodes the job account can open outside any unit stand in for cards.
pick_devices() {
  local spec path
  mkdir -p /dev/qual
  DEVICES=()
  for spec in "10 200" "10 229" "10 237" "10 238" "10 223" "10 232"; do
    path=/dev/qual/node-${spec// /-}
    [ -e "$path" ] || mknod "$path" c $spec 2> /dev/null || continue
    chmod 0666 "$path"
    runuser -u "$JOB" -- bash -c "exec 3<> $path" 2> /dev/null && DEVICES+=("$path")
    [ ${#DEVICES[@]} -eq 2 ] && break
  done
  if [ ${#DEVICES[@]} -eq 2 ]; then
    node_file "QUAL-DEV-0 = [\"${DEVICES[0]}\"]
QUAL-DEV-1 = [\"${DEVICES[1]}\"]"
  fi
}

# Review r1 of #10439 (P1): a polkit rule for verb `start` on oneiron-job@<id>.service also let the engine's account
# create a transient unit of that name with any command, as root. Now the engine's account holds no grant: it cannot
# start a transient unit, a job unit or any other unit through the service manager. The control socket is root's,
# open to the engine's group alone, and starts the job unit only.
the_engines_account_starts_only_job_units_and_only_through_the_control_socket() {
  local id key marker=/run/qual-transient-ran other=/run/qual-other-ran why= stat_line
  key="qual-control-$(date +%s%N)"
  id=$("$BIN" execution-node unit-name "$key"); id=${id#oneiron-job@}; id=${id%.service}
  rm -f "$marker" "$other"
  printf '[Service]\nType=oneshot\nExecStart=/usr/bin/touch %s\n' "$other" > /etc/systemd/system/qual-other.service
  systemctl daemon-reload
  as_engine systemd-run --no-ask-password --quiet --unit="oneiron-job@$id.service" /usr/bin/touch "$marker" 2> /dev/null \
    && why+="systemd-run of a transient oneiron-job@$id.service was accepted; "
  as_engine systemctl --no-ask-password start "oneiron-job@$id.service" 2> /dev/null \
    && why+="systemctl start of the job unit was accepted without the socket; "
  as_engine systemctl --no-ask-password start qual-other.service 2> /dev/null && why+="another unit was started; "
  sleep 1
  [ -e "$marker" ] && why+="the transient unit's command ran; "
  [ -e "$other" ] && why+="the other unit's command ran; "
  runuser -u "$JOB" -- "$BIN" execution-node unit-control start "$key" > /dev/null 2>&1 \
    && why+="the job account could use the control socket; "
  # Raw requests as the engine's account (review r4 R4-07): the handler itself refuses a name that is not a job
  # instance, a job mode and any other verb.
  local raw_name raw_mode raw_verb started
  raw_name=$(printf 'start oneiron-job@x.service\n' | as_engine socat -t 10 - UNIX-CONNECT:/run/oneiron-job-control.sock 2>&1)
  raw_mode=$(printf 'start %s --job-mode=flush\n' "$id" | as_engine socat -t 10 - UNIX-CONNECT:/run/oneiron-job-control.sock 2>&1)
  raw_verb=$(printf 'isolate %s\n' "$id" | as_engine socat -t 10 - UNIX-CONNECT:/run/oneiron-job-control.sock 2>&1)
  [ "$raw_name" = "refused instance_not_a_job" ] || why+="a raw request for oneiron-job@x.service got '$raw_name'; "
  [ "$raw_mode" = "refused instance_not_a_job" ] || why+="a raw request with a job mode got '$raw_mode'; "
  [ "$raw_verb" = "refused verb_unknown" ] || why+="a raw isolate got '$raw_verb'; "
  # The engine's own path (review r4 R4-02): through the socket the job unit starts. This key has no launch file,
  # so its prepare step refuses; the start itself is what is checked.
  as_engine "$BIN" execution-node unit-control start "$key" > /dev/null 2>&1 \
    || why+="the engine's account could not start the job unit through the socket; "
  sleep 2
  started=$(systemctl show -P InactiveExitTimestampMonotonic "oneiron-job@$id.service")
  [ "${started:-0}" -gt 0 ] || why+="the job unit never left inactive after the socket's ok; "
  stat_line=$(stat -c '%U %G %a' /run/oneiron-job-control.sock 2>&1)
  [ "$stat_line" = "root $(id -gn "$ENGINE") 660" ] || why+="control socket is '$stat_line'; "
  systemctl stop "oneiron-job@$id.service" > /dev/null 2>&1
  systemctl reset-failed "oneiron-job@$id.service" > /dev/null 2>&1
  rm -f /etc/systemd/system/qual-other.service "$marker" "$other"; systemctl daemon-reload
  if [ -z "$why" ]; then
    result "$FUNCNAME" PASS "transient start, direct job start and another unit's start refused for the engine's account; the socket refused a non-job name, a job mode and isolate, and started the job unit for the engine; the job account cannot use it; socket $stat_line"
  else
    result "$FUNCNAME" FAIL "$why"
  fi
}

a_child_that_left_its_session_dies_when_the_leader_exits() {
  launch t17 qual 120 256 "" <<'EOF'
setsid bash -c 'trap "" TERM; echo $$ > "$ONEIRON_JOB_OUT/child.pid"; while :; do sleep 1; done' < /dev/null > /dev/null 2>&1 &
sleep 2
exit 0
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record in 60 s"; return; }
  local child; child=$(cat "$P/out/child.pid" 2> /dev/null)
  if [ -z "$child" ]; then result "$FUNCNAME" FAIL "the child never ran: $(ended .refusal)"; return; fi
  if kill -0 "$child" 2> /dev/null; then result "$FUNCNAME" FAIL "the child $child outlived the unit"; return; fi
  if [ "$(ended .workload_started)" = true ] && gone && [ "$(ended .exit_status)" = 0 ]; then
    result "$FUNCNAME" PASS "leader exited 0; the TERM-ignoring child in its own session is gone; cgroup empty"
  else
    result "$FUNCNAME" FAIL "$(cat "$C/ended.json" | tr -d '\n')"
  fi
}

# A 64 MiB request: the unit's own steps count against its cap, so it gets the 256 MiB floor (FIX
# EXEC-UNIT-STEPS-IN-MEMORY-CAP; q3 at 062b3440 saw a 64 MiB cap OOM-kill the unit before the gate's record). The
# workload holds 400 MiB, over the floor.
a_job_over_its_memory_request_ends_as_memory_limit() {
  launch t18 qual 120 64 "" <<'EOF'
head -c 400M /dev/zero | tail -n 1 > /dev/null
exit 0
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record in 60 s"; return; }
  local cap; cap=$(jq -r '.properties[] | select(startswith("MemoryMax="))' "$C/prepared.json")
  if [ "$cap" = "MemoryMax=$((256 << 20))" ] && [ "$(ended .service_result)" = oom-kill ] && [ "$(ended .workload_started)" = true ] && gone; then
    result "$FUNCNAME" PASS "64 MiB request, $cap (the floor); the workload started; service result oom-kill; cgroup empty"
  else
    local scope=absent; [ -f "$C/scope.json" ] && scope=present
    result "$FUNCNAME" FAIL "${cap:-no MemoryMax in prepared.json}; scope.json $scope; $(tr -d '\n' < "$C/ended.json")"
  fi
}

# A workload that ends at once is recorded as started: the gate judges the exec by job-exec's exec mark on the report
# pipe, never by the process after the pipe closed (FIX EXEC-UNIT-GATE-EXEC-RACE). Three runs.
a_workload_that_ends_at_once_is_recorded_as_started() {
  local run why=
  for run in 1 2 3; do
    launch t17c qual 120 256 "" <<'EOF'
exit 3
EOF
    start
    wait_ended 60 || { why="run $run: no end record in 60 s"; break; }
    if [ "$(ended .workload_started)" != true ] || [ "$(ended .exit_code)" != exited ] || [ "$(ended .exit_status)" != 3 ]; then
      why="run $run: $(tr -d '\n' < "$C/ended.json")"; break
    fi
  done
  if [ -z "$why" ]; then
    result "$FUNCNAME" PASS "3 workloads that exit 3 at once: each recorded started, exit 3"
  else
    result "$FUNCNAME" FAIL "$why"
  fi
}

a_job_is_ended_at_its_maximum_with_the_engine_and_the_issuer_stopped() {
  launch t18b qual "$MAXIMUM" 256 "" <<'EOF'
trap '' TERM
echo started > "$ONEIRON_JOB_OUT/started"
bash -c 'trap "" TERM; while :; do sleep 1; done' &
while :; do sleep 1; done
EOF
  local at; at=$(jq -r .launch_boot_ns "$C/launch.json")
  start
  wait_ended $((MAXIMUM + 120)) || { result "$FUNCNAME" FAIL "no end record by the maximum + 120 s"; return; }
  # Full precision (review r2 R2-15). The tree must be gone by the maximum; the end record is taken after the stop,
  # so up to MEASURE_NS later. The cutoff stops it at the maximum less the stop grace and kills it at the maximum,
  # 500 ms early, so it cannot be gone more than 2 s before the maximum either.
  local end ran_ns max_ns=$((MAXIMUM * 1000000000)) MEASURE_NS=1000000000
  end=$(ended .end_boot_ns); ran_ns=$((end - at))
  local ran_ms=$((ran_ns / 1000000))
  if [ ! -e "$P/out/started" ] || [ "$(ended .workload_started)" != true ]; then
    result "$FUNCNAME" FAIL "the workload never started: $(ended .refusal)"
  elif [ "$(ended .cutoff_fired)" = true ] && gone && [ "$ran_ns" -le $((max_ns + MEASURE_NS)) ] && [ "$ran_ns" -ge $((max_ns - 2000000000)) ]; then
    result "$FUNCNAME" PASS "maximum ${MAXIMUM} s: the workload started (its own mark), the cutoff fired, and the TERM-ignoring tree was empty when the end record was taken ${ran_ms} ms after the launch; no engine or issuer ran"
  else
    result "$FUNCNAME" FAIL "the end record was taken ${ran_ms} ms after the launch, maximum ${MAXIMUM} s; $(cat "$C/ended.json" | tr -d '\n')"
  fi
}

a_job_cannot_open_the_vault_store_the_keystore_or_the_control_files() {
  launch t19 qual 120 256 "" <<EOF
for path in "$VAULT/secret" "$VAULT" "$KEYSTORE/key" "$STATE/control" "$STATE/control/\$(basename "\$(dirname "\$ONEIRON_JOB_OUT")")/launch.json" "$ENGINE_HOME"; do
  if cat "\$path" > /dev/null 2>&1 || ls "\$path" > /dev/null 2>&1; then echo "OPENED \$path"; else echo "refused \$path"; fi
done > "\$ONEIRON_JOB_OUT/results"
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  if [ "$(ended .workload_started)" != true ] || [ ! -s "$P/out/results" ]; then result "$FUNCNAME" FAIL "the workload did not run: $(ended .refusal)"; return; fi
  if grep -q '^OPENED' "$P/out/results"; then
    result "$FUNCNAME" FAIL "$(grep '^OPENED' "$P/out/results" | tr '\n' ';')"
  else
    result "$FUNCNAME" PASS "$(grep -c '^refused' "$P/out/results") paths refused (vault, keystore, control files, engine home)"
  fi
}

a_job_writes_only_its_out_tmp_log_and_its_templates_write_paths() {
  launch t20 qual 120 256 "" <<EOF
p=\$(dirname "\$ONEIRON_JOB_OUT")
for path in "\$p/out/a" "\$p/tmp/a" "\$p/log/a"; do : > "\$path" 2> /dev/null && echo "ok \$path" || echo "REFUSED \$path"; done
for path in "\$p/checkout/x" "\$p/x" /tmp/x /var/tmp/x /dev/shm/x "$WORK/x" "$ENGINE_HOME/x" /etc/x; do
  : > "\$path" 2> /dev/null && echo "WROTE \$path" || echo "refused \$path"
done > "\$ONEIRON_JOB_OUT/results-outside"
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  if [ "$(ended .workload_started)" != true ]; then result "$FUNCNAME" FAIL "the workload did not run: $(ended .refusal)"; return; fi
  local own=0; [ -e "$P/out/a" ] && [ -e "$P/tmp/a" ] && [ -e "$P/log/a" ] && own=1
  if [ $own = 1 ] && ! grep -q '^WROTE' "$P/out/results-outside"; then
    result "$FUNCNAME" PASS "out, tmp and log written; $(grep -c '^refused' "$P/out/results-outside") other paths refused (the template has no write paths in this release)"
  else
    result "$FUNCNAME" FAIL "own=$own $(grep '^WROTE' "$P/out/results-outside" | tr '\n' ';')"
  fi
}

# The rate is the payload's logical bytes over the time to write and fsync them, and the bytes are
# incompressible (/dev/urandom), so the device takes as many bytes as the job wrote. Zeros measure a compressing
# filesystem instead of the cap: on mel's btrfs compress=zstd:1, 200 MiB of zeros under a 20 MiB/s cap took 0.33 s
# (609.6 MiB/s logical, 6.2 MiB on disk), random bytes 10.92 s (18.3 MiB/s, 200 MiB on disk; FIX
# QUALIFY-WRITE-RATE-ZEROS-ON-COMPRESSING-FS, R6 on mel). Uncapped, the same random write took 0.47 s there, so
# reading /dev/urandom inside the timed window lowers a capped rate by under 5 %.
a_fast_writer_is_stopped_within_its_request_plus_the_rate_times_five_seconds() {
  launch t20b qual 300 256 "" <<'EOF'
start=$(date +%s%N)
dd if=/dev/urandom of="$ONEIRON_JOB_OUT/big" bs=1M count=200 iflag=fullblock conv=fsync 2> "$ONEIRON_JOB_OUT/dd.err"
dd_rc=$?
end=$(date +%s%N)
# No measurement from a write that did not complete: the bytes can sit in the page cache while the fsync fails.
echo "$dd_rc" > "$ONEIRON_JOB_OUT/dd.rc"
[ "$dd_rc" = 0 ] || exit 0
bytes=$(stat -c %s "$ONEIRON_JOB_OUT/big" 2> /dev/null || echo 0)
echo $(( bytes * 1000000000 / (end - start) )) > "$ONEIRON_JOB_OUT/rate"
echo "$bytes" > "$ONEIRON_JOB_OUT/bytes"
EOF
  start
  wait_ended 280 || { result "$FUNCNAME" FAIL "no end record"; return; }
  local rate bytes dd_rc cap=$((20 * 1048576)) applied
  dd_rc=$(cat "$P/out/dd.rc" 2> /dev/null)
  rate=$(cat "$P/out/rate" 2> /dev/null || echo 0)
  bytes=$(cat "$P/out/bytes" 2> /dev/null || echo 0)
  applied=$(jq -r '.report.proofs.write_rate_cap.strength' "$C/scope.json")
  if [ "$dd_rc" != 0 ]; then
    result "$FUNCNAME" FAIL "the workload's write and fsync did not complete: dd exit ${dd_rc:-none}, $(head -c 200 "$P/out/dd.err" 2> /dev/null | tr '\n' ' ')"
  elif [ "$bytes" != $((200 * 1048576)) ]; then
    result "$FUNCNAME" FAIL "the workload wrote $bytes bytes of the 200 MiB of random bytes it was to write"
  elif [ "$applied" != kernel ]; then
    result "$FUNCNAME" UNPROVEN "the write-rate cap does not hold here: $(jq -r '.report.proofs.write_rate_cap.evidence' "$C/scope.json"); measured $((rate / 1048576)) MiB/s of incompressible bytes. The 5 s payload check is the engine's (server test)"
  elif [ "$rate" -gt 0 ] && [ "$rate" -le $((cap * 3 / 2)) ]; then
    result "$FUNCNAME" PASS "200 MiB of incompressible bytes written and synced at $((rate / 1048576)) MiB/s under a cap of 20 MiB/s; the 5 s payload check is the engine's (server test)"
  else
    result "$FUNCNAME" FAIL "write rate $((rate / 1048576)) MiB/s of incompressible bytes past the cap of 20 MiB/s"
  fi
}

a_job_cannot_see_the_engines_process_or_read_its_environment() {
  as_engine env ONEIRON_QUAL_SECRET=engine-env-secret sleep 600 &
  local fake=$!; sleep 1
  local engine_pid; engine_pid=$(pgrep -u "$ENGINE" -x sleep | head -1)
  launch t21 qual 120 256 "" <<EOF
{ [ -e /proc/$engine_pid ] && echo "SEEN $engine_pid" || echo "hidden $engine_pid"
  [ -e /proc/1 ] && echo "SEEN 1" || echo "hidden 1"
  grep -l engine-env-secret /proc/[0-9]*/environ 2> /dev/null | sed 's/^/READ /'
  ls /proc | grep -c '^[0-9]' | sed 's/^/visible /'; } > "\$ONEIRON_JOB_OUT/results"
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; kill $fake; return; }
  kill $fake 2> /dev/null; wait $fake 2> /dev/null
  if [ "$(ended .workload_started)" = true ] && [ -s "$P/out/results" ] && ! grep -q '^SEEN\|^READ' "$P/out/results"; then
    result "$FUNCNAME" PASS "process 1 and the engine's process hidden; no environment read; $(grep '^visible' "$P/out/results")"
  else
    result "$FUNCNAME" FAIL "$(tr '\n' ';' < "$P/out/results" 2> /dev/null) $(ended .refusal)"
  fi
}

a_job_has_no_network_unless_its_template_opens_it() {
  launch t22 qual 120 256 "" <<'EOF'
{ awk -F: 'NR > 2 { gsub(/ /, "", $1); print "iface " $1 }' /proc/net/dev
  timeout 3 bash -c 'exec 3<> /dev/tcp/1.1.1.1/53' 2> /dev/null && echo "CONNECTED" || echo "no route"; } > "$ONEIRON_JOB_OUT/results"
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  if [ "$(ended .workload_started)" = true ] && [ "$(grep -c '^iface' "$P/out/results")" = 1 ] && grep -q '^iface lo$' "$P/out/results" && ! grep -q CONNECTED "$P/out/results"; then
    result "$FUNCNAME" PASS "only lo, and no connection out (a template that opens the network needs the second unit template: not built in this release)"
  else
    result "$FUNCNAME" FAIL "$(tr '\n' ';' < "$P/out/results" 2> /dev/null) $(ended .refusal)"
  fi
}

# weaken <setting=value>: a drop-in for this one instance, as a kernel that skipped the setting would leave it.
weaken() {
  mkdir -p "/run/systemd/system/$UNIT.d"
  printf '[Service]\n%s\n' "$1" > "/run/systemd/system/$UNIT.d/50-qualification.conf"
  systemctl daemon-reload
}
unweaken() { rm -rf "/run/systemd/system/$UNIT.d"; systemctl daemon-reload; }

marker_workload() { printf 'echo started > "$ONEIRON_JOB_OUT/started"\nsleep 1\n'; }
launch_marker() { launch "$@" < <(marker_workload); }

a_unit_whose_network_or_process_hiding_did_not_apply_refuses_before_the_workload_exists() {
  local why=""
  launch_marker t22b-net qual 120 256 ""
  weaken PrivateNetwork=no; start
  wait_ended 60 || why="$why network: no end record;"
  if [ -z "$why" ]; then
    [ "$(ended .workload_started)" = false ] && [ ! -e "$P/out/started" ] && ended .refusal | grep -q network_closed || why="$why network: $(ended .refusal);"
  fi
  unweaken
  launch_marker t22b-proc qualstrict 120 256 ""
  weaken ProtectProc=default; start
  wait_ended 60 || why="$why processes: no end record;"
  if [ -z "$why" ]; then
    [ "$(ended .workload_started)" = false ] && [ ! -e "$P/out/started" ] && ended .refusal | grep -q processes_hidden || why="$why processes: $(ended .refusal);"
  fi
  unweaken
  # A drop-in that empties the system call filter would let a job take disk with no write (review r13 R13-06 of
  # #10512): the prepare step's check of the effective filter, or job-exec's own fallocate, refuses the job.
  launch_marker t22b-filter qual 120 256 ""
  weaken SystemCallFilter=; start
  wait_ended 60 || why="$why filter: no end record;"
  if [ -z "$why" ]; then
    [ "$(ended .workload_started)" = false ] && [ ! -e "$P/out/started" ] && ended .refusal | grep -qE 'SystemCallFilter|disk_allocation' \
      || why="$why filter: $(ended .refusal);"
  fi
  unweaken
  [ -z "$why" ] && result "$FUNCNAME" PASS "PrivateNetwork=no, (a template requiring it) ProtectProc=default and an emptied SystemCallFilter= each refused before the workload; no marker written" \
    || result "$FUNCNAME" FAIL "$why"
}

a_unit_started_with_another_keys_parameters_fails_in_the_prepare_step() {
  launch_marker t22c-a qual 120 256 ""
  local other_launch; other_launch=$(cat "$C/launch.json")
  launch_marker t22c-b qual 120 256 ""
  printf '%s\n' "$other_launch" | as_engine tee "$C/launch.json" > /dev/null
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  if [ "$(ended .workload_started)" = false ] && [ ! -e "$P/out/started" ] && jq -r .refusal "$C/prepared.json" | grep -q '^key_not_instance'; then
    result "$FUNCNAME" PASS "prepare refused key_not_instance; the workload never started"
  else
    result "$FUNCNAME" FAIL "$(cat "$C/ended.json" | tr -d '\n')"
  fi
}

# forge_gate_report <exchange dir> <log> <seconds>: run as the job account. Waits until the gate of the job whose
# exchange directory is <dir> listens (its socket, or, on a head that still has them, its report pipe), offers it the
# report line in <log>.line once, and writes `<socket|pipe> <pid of the process that delivered it> <exit status>` to
# <log>. The offer is bounded by 5 s; <log>.stop or the end of <seconds> ends the wait (review r7 R7-06, R7-08).
forge_gate_report() {
  local dir=$1 log=$2 end=$((SECONDS + $3)) rc
  while [ $SECONDS -lt $end ] && [ ! -e "$log.stop" ]; do
    if [ -S "$dir/gate.sock" ]; then
      timeout 5 bash -c 'echo $$ > "$1.pid"; exec socat -u "OPEN:$1.line" "UNIX-CONNECT:$2"' _ "$log" "$dir/gate.sock" 2> /dev/null
      rc=$?; echo "socket $(cat "$log.pid" 2> /dev/null) $rc" >> "$log"; return
    elif [ -p "$dir/report" ]; then
      timeout 5 bash -c 'echo $$ > "$1.pid"; exec cat "$1.line" > "$2"' _ "$log" "$dir/report" 2> /dev/null
      rc=$?; echo "pipe $(cat "$log.pid" 2> /dev/null) $rc" >> "$log"; return
    fi
    sleep 0.005
  done
}

# hold_job_exec <unit> <job uid> <log> <seconds>: root. As soon as the unit's main process has become job-exec (a
# process of the job account named oneiron in the unit's cgroup, after its exec, so the service manager starts the
# gate), stops it with STOP and writes `held <pid>` to <log>.held; `not-held` when none came within <seconds>. Once
# <log> says the other process delivered (or after <seconds>), it waits 1 s for the gate to take and refuse that
# connection, then lets job-exec go on with CONT (review r7 R7-06: the other process reaches the gate first).
hold_job_exec() {
  local unit=$1 uid=$2 log=$3 end=$((SECONDS + $4)) cgroup= p comm key value pid=
  while [ -z "$pid" ] && [ $SECONDS -lt $end ]; do
    [ -n "$cgroup" ] || cgroup=$(systemctl show -P ControlGroup "$unit" 2> /dev/null)
    [ -n "$cgroup" ] && [ -r "/sys/fs/cgroup$cgroup/cgroup.procs" ] || continue
    while read -r p; do
      comm=; read -r comm < "/proc/$p/comm" 2> /dev/null
      [ "$comm" = oneiron ] || continue
      value=; while read -r key value _; do [ "$key" = Uid: ] && break; done < "/proc/$p/status" 2> /dev/null
      [ "$value" = "$uid" ] || continue
      kill -STOP "$p" 2> /dev/null && pid=$p
      break
    done < "/sys/fs/cgroup$cgroup/cgroup.procs"
  done
  [ -n "$pid" ] || { echo not-held > "$log.held"; return; }
  echo "held $pid" > "$log.held"
  while [ $SECONDS -lt $end ] && [ ! -s "$log" ]; do sleep 0.01; done
  sleep 1
  kill -CONT "$pid" 2> /dev/null
}

# stop_helper <pid>: waits up to 10 s for a helper started with & to end, then kills it and reaps it (review r7 R7-08).
stop_helper() {
  local i
  for ((i = 0; i < 100; i++)); do kill -0 "$1" 2> /dev/null || break; sleep 0.1; done
  kill -KILL "$1" 2> /dev/null; wait "$1" 2> /dev/null
}

# FIX EXEC-UNIT-ONE-JOB-ACCOUNT: every job runs as the one job account, so another job's workload can reach a starting
# job's exchange (through /proc of a same-uid process where Landlock is missing). Here a shell of the job account on the
# machine plays that workload, with a report that refuses the job. job-exec is held with STOP from its exec until that
# shell has delivered to the gate, so the other process always comes first (review r7 R7-06). Green: the gate refused
# that very process (the journal names its pid and job-exec's), and the job started on job-exec's own report. Red: the
# gate took the other process's report (the record names its refusal). A run where job-exec was not held in time, or
# the other process never reached the gate, is run again, up to 3 runs; then UNPROVEN with why.
another_process_of_the_job_account_cannot_answer_the_gate_for_a_job() {
  local run why= verdict= log forger= holder= job_uid held held_pid via forger_pid rc said
  job_uid=$(id -u "$JOB")
  log=$(mktemp /tmp/qual-forger.XXXXXX); chmod 0666 "$log"
  trap 'touch "$log.stop"; kill $forger $holder 2> /dev/null; rm -f "$log" "$log".*; exit 130' INT TERM
  for run in 1 2 3; do
    launch_marker t21-forge qual 120 256 ""
    : > "$log"; rm -f "$log.stop" "$log.held" "$log.pid"
    jq -cn --arg i "$ID" '{instance: $i, proofs: {}, refusal: "forged_by_another_process"}' > "$log.line"
    chmod 0644 "$log.line"; touch "$log.pid"; chmod 0666 "$log.pid"
    runuser -u "$JOB" -- bash -c "$(declare -f forge_gate_report); forge_gate_report /run/oneiron-jobs/$ID $log 30" &
    forger=$!
    hold_job_exec "$UNIT" "$job_uid" "$log" 20 &
    holder=$!
    start
    wait_ended 60 || why="run $run: no end record in 60 s"
    touch "$log.stop"; stop_helper "$forger"; stop_helper "$holder"; forger= holder=
    [ -n "$why" ] && break
    held=$(head -n 1 "$log.held" 2> /dev/null); held_pid=${held#held }
    read -r via forger_pid rc < "$log" || via=
    if [ "${held%% *}" != held ]; then
      said="run $run: job-exec was not held (${held:-the holder wrote nothing})"; continue
    fi
    if [ -z "$via" ]; then
      said="run $run: the other process never reached the gate (job-exec $held_pid held too late)"; continue
    fi
    if [ "$(ended .workload_started)" != true ] || [ ! -e "$P/out/started" ] || [ "$(jq -r '.report.refusal // ""' "$C/scope.json")" != "" ]; then
      if [ "$(jq -r '.report.refusal // ""' "$C/scope.json" 2> /dev/null)" = forged_by_another_process ]; then
        verdict="FAIL run $run: the gate took the report of the other process $forger_pid (by $via, exit $rc) while job-exec $held_pid was held: the record's refusal is forged_by_another_process"
      else
        verdict="FAIL run $run: the job did not start on its own report (the other process $forger_pid by $via, exit $rc); scope $(jq -c '{released, refusal, report_refusal: .report.refusal}' "$C/scope.json" 2>&1); end $(tr -d '\n' < "$C/ended.json")"
      fi
      break
    fi
    # socat may end with a write error when the gate closed the refused connection first, so its exit status alone
    # says nothing; the gate's journal line names the process it refused.
    journalctl --sync 2> /dev/null
    if journalctl -u "$UNIT" --no-pager -o cat 2> /dev/null | grep -qF "refused a peer: process $forger_pid is not the unit's main process $held_pid"; then
      verdict="PASS run $run: job-exec $held_pid was held until the other process $forger_pid had connected (by $via); the gate refused that process by its pid and the job started on job-exec's own report"
    elif [ "$via" != socket ] || [ "$rc" != 0 ]; then
      said="run $run: the other process's offer by $via ended with exit $rc and the gate names no refusal of it"; continue
    else
      verdict="FAIL run $run: the other process $forger_pid connected while job-exec $held_pid was held, and the job started, but the journal has no refusal naming both"
    fi
    break
  done
  trap - INT TERM
  rm -f "$log" "$log".*
  if [ -n "$why" ]; then
    result "$FUNCNAME" FAIL "$why"
  elif [ -n "$verdict" ]; then
    result "$FUNCNAME" "${verdict%% *}" "${verdict#* }"
  else
    result "$FUNCNAME" UNPROVEN "3 runs without a verdict; last: $said"
  fi
}

# Review r7 R7-05: an exchange directory a binary from before the gate's socket left in /run (its report and go pipes,
# after an interrupted job and then an update in place) does not stop the next start of that instance: the prepare step
# removes the two old names with the rest and makes the exchange fresh.
a_stale_exchange_from_before_the_gate_socket_does_not_stop_the_job() {
  local stale why= group
  launch_marker t21-stale qual 120 256 ""
  stale=/run/oneiron-jobs/$ID; group=$(id -g "$JOB")
  mkdir -p "$stale" && chown "root:$group" "$stale" && chmod 0750 "$stale" && mkfifo -m 0620 "$stale/report" "$stale/go" \
    && chown "root:$group" "$stale/report" "$stale/go" || { result "$FUNCNAME" FAIL "the stale exchange could not be made"; return; }
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record in 60 s; prepared $(jq -c '{refusal}' "$C/prepared.json" 2>&1)"; return; }
  [ "$(ended .workload_started)" = true ] && [ -e "$P/out/started" ] || why="the workload did not start: prepared $(jq -c '{refusal}' "$C/prepared.json" 2>&1); end $(tr -d '\n' < "$C/ended.json")"
  [ -z "$why" ] && { [ -e "$stale/report" ] || [ -e "$stale/go" ]; } && why="an old pipe is still in the exchange"
  if [ -z "$why" ]; then
    result "$FUNCNAME" PASS "the old report and go pipes were removed with the exchange and the job started"
  else
    result "$FUNCNAME" FAIL "$why"
  fi
}

a_required_bound_the_scope_lacks_blocks_and_an_unrequired_one_is_recorded_unproven() {
  local why=""
  launch_marker t23-unrequired qual 120 256 ""
  weaken ProtectProc=default; start
  wait_ended 60 || why="$why unrequired: no end record;"
  if [ -z "$why" ]; then
    [ "$(ended .workload_started)" = true ] && [ -e "$P/out/started" ] || why="$why unrequired: did not run: $(ended .refusal);"
    [ "$(jq -r '.report.proofs.processes_hidden.strength' "$C/scope.json")" = none ] || why="$why unrequired: processes_hidden not recorded as none;"
  fi
  unweaken
  launch_marker t23-required qual 120 256 ""
  weaken PrivateNetwork=no; start
  wait_ended 60 || why="$why required: no end record;"
  if [ -z "$why" ]; then
    [ "$(ended .workload_started)" = false ] && [ ! -e "$P/out/started" ] || why="$why required: the workload started;"
  fi
  unweaken
  [ -z "$why" ] && result "$FUNCNAME" PASS "processes_hidden (not required) missing: ran, recorded none; network_closed (required) missing: refused before the workload" \
    || result "$FUNCNAME" FAIL "$why"
}

a_workload_cannot_write_or_replace_its_end_record() {
  launch t23b qual 120 256 "" <<EOF
for path in "$STATE/control/\$(basename "\$(dirname "\$ONEIRON_JOB_OUT")")/ended.json" "$STATE/control/x" /run/oneiron-jobs/x /run/oneiron-job-x /run/oneiron-payloads/x; do
  { echo '{"key":"forged"}' > "\$path"; } 2> /dev/null && echo "WROTE \$path" || echo "refused \$path"
done > "\$ONEIRON_JOB_OUT/results"
exit 7
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  local owner; owner=$(stat -c %u "$C/ended.json")
  if [ "$owner" = 0 ] && [ "$(ended .key)" = "$KEY" ] && [ "$(ended .exit_status)" = 7 ] && ! grep -q '^WROTE' "$P/out/results"; then
    result "$FUNCNAME" PASS "ended.json is root's, names the key and the exit 7; $(grep -c '^refused' "$P/out/results") writes refused"
  else
    result "$FUNCNAME" FAIL "owner=$owner $(tr '\n' ';' < "$P/out/results") $(cat "$C/ended.json" | tr -d '\n')"
  fi
}

the_unit_opens_the_leased_device_and_no_other() {
  if [ ${#DEVICES[@]} -lt 2 ]; then
    result "$FUNCNAME" UNPROVEN "no two device nodes the job account can open exist here"; return
  fi
  launch t23c qual 120 256 QUAL-DEV-0 <<EOF
{ (exec 3<> "${DEVICES[0]}") 2>&1 && echo "leased opened" || echo "LEASED REFUSED"
  (exec 3<> "${DEVICES[1]}") 2>&1 | grep -q 'Operation not permitted' && echo "other refused EPERM" || echo "OTHER NOT EPERM"; } > "\$ONEIRON_JOB_OUT/results"
EOF
  start
  wait_ended 60 || { result "$FUNCNAME" FAIL "no end record"; return; }
  if [ "$(ended .workload_started)" = true ] && grep -q '^leased opened' "$P/out/results" && grep -q '^other refused EPERM' "$P/out/results"; then
    result "$FUNCNAME" PASS "the leased node opens; the other fails with the device policy's EPERM; proof: $(jq -r '.report.proofs.device_closure.evidence' "$C/scope.json")"
  else
    result "$FUNCNAME" FAIL "$(tr '\n' ';' < "$P/out/results" 2> /dev/null) $(ended .refusal)"
  fi
}

# The unit half: an end record taken while a process of the unit lives says the cgroup is not empty, so the engine
# quarantines the device (R3a's end handling; its server test has the engine half).
a_kill_that_cannot_be_confirmed_quarantines_the_device() {
  launch t23d qual 120 256 "" <<'EOF'
while :; do sleep 1; done
EOF
  start
  local i; for ((i = 0; i < 100; i++)); do [ "$(systemctl show -P ActiveState "$UNIT")" = active ] && break; sleep 0.2; done
  SERVICE_RESULT=success EXIT_CODE=exited EXIT_STATUS=0 "$BIN" job-ended --node-file "$NODE_FILE" --engine-account "$ENGINE" "$ID"
  local empty; empty=$(ended .cgroup_empty)
  systemctl stop "$UNIT"
  if [ "$empty" = false ] && [ "$(ended .cgroup_empty)" = false ]; then
    result "$FUNCNAME" PASS "an end record taken with the workload alive says cgroup_empty false, and the stop kept that first record"
  else
    result "$FUNCNAME" FAIL "cgroup_empty=$empty"
  fi
}

# The template the log and notice cases use: a 1 MiB log cap and USR1 as its checkpoint notice. It is in the node file
# only while one of those cases runs; a build without the two fields refuses the node file then, and the case fails.
# The saved node file is put back on the case's own path and on any exit or signal of this script, and a save or a
# restore that fails fails the case (review r6 R6-05).
with_quallog_template() {
  cp -p "$NODE_FILE" "$NODE_FILE.saved" || return 1
  trap 'without_quallog_template' EXIT
  trap 'without_quallog_template; exit 130' INT TERM
  cat >> "$NODE_FILE" <<'EOF' || { without_quallog_template; return 1; }

[execution_node.templates.quallog]
repo = "/srv/git/qual.git"
entries = ["units/*.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 600
memory_gib = 2
disk_gib = 1
log_max_mib = 1
checkpoint_signal = "USR1"
EOF
}
without_quallog_template() {
  [ -e "$NODE_FILE.saved" ] || return 0
  mv "$NODE_FILE.saved" "$NODE_FILE" || return 1
  trap - EXIT INT TERM
}

# same_bytes <a> <b>: whether two byte streams (files or process substitutions) hold the same bytes, by coreutils alone.
same_bytes() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }

# The stream the log case's workload writes to stdout: 400,000 numbered lines of 14 bytes, 5,600,000 bytes.
numbered_lines() { awk 'BEGIN { for (i = 1; i <= 400000; i++) printf "line %08d\n", i }'; }

# Pass 34, 7.2 and R4's Q3-LOG-CONTRACT (02:07, with the 12:02 additions): the unit's log writer keeps log/<stream> at
# most the template's log_max_mib. Past it the file is the stream's first half-cap of bytes, then its newest bytes, and
# log/<stream>.dropped says {"at": <head bytes>, "dropped": <bytes between>}, not rotating once the writer is done.
a_log_past_its_cap_keeps_its_head_and_its_newest_tail() {
  with_quallog_template || { result "$FUNCNAME" FAIL "the quallog template was not installed"; return; }
  launch t72 quallog 120 256 "" <<'EOF'
awk 'BEGIN { for (i = 1; i <= 400000; i++) printf "line %08d\n", i }'
echo stderr-ok >&2
exit 0
EOF
  start
  wait_ended 120 || { without_quallog_template; result "$FUNCNAME" FAIL "no end record in 120 s"; return; }
  without_quallog_template || { result "$FUNCNAME" FAIL "the node file was not restored"; return; }
  local log=$P/log/stdout record=$P/log/stdout.dropped expected=/tmp/qual-t72-expected
  if [ "$(ended .workload_started)" != true ] || [ "$(ended .exit_status)" != 0 ]; then
    result "$FUNCNAME" FAIL "the workload did not run to exit 0: $(tr -d '\n' < "$C/ended.json")"; return
  fi
  if [ ! -f "$log" ] || [ ! -f "$record" ]; then
    result "$FUNCNAME" FAIL "log/stdout or its drop record is missing: $(ls -la "$P/log" 2>&1 | tr '\n' ';')"; return
  fi
  numbered_lines > "$expected"
  local at dropped len total cap=$((1 << 20)) why=
  # The record's types as R4's reader reads them, before any arithmetic: whole numbers, and rotating the JSON false
  # (review r6 R6-07).
  if ! jq -e '(.at | type == "number" and . == floor and . >= 0) and (.dropped | type == "number" and . == floor and . >= 0) and .rotating == false' "$record" > /dev/null 2>&1; then
    rm -f "$expected"
    result "$FUNCNAME" FAIL "the drop record is not {at: whole number, dropped: whole number, rotating: false}: $(head -c 200 "$record")"; return
  fi
  at=$(jq -r .at "$record"); dropped=$(jq -r .dropped "$record")
  len=$(stat -c %s "$log"); total=$(stat -c %s "$expected")
  [ "$at" = $((cap / 2)) ] || why="at $at, not half the cap $((cap / 2))"
  [ -z "$why" ] && [ "$len" -gt "$cap" ] && why="the file is $len bytes, over the cap $cap"
  [ -z "$why" ] && [ $((len + dropped)) != "$total" ] && why="file $len + dropped $dropped is not the stream's $total bytes"
  [ -z "$why" ] && ! same_bytes <(head -c "$at" "$log") <(head -c "$at" "$expected") && why="the head is not the stream's first $at bytes"
  [ -z "$why" ] && ! same_bytes <(tail -c $((len - at)) "$log") <(tail -c $((len - at)) "$expected") && why="the tail is not the stream's newest $((len - at)) bytes"
  [ -z "$why" ] && [ "$(stat -c '%U %a' "$log")" != "$JOB 644" ] && why="log/stdout is $(stat -c '%U %a' "$log"), not $JOB 644"
  [ -z "$why" ] && [ "$(cat "$P/log/stderr" 2> /dev/null)" != stderr-ok ] && why="log/stderr is not the workload's stderr: $(head -c 200 "$P/log/stderr" 2>&1)"
  [ -z "$why" ] && [ -e "$P/log/stderr.dropped" ] && why="log/stderr has a drop record under its cap"
  rm -f "$expected"
  if [ -z "$why" ]; then
    result "$FUNCNAME" PASS "1 MiB cap, $total bytes written: the file holds the first $at bytes and the newest $((len - at)), dropped $dropped; stderr kept whole"
  else
    result "$FUNCNAME" FAIL "$why"
  fi
}

# Design 7.1 Signal (R4's checkpoint notice): the engine's account asks the control socket for the template's signal;
# root sends it to the unit's main process, the workload, and nothing stops. A signal the templates may not name is
# refused, raw or through the CLI. The workload keeps a child that catches USR1 too and is ready before the notice, so a
# signal to the whole unit would show (review r6 R6-09). The handler sends a notice only to an active unit (r6 R6-06),
# so the case waits for that first.
a_checkpoint_notice_reaches_the_workload_and_stops_nothing() {
  with_quallog_template || { result "$FUNCNAME" FAIL "the quallog template was not installed"; return; }
  launch t71 quallog 120 256 "" <<'EOF'
trap 'echo notice >> "$ONEIRON_JOB_OUT/notices"' USR1
bash -c 'note() { echo child >> "$ONEIRON_JOB_OUT/child-notices"; }; trap note USR1
echo ready > "$ONEIRON_JOB_OUT/child-ready"
while [ ! -s "$ONEIRON_JOB_OUT/notices" ]; do sleep 0.1; done
sleep 0.5' &
child=$!
for ((i = 0; i < 100; i++)); do [ -e "$ONEIRON_JOB_OUT/child-ready" ] && break; sleep 0.1; done
echo started > "$ONEIRON_JOB_OUT/started"
for ((i = 0; i < 300; i++)); do [ -s "$ONEIRON_JOB_OUT/notices" ] && break; sleep 0.1; done
[ -s "$ONEIRON_JOB_OUT/notices" ] || exit 4
wait "$child" || exit 5
exit 0
EOF
  start
  local i why= reply
  for ((i = 0; i < 300; i++)); do [ -e "$P/out/started" ] && break; sleep 0.1; done
  [ -e "$P/out/started" ] || why="the workload never started"
  [ -z "$why" ] && [ -e "$P/out/child-ready" ] || why="${why:-the child of the workload was not ready}"
  for ((i = 0; i < 100; i++)); do [ "$(systemctl show -P ActiveState "$UNIT")" = active ] && break; sleep 0.1; done
  if [ -z "$why" ]; then
    as_engine "$BIN" execution-node unit-control signal "$KEY" KILL > /dev/null 2>&1 && why="the CLI sent KILL"
    # The raw request must reach the handler and come back refused for its reason (review r6 R6-08).
    reply=$(as_engine socat -t 5 - UNIX-CONNECT:/run/oneiron-job-control.sock <<< "signal $ID TERM" 2>&1)
    [ -z "$why" ] && [ "$reply" != "refused signal_not_a_checkpoint_signal" ] && why="the socket's answer to TERM: ${reply:-none}"
    sleep 0.5
    [ -z "$why" ] && [ "$(systemctl show -P ActiveState "$UNIT")" != active ] && why="the unit stopped after a refused signal"
    [ -z "$why" ] && ! as_engine "$BIN" execution-node unit-control signal "$KEY" USR1 && why="the notice was not taken"
  fi
  wait_ended 60 || { without_quallog_template; result "$FUNCNAME" FAIL "${why:-no end record in 60 s}"; return; }
  without_quallog_template || why="${why:-the node file was not restored}"
  [ -z "$why" ] && [ -e "$P/out/child-notices" ] && why="the workload's child got the notice: the signal reached more than the main process"
  if [ -z "$why" ] && [ "$(cat "$P/out/notices" 2> /dev/null)" = notice ] && [ "$(ended .exit_status)" = 0 ] && [ "$(ended .workload_started)" = true ] && gone; then
    result "$FUNCNAME" PASS "KILL refused by the CLI and TERM by the socket (refused signal_not_a_checkpoint_signal) with the unit still active; USR1 reached the main process once and not its ready child; exit 0"
  else
    result "$FUNCNAME" FAIL "${why:-notices=$(cat "$P/out/notices" 2>&1 | tr '\n' ' ')} $(tr -d '\n' < "$C/ended.json")"
  fi
}

# FIX EXEC-NODE-DISK-CHECK-UNBUILT (design 7.9): the engine's disk check asks root for a running job's payload size
# through the control socket's `usage` verb, since a job runs as the job account and may make a directory the
# engine's account cannot list. Here the job writes 3 MiB into a 0700 directory of its own and 2 MiB into a file it holds open
# with its name removed (review r12 R12-01: no walk of names sees it), and root's answer, taken before anything else
# is written, counts both (r13 R13-12: the held 2 MiB alone lifts it past 5 MiB). A 4 MiB bound, past the named part
# alone, answers `past` from the held file (r14 R14-11), and an account that is not the engine's is not answered. Only
# then, on root's word, does the job ask `fallocate` for 64 MiB, and it is refused (R12-04: the plain way to take disk
# with no write); a job's fallocate that took its 64 MiB FAILs, and its refusal is evidence only where the payload's
# file system takes fallocate outside the unit, so on one that does not it is UNPROVEN (R13-12). A file held only by a
# mapping is not exercised: bash maps no file. Red (a binary from before the verb): the CLI refuses `usage`, and the
# fallocate takes its 64 MiB.
the_engine_learns_the_size_of_a_payload_with_a_private_directory_through_root() {
  launch t75 qual 120 256 "" <<'EOF'
mkdir -m 0700 "$ONEIRON_JOB_OUT/private"
head -c 3145728 /dev/urandom > "$ONEIRON_JOB_OUT/private/blob"
exec 3> "$ONEIRON_JOB_OUT/held"
rm "$ONEIRON_JOB_OUT/held"
head -c 2097152 /dev/urandom >&3
sync
echo written > "$ONEIRON_JOB_OUT/written"
for ((i = 0; i < 600; i++)); do [ -e "$ONEIRON_JOB_OUT/measured" ] && break; sleep 0.1; done
if [ -e "$ONEIRON_JOB_OUT/measured" ]; then
  fallocate -l 67108864 "$ONEIRON_JOB_OUT/prealloc" 2> "$ONEIRON_JOB_OUT/fallocate.err"
  echo $? > "$ONEIRON_JOB_OUT/fallocate.rc"
else
  echo no-word > "$ONEIRON_JOB_OUT/fallocate.rc"
fi
sleep 60
EOF
  start
  local i why= whole= past= other= listed=no native=no refused=no job_rc=
  for ((i = 0; i < 300; i++)); do [ -e "$P/out/written" ] && break; sleep 0.1; done
  [ -e "$P/out/written" ] || why="the workload never wrote its payload"
  if [ -z "$why" ]; then
    as_engine ls "$P/out/private" > /dev/null 2>&1 && listed=yes
    whole=$(as_engine "$BIN" execution-node unit-control usage "$KEY" 18446744073709551615 2>&1)
    past=$(as_engine "$BIN" execution-node unit-control usage "$KEY" 4194304 2>&1)
    other=$(runuser -u "$JOB" -- "$BIN" execution-node unit-control usage "$KEY" 1048576 2>&1) \
      && why="an account that is not the engine's was answered: $other"
    touch "$P/out/measured"
    for ((i = 0; i < 300; i++)); do [ -s "$P/out/fallocate.rc" ] && break; sleep 0.1; done
    # Whether the payload's file system takes fallocate at all, outside the unit's filter.
    fallocate -l 1048576 "$P/tmp/.native-fallocate" 2> /dev/null && native=yes
    rm -f "$P/tmp/.native-fallocate"
  fi
  as_engine "$BIN" execution-node unit-control stop "$KEY" > /dev/null 2>&1
  wait_ended 60 || why="${why:-no end record in 60 s after the stop}"
  [ -z "$why" ] && [ "$listed" = yes ] && why="the engine's account could list the job's 0700 directory, so the case proves nothing"
  if [ -z "$why" ] && ! { [[ "$whole" =~ ^bytes\ [0-9]+$ ]] && [ "${whole#bytes }" -ge 5242880 ]; }; then
    why="root's answer for the whole payload (3 MiB named, 2 MiB held with no name): ${whole:-none}"
  fi
  if [ -z "$why" ] && [ "${whole#bytes }" -ge 67108864 ]; then
    why="root's answer, taken before the fallocate, holds 64 MiB: ${whole}"
  fi
  if [ -z "$why" ] && ! { [[ "$past" =~ ^past\ [0-9]+$ ]] && [ "${past#past }" -gt 4194304 ]; }; then
    why="root's answer under a 4 MiB bound (past the 3 MiB named only with the held file): ${past:-none}"
  fi
  job_rc=$(cat "$P/out/fallocate.rc" 2> /dev/null)
  if [ -z "$why" ] && [ "$job_rc" = no-word ]; then
    why="the workload had no word in 60 s that root measured, so it asked no fallocate"
  elif [ -z "$why" ] && [ -z "$job_rc" ]; then
    why="the workload recorded no fallocate result"
  elif [ -z "$why" ] && [ "$job_rc" = 0 ]; then
    why="the job's fallocate took its 64 MiB"
  fi
  grep -qi 'not supported' "$P/out/fallocate.err" 2> /dev/null && refused=yes
  if [ -z "$why" ] && [ "$native" = yes ] && [ "$refused" = no ]; then
    why="the job's fallocate failed for another reason than the filter's: rc $job_rc, $(tr '\n' ' ' < "$P/out/fallocate.err" 2>&1)"
  fi
  local measured="the engine's account cannot list the job's 0700 directory; root answered '$whole' (3 MiB there and 2 MiB held with no name, before the fallocate) and '$past' under a 4 MiB bound; a job's uid was refused"
  if [ -n "$why" ]; then
    result "$FUNCNAME" FAIL "$why"
  elif [ "$native" = yes ]; then
    result "$FUNCNAME" PASS "$measured; the job's 64 MiB fallocate was refused ($(head -c 80 "$P/out/fallocate.err")) on a file system that takes it outside the unit"
  else
    result "$FUNCNAME" UNPROVEN "$measured; the payload's file system takes no fallocate outside the unit either, so the filter's refusal is not shown here"
  fi
}

setup
echo "## SETUP host=$(uname -r) systemd=$(systemctl --version | head -1) landlock-abi=$(cat /sys/kernel/security/landlock/abi_version 2> /dev/null || echo ?) cgroup=$(cut -d: -f3 /proc/self/cgroup) root-subtree=[$(cat /sys/fs/cgroup/cgroup.subtree_control 2> /dev/null)]"
wanted a_machine_without_the_minimum_contract_offers_no_jobs && BEFORE_INSTALL=1
if [ -n "${BEFORE_INSTALL:-}" ]; then
  before=$("$BIN" execution-node check --file "$NODE_FILE" 2>&1)
fi
do_install || { echo "## QUALIFY rc=1 why=install-failed"; exit 1; }
pick_devices
if [ -n "${BEFORE_INSTALL:-}" ]; then
  after=$("$BIN" execution-node check --file "$NODE_FILE" 2>&1)
  echo "$after" | sed 's/^/## CHECK /'
  if grep -q 'minimum contract' <<<"$before" && ! grep -q 'minimum contract' <<<"$after" && grep -q '^scope tree_kill: Kernel' <<<"$after"; then
    result a_machine_without_the_minimum_contract_offers_no_jobs PASS "before install: refused (minimum contract); after install and the probe unit: $(grep -c ': Kernel' <<<"$after") bounds Kernel"
  else
    result a_machine_without_the_minimum_contract_offers_no_jobs FAIL "before: $(grep -c 'minimum contract' <<<"$before") refusal line(s); after: $(grep '^scope' <<<"$after" | tr '\n' ';')"
  fi
fi
# FIX EXEC-NODE-PROBE-TEST-GAPS: device-query cases, sourced after install.
. "$(dirname "$0")/qualify_device_query.sh"
for test in \
  the_engines_account_starts_only_job_units_and_only_through_the_control_socket \
  a_child_that_left_its_session_dies_when_the_leader_exits \
  a_job_over_its_memory_request_ends_as_memory_limit \
  a_workload_that_ends_at_once_is_recorded_as_started \
  a_job_cannot_open_the_vault_store_the_keystore_or_the_control_files \
  a_job_writes_only_its_out_tmp_log_and_its_templates_write_paths \
  a_fast_writer_is_stopped_within_its_request_plus_the_rate_times_five_seconds \
  a_job_cannot_see_the_engines_process_or_read_its_environment \
  a_job_has_no_network_unless_its_template_opens_it \
  a_unit_whose_network_or_process_hiding_did_not_apply_refuses_before_the_workload_exists \
  a_unit_started_with_another_keys_parameters_fails_in_the_prepare_step \
  another_process_of_the_job_account_cannot_answer_the_gate_for_a_job \
  a_stale_exchange_from_before_the_gate_socket_does_not_stop_the_job \
  a_required_bound_the_scope_lacks_blocks_and_an_unrequired_one_is_recorded_unproven \
  a_workload_cannot_write_or_replace_its_end_record \
  the_unit_opens_the_leased_device_and_no_other \
  "${DEVICE_QUERY_CASES[@]}" \
  a_kill_that_cannot_be_confirmed_quarantines_the_device \
  a_log_past_its_cap_keeps_its_head_and_its_newest_tail \
  a_checkpoint_notice_reaches_the_workload_and_stops_nothing \
  the_engine_learns_the_size_of_a_payload_with_a_private_directory_through_root \
  a_job_is_ended_at_its_maximum_with_the_engine_and_the_issuer_stopped; do
  wanted "$test" && "$test"
done
rc=0; [ $FAIL -gt 0 ] && rc=1
echo "## QUALIFY rc=$rc pass=$PASS fail=$FAIL unproven=$UNPROVEN"
exit $rc
