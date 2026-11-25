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
command -v jq >/dev/null || { echo "## QUALIFY rc=77 why=no-jq"; exit 77; }

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

a_fast_writer_is_stopped_within_its_request_plus_the_rate_times_five_seconds() {
  launch t20b qual 300 256 "" <<'EOF'
start=$(date +%s%N)
dd if=/dev/zero of="$ONEIRON_JOB_OUT/big" bs=1M count=200 conv=fsync 2> /dev/null
end=$(date +%s%N)
echo $(( 200 * 1048576 * 1000000000 / (end - start) )) > "$ONEIRON_JOB_OUT/rate"
EOF
  start
  wait_ended 280 || { result "$FUNCNAME" FAIL "no end record"; return; }
  local rate cap=$((20 * 1048576)) applied
  rate=$(cat "$P/out/rate" 2> /dev/null || echo 0)
  applied=$(jq -r '.report.proofs.write_rate_cap.strength' "$C/scope.json")
  if [ "$applied" != kernel ]; then
    result "$FUNCNAME" UNPROVEN "the write-rate cap does not hold here: $(jq -r '.report.proofs.write_rate_cap.evidence' "$C/scope.json"); measured $((rate / 1048576)) MiB/s. The 5 s payload check is the engine's (server test)"
  elif [ "$rate" -gt 0 ] && [ "$rate" -le $((cap * 3 / 2)) ]; then
    result "$FUNCNAME" PASS "write rate $((rate / 1048576)) MiB/s under a cap of 20 MiB/s, so request + rate x 5 s bounds the overrun; the 5 s payload check is the engine's (server test)"
  else
    result "$FUNCNAME" FAIL "write rate $((rate / 1048576)) MiB/s past the cap of 20 MiB/s"
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
  [ -z "$why" ] && result "$FUNCNAME" PASS "PrivateNetwork=no and (a template requiring it) ProtectProc=default each refused before the workload; no marker written" \
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

# forge_gate_report <exchange dir> <report line> <log> <seconds>: run as the job account. Until <log>.stop exists or
# the time is up, it offers <report line> to the gate of the job whose exchange directory is <dir>: through the gate's
# socket, or, on a head that still has them, through the report pipe. Each delivery that went through adds a line.
forge_gate_report() {
  local dir=$1 line=$2 log=$3 end=$((SECONDS + $4))
  while [ $SECONDS -lt $end ] && [ ! -e "$log.stop" ]; do
    if [ -S "$dir/gate.sock" ]; then
      printf '%s\n' "$line" | socat -u - "UNIX-CONNECT:$dir/gate.sock" 2> /dev/null && echo socket >> "$log"
    elif [ -p "$dir/report" ]; then
      timeout 2 bash -c 'printf "%s\n" "$1" > "$2"' _ "$line" "$dir/report" 2> /dev/null && echo pipe >> "$log"
    else
      sleep 0.005
    fi
  done
}

# FIX EXEC-UNIT-ONE-JOB-ACCOUNT: every job runs as the one job account, so another job's workload can reach a starting
# job's exchange (through /proc of a same-uid process where Landlock is missing). Here a shell of the job account on the
# machine plays that workload: from before the start it offers the gate a report that refuses the job. The job must
# start on job-exec's own report, and the gate must have refused the other process. Up to 3 runs, until one shows the
# gate refusing it; none: UNPROVEN (job-exec reached the gate first each time).
another_process_of_the_job_account_cannot_answer_the_gate_for_a_job() {
  local run why= refused=0 log forger line
  log=$(mktemp /tmp/qual-forger.XXXXXX); chmod 0666 "$log"
  for run in 1 2 3; do
    launch_marker t21-forge qual 120 256 ""
    line=$(jq -cn --arg i "$ID" '{instance: $i, proofs: {}, refusal: "forged_by_another_process"}')
    : > "$log"; rm -f "$log.stop"
    runuser -u "$JOB" -- bash -c "$(declare -f forge_gate_report); forge_gate_report /run/oneiron-jobs/$ID '$line' $log 60" &
    forger=$!
    sleep 0.3
    start
    wait_ended 60 || why="run $run: no end record in 60 s"
    touch "$log.stop"; wait "$forger" 2> /dev/null
    [ -n "$why" ] && break
    if [ "$(ended .workload_started)" != true ] || [ ! -e "$P/out/started" ] || [ "$(jq -r '.report.refusal // ""' "$C/scope.json")" != "" ]; then
      why="run $run: the job did not start on its own report (deliveries: $(sort "$log" | uniq -c | tr -s ' \n' ' ')); scope $(jq -c '{released, refusal, report_refusal: .report.refusal}' "$C/scope.json" 2>&1); end $(tr -d '\n' < "$C/ended.json")"
      break
    fi
    journalctl --sync 2> /dev/null
    refused=$(journalctl -u "$UNIT" --no-pager -o cat 2> /dev/null | grep -c 'refused a peer')
    [ "$refused" -gt 0 ] && break
  done
  rm -f "$log" "$log.stop"
  if [ -n "$why" ]; then
    result "$FUNCNAME" FAIL "$why"
  elif [ "$refused" -gt 0 ]; then
    result "$FUNCNAME" PASS "run $run: the gate refused $refused connection(s) of another process of the job account; the job started on job-exec's own report"
  else
    result "$FUNCNAME" UNPROVEN "in 3 runs the other process never reached the gate before job-exec"
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
  [ -z "$why" ] && ! cmp -s <(head -c "$at" "$log") <(head -c "$at" "$expected") && why="the head is not the stream's first $at bytes"
  [ -z "$why" ] && ! cmp -s <(tail -c $((len - at)) "$log") <(tail -c $((len - at)) "$expected") && why="the tail is not the stream's newest $((len - at)) bytes"
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
  a_required_bound_the_scope_lacks_blocks_and_an_unrequired_one_is_recorded_unproven \
  a_workload_cannot_write_or_replace_its_end_record \
  the_unit_opens_the_leased_device_and_no_other \
  a_kill_that_cannot_be_confirmed_quarantines_the_device \
  a_log_past_its_cap_keeps_its_head_and_its_newest_tail \
  a_checkpoint_notice_reaches_the_workload_and_stops_nothing \
  a_job_is_ended_at_its_maximum_with_the_engine_and_the_issuer_stopped; do
  wanted "$test" && "$test"
done
rc=0; [ $FAIL -gt 0 ] && rc=1
echo "## QUALIFY rc=$rc pass=$PASS fail=$FAIL unproven=$UNPROVEN"
exit $rc
