#!/usr/bin/env bash
# T41 of pass 33 (33-exec-node/DESIGN.md sections 11 and 12, "R6 in five steps", step 3; pass 34 9.2: T18b at the
# attempt's own maximum, first case 1,800 s): a harmless job is ended at its maximum with the engine and the issuer
# stopped, and the card is clean. Run as root at the node, twice around one job of harmless_workload.sh:
#   --phase armed  while the job runs, before the operator stops the issuer's engine and restarts this node's engine:
#                  the unit is active; both workload processes live in it; the child left the leader's session; with
#                  --hold-device the child holds a compute context on the card. Writes the record `after` reads.
#   --phase after  once the maximum has passed: the unit is inactive, its control group gone, and it never started
#                  again; no recorded process lives; no process sits in the unit's group; the end record names this
#                  key and boot and says the cutoff fired, the workload had started and the group was empty, at the
#                  maximum and not before it; the last heartbeat is inside the maximum; this node's engine was
#                  restarted meanwhile; nothing holds the card's files, no context lives on it, and it answers a probe.
# The issuer's half (its engine stopped during the run; one Find answers one end record) is read on the issuer
# (R6-RUNBOOK.md step 3).
#
# usage: check_cutoff_on_card.sh --phase armed|after --key <job key> --device <GPU-uuid> --record <file>
#          [--node-file <file>] [--engine-unit <unit> [--engine-user <account>]] [--oneiron <binary>]
#          [--grace-secs <n>] [--stop-grace-secs <n>] [--hold-device] [--allow-holder <command name>]...
#          [--unit <unit name> --id <key id>]
#   --node-file     the node's [execution_node] file (default /etc/oneiron/execution-node.toml): state_dir, work_dir
#   --engine-unit   the node engine's systemd unit (default oneiron.service; with --engine-user, that account's user unit)
#   --grace-secs    how long after the maximum the end may come (default 30)
#   --stop-grace-secs  the node file's stop_grace_secs (default 10): the cutoff fires that long before the maximum
#   --unit, --id    the job unit and key id, in place of `oneiron execution-node unit-name <key>` (fixtures)
# Prints `## EVIDENCE` and `## CHECK <name> PASS|FAIL <why>` lines, then one `## TEST <name> PASS|FAIL <why>`.
# Exit 0 on PASS, 1 on FAIL, 64 on a usage error, 75 when `after` runs before the maximum has passed (run it again
# later), 77 when it cannot run here (not root, no systemd, no jq, no NVIDIA driver, no such card or job).
# Fixtures set NVIDIA_PROC, NVIDIA_DEV and a stand-in nvidia-smi as card.sh says.
set -u
PHASE=; KEY=; DEVICE=; RECORD=; NODE_FILE=/etc/oneiron/execution-node.toml; ENGINE_UNIT=oneiron.service; ENGINE_USER=
ONEIRON=oneiron; GRACE=30; STOP_GRACE=10; HOLD=no; ALLOW=(); UNIT=; ID=
while [ $# -gt 0 ]; do
  case $1 in
    --phase) PHASE=$2; shift 2;;
    --key) KEY=$2; shift 2;;
    --device) DEVICE=$2; shift 2;;
    --record) RECORD=$2; shift 2;;
    --node-file) NODE_FILE=$2; shift 2;;
    --engine-unit) ENGINE_UNIT=$2; shift 2;;
    --engine-user) ENGINE_USER=$2; shift 2;;
    --oneiron) ONEIRON=$2; shift 2;;
    --grace-secs) GRACE=$2; shift 2;;
    --stop-grace-secs) STOP_GRACE=$2; shift 2;;
    --hold-device) HOLD=yes; shift;;
    --allow-holder) ALLOW+=("$2"); shift 2;;
    --unit) UNIT=$2; shift 2;;
    --id) ID=$2; shift 2;;
    *) echo "unknown argument $1" >&2; exit 64;;
  esac
done
case $PHASE in armed|after) ;; *) echo "--phase armed|after" >&2; exit 64;; esac
[ -n "$KEY" ] && [ -n "$DEVICE" ] && [ -n "$RECORD" ] || { echo "--key, --device and --record are required" >&2; exit 64; }
TEST=a_harmless_job_is_ended_at_1800_s_with_the_engine_and_the_issuer_stopped_and_the_card_is_clean
. "$(dirname "$0")/card.sh"

unproven() { echo "## TEST $TEST UNPROVEN $1"; exit 77; }
[ "$(id -u)" = 0 ] || unproven "not-root"
[ "$(cat /proc/1/comm 2> /dev/null)" = systemd ] || unproven "process-1-is-not-systemd"
command -v jq > /dev/null || unproven "no-jq"
command -v nvidia-smi > /dev/null || unproven "no-nvidia-smi"
card_resolve "$DEVICE" || unproven "no-card-$DEVICE"

toml_path() { sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "$NODE_FILE" 2> /dev/null | head -1; }
STATE=$(toml_path state_dir); WORK=$(toml_path work_dir)
[ -n "$STATE" ] && [ -n "$WORK" ] || unproven "no-state_dir-or-work_dir-in-$NODE_FILE"
if [ -z "$UNIT" ]; then
  UNIT=$("$ONEIRON" execution-node unit-name "$KEY" 2> /dev/null) || unproven "no-unit-name (needs R3b's oneiron)"
  ID=${UNIT#oneiron-job@}; ID=${ID%.service}
fi
[ -n "$ID" ] || { echo "--id goes with --unit" >&2; exit 64; }
CONTROL=$STATE/control/$ID; OUT=$WORK/$ID/out

FAILED=()
check() { echo "## CHECK $1 $2 $3"; [ "$2" = PASS ] || FAILED+=("$1"); }
finish() {
  if [ ${#FAILED[@]} -eq 0 ]; then echo "## TEST $TEST PASS phase=$PHASE $1"; exit 0; fi
  echo "## TEST $TEST FAIL phase=$PHASE failed=[${FAILED[*]}] $1"; exit 1
}
unit_prop() { systemctl show "$UNIT" -p "$1" --value 2> /dev/null; }
engine_prop() {
  if [ -n "$ENGINE_USER" ]; then systemctl --user -M "$ENGINE_USER@" show "$ENGINE_UNIT" -p "$1" --value 2> /dev/null
  else systemctl show "$ENGINE_UNIT" -p "$1" --value 2> /dev/null; fi
}
# The boot clock in nanoseconds, from /proc/uptime (10 ms steps), as qualify_systemd_scope.sh reads it.
boot_ns() { local up; read -r up _ < /proc/uptime; echo $(( ${up%.*} * 1000000000 + 10#${up#*.} * 10000000 )); }
start_of() { local stat; stat=$(cat "/proc/$1/stat" 2> /dev/null) || return 1; stat=${stat##*) }; set -- $stat; echo "${20}"; }
# The processes whose control group is the unit's.
in_unit() { grep -lsF "/$UNIT" /proc/[0-9]*/cgroup | cut -d/ -f3 | sort -n | tr '\n' ' '; }
rec() { awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$RECORD"; }

echo "## EVIDENCE at=$(date -u +%FT%TZ) boot_id=$(cat /proc/sys/kernel/random/boot_id) unit=$UNIT control=$CONTROL card=$DEVICE minor=$CARD_MINOR"

if [ "$PHASE" = armed ]; then
  [ -f "$CONTROL/launch.json" ] || unproven "no-launch.json-in-$CONTROL"
  launch_ns=$(jq -r '.launch_boot_ns' "$CONTROL/launch.json"); maximum=$(jq -r '.maximum_secs' "$CONTROL/launch.json")
  state=$(unit_prop ActiveState)
  [ "$state" = active ] && check unit-active PASS "$state" || check unit-active FAIL "ActiveState=$state"
  leader=$(awk '$1 == "leader"' "$OUT/pids" 2> /dev/null | tail -1); child=$(awk '$1 == "child"' "$OUT/pids" 2> /dev/null | tail -1)
  field() { sed -nE "s/.* $1=([^ ]+).*/\1/p" <<< "$2"; }
  lp=$(field pid "$leader"); ls_=$(field start "$leader"); lsid=$(field sid "$leader")
  cp=$(field pid "$child"); cs=$(field start "$child"); csid=$(field sid "$child")
  members=" $(in_unit)"
  for role in leader child; do
    p=$lp; s=$ls_; [ $role = child ] && { p=$cp; s=$cs; }
    if [ -z "$p" ]; then check "$role-alive" FAIL "no $role line in $OUT/pids"
    elif [ "$(start_of "$p")" != "$s" ]; then check "$role-alive" FAIL "pid $p is gone or another process"
    elif [[ $members != *" $p "* ]]; then check "$role-alive" FAIL "pid $p lives outside $UNIT"
    else check "$role-alive" PASS "pid $p start $s in $UNIT"; fi
  done
  [ -n "$csid" ] && [ "$csid" != "$lsid" ] && check child-left-session PASS "leader sid $lsid, child sid $csid" \
    || check child-left-session FAIL "leader sid $lsid, child sid ${csid:-none}"
  if [ $HOLD = yes ]; then
    contexts=$(card_contexts "$DEVICE")
    if awk -F', *' -v p="$cp" '$2 == p { found = 1 } END { exit !found }' <<< "$contexts"; then check child-holds-card PASS "context of pid $cp"
    else check child-holds-card FAIL "no context of pid $cp: [$(tr '\n' ';' <<< "$contexts")] $(cat "$OUT/device" 2> /dev/null)"; fi
  fi
  engine=$(engine_prop InvocationID)
  [ -n "$engine" ] && check engine-known PASS "$ENGINE_UNIT invocation $engine" || check engine-known FAIL "no invocation of $ENGINE_UNIT"
  { echo "unit=$UNIT"; echo "id=$ID"; echo "invocation=$(unit_prop InvocationID)"; echo "cgroup=$(unit_prop ControlGroup)"
    echo "leader_pid=$lp"; echo "leader_start=$ls_"; echo "child_pid=$cp"; echo "child_start=$cs"
    echo "engine_invocation=$engine"; echo "launch_boot_ns=$launch_ns"; echo "maximum_secs=$maximum"
    echo "armed_unix=$(date +%s)"; echo "armed_boot_ns=$(boot_ns)"; } > "$RECORD"
  finish "record=$RECORD maximum=${maximum}s"
fi

# after
[ -f "$RECORD" ] || unproven "no-record-$RECORD (run --phase armed first)"
launch_ns=$(rec launch_boot_ns); maximum=$(rec maximum_secs)
deadline_ns=$(( launch_ns + maximum * 1000000000 ))
now_ns=$(boot_ns)
if [ "$now_ns" -lt "$deadline_ns" ]; then
  echo "## TEST $TEST WAIT the maximum passes in $(( (deadline_ns - now_ns) / 1000000000 + 1 )) s"; exit 75
fi
state=$(unit_prop ActiveState); invocation=$(unit_prop InvocationID)
case $state in inactive|failed) check unit-ended PASS "ActiveState=$state";; *) check unit-ended FAIL "ActiveState=$state";; esac
[ "$invocation" = "$(rec invocation)" ] && check one-start PASS "invocation $invocation" \
  || check one-start FAIL "invocation $(rec invocation) at arming, $invocation now: the unit started again"
cg=/sys/fs/cgroup$(rec cgroup)
if [ ! -d "$cg" ] || [ -z "$(cat "$cg/cgroup.procs" 2> /dev/null)" ]; then check cgroup-gone PASS "$cg"
else check cgroup-gone FAIL "$cg holds $(tr '\n' ' ' < "$cg/cgroup.procs")"; fi
members=$(in_unit)
[ -z "$members" ] && check no-process-in-unit PASS "none" || check no-process-in-unit FAIL "pids $members"
for role in leader child; do
  p=$(rec ${role}_pid); s=$(rec ${role}_start)
  if [ -n "$p" ] && [ "$(start_of "$p")" = "$s" ]; then check "$role-gone" FAIL "pid $p (start $s) still lives"
  else check "$role-gone" PASS "pid ${p:-none}"; fi
done
end=$CONTROL/ended.json
if [ ! -f "$end" ]; then check end-record FAIL "no $end"
else
  echo "## EVIDENCE ended.json $(jq -c . "$end")"
  why=$(jq -r --arg key "$KEY" --arg boot "$(cat /proc/sys/kernel/random/boot_id)" '[
      (if .key != $key then "key \(.key)" else empty end),
      (if .boot_id != $boot then "boot \(.boot_id)" else empty end),
      (if .cutoff_fired != true then "cutoff_fired \(.cutoff_fired)" else empty end),
      (if .workload_started != true then "workload_started \(.workload_started)" else empty end),
      (if .cgroup_empty != true then "cgroup_empty \(.cgroup_empty)" else empty end)] | join(", ")' "$end")
  end_ns=$(jq -r '.end_boot_ns' "$end")
  earliest=$(( deadline_ns - (STOP_GRACE + 5) * 1000000000 )); latest=$(( deadline_ns + GRACE * 1000000000 ))
  ran=$(( (end_ns - launch_ns) / 1000000 ))
  if [ -n "$why" ]; then check end-record FAIL "$why"
  elif [ "$end_ns" -lt "$earliest" ]; then check end-record FAIL "ended ${ran} ms after the launch: before the maximum of ${maximum} s"
  elif [ "$end_ns" -gt "$latest" ]; then check end-record FAIL "ended ${ran} ms after the launch: past the maximum plus ${GRACE} s"
  else check end-record PASS "cutoff fired; workload started; group empty; ended ${ran} ms after the launch (maximum ${maximum} s)"; fi
fi
[ -f "$CONTROL/cutoff.json" ] && check cutoff-mark PASS "$(jq -c . "$CONTROL/cutoff.json")" || check cutoff-mark FAIL "no $CONTROL/cutoff.json"
# The last heartbeat, against the maximum on the wall clock: the arming read both clocks at one moment.
deadline_unix=$(( $(rec armed_unix) + (deadline_ns - $(rec armed_boot_ns)) / 1000000000 ))
last=$(awk '{ print $3 }' "$OUT/heartbeat" 2> /dev/null | sort -n | tail -1)
if [ -z "$last" ]; then check last-heartbeat FAIL "no heartbeat in $OUT"
elif [ "$last" -gt $(( deadline_unix + 1 )) ]; then check last-heartbeat FAIL "a heartbeat at $last, after the maximum at $deadline_unix"
else check last-heartbeat PASS "last at $last, $(( deadline_unix - last )) s before the maximum"; fi
engine=$(engine_prop InvocationID); engine_state=$(engine_prop ActiveState)
if [ "$engine" = "$(rec engine_invocation)" ]; then check engine-restarted FAIL "$ENGINE_UNIT has the invocation it had at arming"
else check engine-restarted PASS "$ENGINE_UNIT invocation $(rec engine_invocation) -> ${engine:-none} ($engine_state)"; fi
holders=$(card_holders "${ALLOW[@]}" | awk '$5 == "not-allowed" { print $1 ":" $2 }' | tr '\n' ' ')
[ -z "$holders" ] && check card-files-free PASS "no holder but [${ALLOW[*]}]" || check card-files-free FAIL "held by $holders"
contexts=$(card_contexts "$DEVICE")
[ -z "$contexts" ] && check card-no-context PASS "none" || check card-no-context FAIL "$(tr '\n' ';' <<< "$contexts")"
if probe=$(card_probe "$DEVICE"); then check card-probe PASS "$probe"; else check card-probe FAIL "$probe"; fi
finish "maximum=${maximum}s key=$KEY"
