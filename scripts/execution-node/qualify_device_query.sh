# FIX EXEC-NODE-PROBE-TEST-GAPS: qualify device queries through the installed job control socket.
# Sourced by qualify_systemd_scope.sh after install. Needs root and systemd as PID 1 on a scratch machine.

DEVICE_QUERY_CASES=(
  the_engines_device_query_is_served_by_a_per_connection_handler_past_its_peer_check
  a_device_query_left_running_holds_the_lock_across_handler_instances
  a_device_query_past_its_deadline_is_refused_and_the_next_instance_is_served
)
DEVICE_QUERY_SOCKET=/run/oneiron-job-control.sock
DEVICE_QUERY_LOCK_DIR=/var/lib/oneiron-job-control
DEVICE_QUERY_TOOL=/usr/bin/nvidia-smi
DEVICE_QUERY_CARD='GPU-cb30cb3d-5547-c5ae-4990-85433256f138, NVIDIA GeForce RTX 4090, 24564'
DEVICE_QUERY_NVML_REFUSAL='Failed to initialize NVML: Insufficient Permissions'

# The fixture keeps a PID only for the escaping and slow stand-ins.
device_query_pid() {
  local pid
  read -r pid < "$fixture/pid" || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" != 1 ]] || return 1
  printf '%s\n' "$pid"
}

device_query_pid_gone() {
  local pid="$1" i
  for ((i = 0; i < 100; i++)); do
    [ ! -e "/proc/$pid" ] && return 0
    sleep 0.1
  done
  [ ! -e "/proc/$pid" ]
}

device_query_cleanup() {
  local rc="$1" failed=0 pid
  if [ "$pid_checked_gone" = 0 ] && [ -n "$fixture" ] && [ -s "$fixture/pid" ]; then
    if pid=$(device_query_pid) && [ -e "/proc/$pid" ]; then
      kill -KILL "$pid" 2>/dev/null || :
      device_query_pid_gone "$pid" || failed=1
    fi
  fi
  if [ -n "$tool_dir" ]; then
    if [ -e "$tool_dir/original" ] || [ -L "$tool_dir/original" ]; then
      if ! mv -fT -- "$tool_dir/original" "$DEVICE_QUERY_TOOL"; then
        printf 'could not restore %s (original is at %s/original)\n' "$DEVICE_QUERY_TOOL" "$tool_dir"
        tool_dir=""
        failed=1
      fi
    elif [ "$tool_was_absent" = 1 ]; then
      rm -f -- "$DEVICE_QUERY_TOOL" || failed=1
    fi
    [ -z "$tool_dir" ] || rm -rf -- "$tool_dir" || failed=1
  fi
  [ -z "$peer_created" ] || userdel "$peer_created" || failed=1
  [ -z "$fixture" ] || rm -rf -- "$fixture" || failed=1
  [ -z "$state_mode" ] || chmod "$state_mode" "$STATE" || failed=1
  [ -z "$scratch" ] || rm -rf -- "$scratch" || failed=1
  if [ "$failed" = 1 ]; then
    printf '%s\n' 'fixture cleanup failed'
    exit 1
  fi
  exit "$rc"
}

# Run the check with per-case fixture paths. The exit trap does not replace the parent's traps.
device_query_case() {
  local name="$1" check="$2" detail
  local scratch="" fixture="" state_mode="" tool_dir="" tool_was_absent=0 peer_created="" pid_checked_gone=0
  local reply err job_uid job_gid
  if detail=$(
    trap 'device_query_cleanup "$?"' EXIT
    scratch=$(mktemp -d) || { echo 'cannot make a reply directory'; exit 1; }
    reply="$scratch/reply"; err="$scratch/err"
    job_uid=$(id -u "$JOB") && job_gid=$(id -g "$JOB") || { echo 'cannot read the job uid and gid'; exit 1; }
    # PrivateTmp is not shared with the handler. Its only configured ReadWritePaths is $STATE;
    # install gives that directory mode 0700, so let the job traverse it only for this case.
    state_mode=$(stat -c %a "$STATE") && fixture=$(mktemp -d "$STATE/.device-query-qual.XXXXXX") &&
      chown "$JOB" "$fixture" && chmod 0711 "$fixture" && chmod go+x "$STATE" &&
      : > "$fixture/runs" && chmod 0666 "$fixture/runs" || { echo 'cannot set up the state fixture'; exit 1; }
    # /usr/bin is the first fixed tool directory. Move the original on the same filesystem,
    # so writing the stand-in never follows a symlink or changes the original inode.
    tool_dir=$(mktemp -d "${DEVICE_QUERY_TOOL%/*}/.device-query-qual.XXXXXX") || { echo 'cannot make a tool backup directory'; exit 1; }
    if [ -e "$DEVICE_QUERY_TOOL" ] || [ -L "$DEVICE_QUERY_TOOL" ]; then
      mv -T -- "$DEVICE_QUERY_TOOL" "$tool_dir/original" || { echo 'cannot save the original nvidia-smi'; exit 1; }
    else
      tool_was_absent=1
    fi
    "$check"
  ); then
    result "$name" PASS "$detail"
  else
    result "$name" FAIL "${detail//$'\n'/; }"
  fi
}

device_query_install_standin() {
  local mode="$1" staged="$tool_dir/standin"
  cat > "$staged" <<EOF || return 1
#!/bin/sh
printf '%s\n' run >> "$fixture/runs" || exit 3
if [ "\${USER:-}" != "$JOB" ] || [ "\${LOGNAME:-}" != "$JOB" ] || [ "\$(id -u)" != "$job_uid" ] || [ "\$(id -g)" != "$job_gid" ]; then
  echo "$DEVICE_QUERY_NVML_REFUSAL" >&2
  exit 4
fi
EOF
  case "$mode" in
    escaping)
      # setsid leaves the tool's process group, not its systemd cgroup. Ignore TERM
      # during service teardown, retain fd 3 (the lock), but release the output pipes.
      cat >> "$staged" <<EOF || return 1
pid_file="$fixture/pid"
if [ ! -s "\$pid_file" ]; then
  setsid sh -c 'trap "" TERM; echo "\$\$" > "\$1.new" && mv "\$1.new" "\$1" && exec sleep 300' sh "\$pid_file" < /dev/null > /dev/null 2>&1 &
  for i in \$(seq 1 100); do
    [ -s "\$pid_file" ] && break
    sleep 0.1
  done
  [ -s "\$pid_file" ] || exit 5
fi
EOF
      ;;
    slow)
      cat >> "$staged" <<EOF || return 1
trap '' TERM
echo "\$\$" > "$fixture/pid" || exit 5
exec sleep 60
EOF
      ;;
  esac
  if [ "$mode" != slow ]; then
    cat >> "$staged" <<EOF || return 1
case "\$1 \$2" in
  '--query-gpu=uuid,name,memory.total --format=csv,noheader,nounits') echo "$DEVICE_QUERY_CARD" ;;
  *) exit 2 ;;
esac
EOF
  fi
  chmod 0755 "$staged" && mv -fT -- "$staged" "$DEVICE_QUERY_TOOL"
}

device_query_request() {
  local bound="$1"; shift
  printf 'device-query nvidia-devices\n' |
    "$@" timeout "$bound" socat -t "$bound" - "UNIX-CONNECT:$DEVICE_QUERY_SOCKET" > "$reply" 2> "$err"
}

device_query_reply_is() {
  local expected="$1"$'\n' actual
  # Keep the final newline through command substitution; length also rules out extra bytes.
  actual=$(cat "$reply" && printf '.') || return 1
  [[ "$actual" = "$expected." && "$(stat -c %s "$reply")" = "${#expected}" ]]
}

device_query_reply_has_card() {
  local bytes="$(( ${#DEVICE_QUERY_CARD} + 1 ))"
  device_query_reply_is "ok $bytes"$'\n'"$DEVICE_QUERY_CARD"
}

device_query_bad_reply() {
  printf '%s (reply: %s; client: %s)\n' "$1" "$(head -n 1 "$reply")" "$(head -n 1 "$err")"
  return 1
}

the_engines_device_query_is_served_by_a_per_connection_handler_past_its_peer_check() {
  device_query_case "$FUNCNAME" device_query_check_peer
}

device_query_check_peer() {
  local unit=oneiron-job-control.socket before after socket_group peer peer_uid job_group
  local lock="$DEVICE_QUERY_LOCK_DIR/device-query.lock"
  device_query_install_standin answering || { echo 'cannot install the answering stand-in'; return 1; }
  before=$(systemctl show -P NAccepted "$unit") || { echo 'cannot read initial NAccepted'; return 1; }
  device_query_request 15 as_engine || :
  device_query_reply_has_card || { device_query_bad_reply "the engine's device query did not return the card"; return 1; }
  after=$(systemctl show -P NAccepted "$unit") || { echo 'cannot read final NAccepted'; return 1; }
  [[ "$before" =~ ^[0-9]+$ && "$after" = "$((before + 1))" ]] || { echo "NAccepted went $before->$after, wanted +1"; return 1; }
  [[ -f "$fixture/runs" && "$(wc -l < "$fixture/runs")" -eq 1 ]] || { echo 'the engine request did not run the tool exactly once'; return 1; }

  socket_group=$(stat -c %G "$DEVICE_QUERY_SOCKET") && job_group=$(id -gn "$JOB") || { echo 'cannot read the socket or job group'; return 1; }
  peer="oneiron-qual-${fixture##*.}"
  peer="${peer,,}"
  useradd --system --no-create-home --shell /bin/false --gid "$job_group" --groups "$socket_group" "$peer" || { echo 'cannot make the non-engine peer'; return 1; }
  peer_created="$peer"
  peer_uid=$(id -u "$peer") || { echo 'cannot read the non-engine peer UID'; return 1; }
  # The handler can close with unread request bytes after the refusal; socat may report a reset.
  device_query_request 15 runuser -u "$peer" -- || :
  device_query_reply_is "refused caller_not_the_engine: uid $peer_uid" || { device_query_bad_reply 'the non-engine account was not refused at the peer check'; return 1; }
  [ "$(wc -l < "$fixture/runs")" -eq 1 ] || { echo 'the refused peer ran the tool'; return 1; }
  [[ -f "$lock" && "$(stat -c '%u %a' "$lock")" = '0 600' &&
    -d "$DEVICE_QUERY_LOCK_DIR" && "$(stat -c '%u %a' "$DEVICE_QUERY_LOCK_DIR")" = '0 700' ]] || { echo 'the lock or its directory has the wrong owner or mode'; return 1; }
  echo "engine served, NAccepted $before->$after; non-engine uid $peer_uid refused without running the tool; root lock 600 in root directory 700"
}

a_device_query_left_running_holds_the_lock_across_handler_instances() {
  device_query_case "$FUNCNAME" device_query_check_held_lock
}

device_query_check_held_lock() {
  local pid
  device_query_install_standin escaping || { echo 'cannot install the escaping stand-in'; return 1; }
  device_query_request 15 as_engine || :
  device_query_reply_has_card || { device_query_bad_reply 'request 1 did not return the card'; return 1; }
  pid=$(device_query_pid) && kill -0 "$pid" 2>/dev/null || { echo 'request 1 left no live descendant'; return 1; }
  device_query_request 15 as_engine || :
  device_query_reply_is 'refused query_stuck: an earlier device query has not ended' || { device_query_bad_reply 'request 2 was not refused with query_stuck'; return 1; }
  kill -KILL "$pid" && device_query_pid_gone "$pid" || { echo "descendant $pid did not die within 10 s"; return 1; }
  pid_checked_gone=1
  device_query_request 15 as_engine || :
  device_query_reply_has_card || { device_query_bad_reply 'request 3 did not return the card after the descendant died'; return 1; }
  echo "request 1 served; request 2 refused with query_stuck; request 3 served after descendant $pid died"
}

a_device_query_past_its_deadline_is_refused_and_the_next_instance_is_served() {
  device_query_case "$FUNCNAME" device_query_check_deadline
}

device_query_check_deadline() {
  local start end elapsed pid
  device_query_install_standin slow || { echo 'cannot install the slow stand-in'; return 1; }
  start=$(date +%s) || { echo 'cannot read the start time'; return 1; }
  device_query_request 16 as_engine || :
  end=$(date +%s) || { echo 'cannot read the end time'; return 1; }
  elapsed="$((end - start))"
  device_query_reply_is "refused $DEVICE_QUERY_TOOL did not answer within 10 s" || { device_query_bad_reply 'the slow query was not refused at the deadline'; return 1; }
  [[ "$elapsed" -ge 0 && "$elapsed" -le 16 ]] || { echo "the slow request took ${elapsed}s, wanted at most 16 s"; return 1; }
  pid=$(device_query_pid) && device_query_pid_gone "$pid" || { echo 'the slow query has no PID or is still alive after 10 s'; return 1; }
  pid_checked_gone=1
  device_query_install_standin answering || { echo 'cannot reinstall the answering stand-in'; return 1; }
  device_query_request 15 as_engine || :
  device_query_reply_has_card || { device_query_bad_reply 'the next instance did not return the card'; return 1; }
  echo "slow query refused after ${elapsed}s; PID $pid gone within 10 s; next instance served"
}
