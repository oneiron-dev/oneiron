#!/usr/bin/env bash
# T40 of pass 33 (33-exec-node/DESIGN.md sections 7.10 and 11): after the handoff no other ordinary account can open
# the card. Run as root at the box, in the handoff window (card CG-1), once for each phase of 7.10:
#   --phase nobody        step 2: the card's files are closed to every ordinary account, the job account's too.
#   --phase oneiron-only  step 3: only the job account's group may open them (T40 proper).
# Each phase also checks that the closing is the driver's persistent setting (so it survives a reboot), that no
# process holds the card's files open (closing them closes no descriptor that is already open), and that no compute
# context lives on the card. Every line also goes to the evidence file, kept beside the node's configuration.
#
# usage: check_device_handoff.sh --phase nobody|oneiron-only --device <GPU-uuid> --job-account <name>
#          [--engine-account <name>] [--also-account <name>]... [--allow-holder <command name>]... [--evidence <file>]
#   --engine-account  the engine's account: in phase oneiron-only its GPU probe must read the card through the job
#                   control socket (ONEIRON_JOB_CONTROL_SOCKET, default /run/oneiron-job-control.sock), whose root
#                   handler runs the query as the job account (FIX EXEC-NODE-PROBE-AFTER-HANDOVER). Name it in
#                   --also-account too, so its own open is checked closed.
#   --also-account  an account to try besides the ordinary ones (UID_MIN..UID_MAX of /etc/login.defs): the engine's
#                   account, or the private tool's account when either is a system account.
#   --allow-holder  a process that may hold the card's files open, by its command name (e.g. nvidia-persistenced).
#   --evidence      default /etc/oneiron/device-handoff-<uuid>-<phase>.txt
# Prints `## EVIDENCE ...` and `## CHECK <name> PASS|FAIL <why>` lines, then one `## TEST <name> PASS|FAIL <why>`.
# Exit 0 on PASS, 1 on FAIL, 64 on a usage error, 77 when it cannot run here (not root, no NVIDIA driver, no such
# card), so off the field host it never claims a result.
# Fixtures (fixture_checks_in_container.sh): NVIDIA_PROC (default /proc/driver/nvidia), NVIDIA_DEV (default /dev) and
# an nvidia-smi on PATH stand in for the driver.
set -u
PHASE=; DEVICE=; JOB=; ENGINE=; ALSO=(); ALLOW=(); EVIDENCE=
while [ $# -gt 0 ]; do
  case $1 in
    --phase) PHASE=$2; shift 2;;
    --device) DEVICE=$2; shift 2;;
    --job-account) JOB=$2; shift 2;;
    --engine-account) ENGINE=$2; shift 2;;
    --also-account) ALSO+=("$2"); shift 2;;
    --allow-holder) ALLOW+=("$2"); shift 2;;
    --evidence) EVIDENCE=$2; shift 2;;
    *) echo "unknown argument $1" >&2; exit 64;;
  esac
done
case $PHASE in nobody|oneiron-only) ;; *) echo "--phase nobody|oneiron-only" >&2; exit 64;; esac
[ -n "$DEVICE" ] && [ -n "$JOB" ] || { echo "--device and --job-account are required" >&2; exit 64; }
TEST=after_the_handoff_no_other_ordinary_account_can_open_the_card
[ "$PHASE" = nobody ] && TEST=before_the_grant_no_ordinary_account_can_open_the_card
. "$(dirname "$0")/card.sh"
EVIDENCE=${EVIDENCE:-/etc/oneiron/device-handoff-$DEVICE-$PHASE.txt}

unproven() { echo "## TEST $TEST UNPROVEN $1"; exit 77; }
[ "$(id -u)" = 0 ] || unproven "not-root"
[ -d "$NVIDIA_PROC/gpus" ] || unproven "no-nvidia-driver ($NVIDIA_PROC/gpus)"
command -v nvidia-smi > /dev/null || unproven "no-nvidia-smi"
command -v python3 > /dev/null || unproven "no-python3 (the open probe)"
id -u "$JOB" > /dev/null 2>&1 || unproven "no-job-account-$JOB"

mkdir -p "$(dirname "$EVIDENCE")" && : > "$EVIDENCE" || unproven "evidence-file-not-writable"
say() { echo "$*"; echo "$*" >> "$EVIDENCE"; }
FAILED=()
check() { # <name> <PASS|FAIL> <why>
  say "## CHECK $1 $2 $3"
  [ "$2" = PASS ] || FAILED+=("$1")
}

# The card: its PCI address, minor and files (card.sh).
card_resolve "$DEVICE" || unproven "no-card-$DEVICE"
say "## EVIDENCE at=$(date -u +%FT%TZ) boot_id=$(cat /proc/sys/kernel/random/boot_id) kernel=$(uname -r) phase=$PHASE"
say "## EVIDENCE card uuid=$DEVICE bus=$CARD_BUS minor=$CARD_MINOR driver=$CARD_DRIVER"

# The accounts to try: every ordinary one, the named ones, never the job account (it is tried on its own).
uid_min=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null); uid_min=${uid_min:-1000}
uid_max=$(awk '$1 == "UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null); uid_max=${uid_max:-60000}
mapfile -t OTHERS < <({ getent passwd | awk -F: -v lo="$uid_min" -v hi="$uid_max" '$3 >= lo && $3 <= hi { print $1 }'
  [ ${#ALSO[@]} -eq 0 ] || printf '%s\n' "${ALSO[@]}"; } | grep -v '^$' | grep -vx -- "$JOB" | sort -u)
job_gid=$(id -g "$JOB")
say "## EVIDENCE accounts tried=[${OTHERS[*]}] job=$JOB job_gid=$job_gid"

# Whether <account> gets past the permission check of <file>: `closed` for EACCES or EPERM, else what the open gave
# (`opened`, or an errno past the permission check, such as ENXIO on a fixture's node with no driver behind it).
open_as() {
  runuser -u "$1" -- python3 -c '
import errno, os, sys
try:
    os.close(os.open(sys.argv[1], os.O_RDWR))
    print("opened")
except OSError as e:
    print("closed" if e.errno in (errno.EACCES, errno.EPERM) else errno.errorcode.get(e.errno, str(e.errno)))
' "$2" 2>&1 | tail -1
}

# 1. Each file of the card: owner, group and mode; no bit for others; the group is the job account's (oneiron-only) or
#    no ordinary account's (nobody).
members_of_gid() { # the accounts whose primary or supplementary group is <gid>
  { getent passwd | awk -F: -v g="$1" '$4 == g { print $1 }'
    getent group "$1" | awk -F: '{ gsub(",", "\n", $4); print $4 }'; } | grep -v '^$' | sort -u
}
for f in "${CARD[@]}" "${CARD_SIDE[@]}"; do
  [ -e "$f" ] && say "## EVIDENCE file $(stat -c '%n owner=%U group=%G gid=%g mode=%a' "$f")"
done
for f in "${CARD[@]}"; do
  [ -e "$f" ] || { check "file-$(basename "$f")" FAIL "missing"; continue; }
  mode=$(stat -c %a "$f"); gid=$(stat -c %g "$f")
  others=$(members_of_gid "$gid" | grep -vx -- "$JOB" | tr '\n' ' ')
  why="mode=$mode gid=$gid other_members=[${others% }]"
  if (( 8#$mode & 8#007 )); then check "file-$(basename "$f")" FAIL "$why: open to every account"
  elif [ -n "$others" ] && (( 8#$mode & 8#070 )); then check "file-$(basename "$f")" FAIL "$why: open to the group's other members"
  elif [ "$PHASE" = oneiron-only ] && { [ "$gid" != "$job_gid" ] || ! (( (8#$mode & 8#060) == 8#060 )); }; then
    check "file-$(basename "$f")" FAIL "$why: the job account's group $job_gid cannot read and write it"
  elif [ "$PHASE" = nobody ] && [ "$gid" = "$job_gid" ] && (( 8#$mode & 8#070 )); then
    check "file-$(basename "$f")" FAIL "$why: still open to the job account's group"
  else check "file-$(basename "$f")" PASS "$why"; fi
done

# 2. Persistent: the driver makes /dev/nvidia* itself (ModifyDeviceFiles=1) with the mode and group of a modprobe
#    options line, so a reboot or a reload makes them the same way again.
param() { awk -F': *' -v k="$1" '$1 == k { print $2 }' "$NVIDIA_PROC/params" 2>/dev/null; }
p_modify=$(param ModifyDeviceFiles); p_gid=$(param DeviceFileGID); p_mode=$(param DeviceFileMode)
options=$(grep -rhs 'NVreg_DeviceFile' /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d | grep -v '^\s*#' | tr '\n' ' ')
say "## EVIDENCE driver ModifyDeviceFiles=$p_modify DeviceFileGID=$p_gid DeviceFileMode=$p_mode options=[${options% }]"
want_gid=0; [ "$PHASE" = oneiron-only ] && want_gid=$job_gid
if [ "$p_modify" != 1 ]; then check driver-setting FAIL "ModifyDeviceFiles=$p_modify: the driver does not set the files' mode"
elif [ -z "$p_mode" ] || (( p_mode & 8#007 )); then check driver-setting FAIL "DeviceFileMode=$p_mode (decimal) leaves the card open to every account"
elif [ "$p_gid" != "$want_gid" ]; then check driver-setting FAIL "DeviceFileGID=$p_gid, want $want_gid"
elif ! grep -Eq "NVreg_DeviceFileGID=$p_gid([^0-9]|$)" <<< "$options" || ! grep -q 'NVreg_DeviceFileMode=' <<< "$options"; then
  check driver-setting FAIL "the running values are in no modprobe options line: a reboot may undo them"
else check driver-setting PASS "gid=$p_gid mode=$(printf '%o' "$p_mode") from a modprobe options line"; fi
dri=0; for f in "${CARD[@]}"; do case $f in */dri/*) dri=1;; esac; done
if [ $dri = 1 ]; then
  if grep -rlsE 'renderD|SUBSYSTEM=="drm"' /etc/udev/rules.d > /dev/null; then check dri-rule PASS "a rule under /etc/udev/rules.d names the drm nodes"
  else check dri-rule FAIL "the card has drm nodes and no rule under /etc/udev/rules.d sets them: a reboot restores the default mode"; fi
fi

# 3. An open under every other account fails at the permission check; the job account's succeeds only in oneiron-only.
for account in "${OTHERS[@]}"; do
  id -u "$account" > /dev/null 2>&1 || { check "open-as-$account" FAIL "no such account"; continue; }
  got=""; for f in "${CARD[@]}"; do [ -e "$f" ] && got="$got $(basename "$f")=$(open_as "$account" "$f")"; done
  if grep -qvE '=closed$' <<< "$(tr ' ' '\n' <<< "${got# }")"; then check "open-as-$account" FAIL "${got# }"
  else check "open-as-$account" PASS "${got# }"; fi
done
got="$(basename "${CARD[0]}")=$(open_as "$JOB" "${CARD[0]}") $(basename "${CARD[1]}")=$(open_as "$JOB" "${CARD[1]}")"
if [ "$PHASE" = oneiron-only ]; then
  if grep -q '=closed' <<< "$got"; then check "open-as-job-account" FAIL "$got: the job account cannot open the card"
  else check "open-as-job-account" PASS "$got"; fi
else
  if grep -qvE '=closed$' <<< "$(tr ' ' '\n' <<< "$got")"; then check "open-as-job-account" FAIL "$got: open before the grant"
  else check "open-as-job-account" PASS "$got"; fi
fi

# 4. No descriptor on the card's files is open, but an allowed holder's.
holders=""
while read -r pid comm uid file allowed; do
  say "## EVIDENCE holder pid=$pid comm=$comm uid=$uid file=$file $allowed"
  [ "$allowed" = allowed ] || holders="$holders $pid:$comm:$(basename "$file")"
done < <(card_holders "${ALLOW[@]}")
if [ -n "$holders" ]; then check open-descriptors FAIL "held open by${holders}"
else check open-descriptors PASS "none but allowed holders [${ALLOW[*]}]"; fi

# 5. No compute context on the card, and the card answers a probe.
contexts=$(card_contexts "$DEVICE")
if [ -n "$contexts" ]; then check compute-contexts FAIL "$(tr '\n' ';' <<< "$contexts")"
else check compute-contexts PASS "none on $DEVICE"; fi
if probe=$(card_probe "$DEVICE"); then check probe PASS "$probe"; else check probe FAIL "$probe"; fi

# 6. The engine's GPU probe reads the card through the job control socket, as the job account, while the engine's own
#    account stays closed to the card (3, with --also-account). One `device-query` request, as the engine sends it, and
#    its reply read as the engine reads it: the length frame first, then the card's own UUID field (engine_probe.py,
#    whose text goes to python3 as an argument, since the engine's account may not read this tree; its own red/green
#    runs: engine_probe_fixture.sh).
if [ -n "$ENGINE" ] && [ "$PHASE" = oneiron-only ]; then
  control_socket=${ONEIRON_JOB_CONTROL_SOCKET:-/run/oneiron-job-control.sock}
  answer=$(runuser -u "$ENGINE" -- python3 -c "$(cat "$(dirname "$0")/engine_probe.py")" "$control_socket" "$DEVICE" 2>&1)
  probe_rc=$?
  verdict=$(head -1 <<< "$answer")
  # A PASS line counts only from a probe that also exited 0.
  if [ "$probe_rc" -eq 0 ] && [[ $verdict == "PASS "* ]]; then
    check engine-probe PASS "$ENGINE via $control_socket: ${verdict#PASS }"
  else check engine-probe FAIL "$ENGINE via $control_socket: exit $probe_rc: ${verdict:-no answer}"; fi
fi

if [ ${#FAILED[@]} -eq 0 ]; then say "## TEST $TEST PASS phase=$PHASE evidence=$EVIDENCE"; exit 0; fi
say "## TEST $TEST FAIL phase=$PHASE failed=[${FAILED[*]}] evidence=$EVIDENCE"
exit 1
