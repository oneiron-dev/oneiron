#!/usr/bin/env bash
# T40 of pass 33 (33-exec-node/DESIGN.md sections 7.10 and 11): after the handoff no other ordinary account can open
# the card. Run as root at the box, in the handoff window (card CG-1), once for each phase of 7.10:
#   --phase nobody        step 2: the card's files are closed to every ordinary account and to the job device group.
#   --phase oneiron-only  step 3: only the job device group may open them (T40 proper).
# Each phase also checks that the closing is the driver's persistent setting (so it survives a reboot), that no
# process holds the card's files open (closing them closes no descriptor that is already open), and that no compute
# context lives on the card. Every line also goes to the evidence file, kept beside the node's configuration.
#
# usage: check_device_handoff.sh --phase nobody|oneiron-only --device <GPU-uuid> --job-device-group <name>
#          [--job-uid <n>] [--also-account <name>]... [--allow-holder <command name>]... [--evidence <file>]
#   --job-device-group  the node file's job_device_group (default oneiron-job-devices): the group that owns every device
#                   file a job may lease. Each job unit runs as its own uid from the node's range and keeps this group
#                   as its one supplementary group when it leases a device (FIX EXEC-UNIT-CROSS-JOB-SAME-UID).
#   --job-uid       the uid a job's open is tried as, holding that group alone: an id of the node's range no job
#                   holds and no account or group has (default 1879113727, the last id of the default range).
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
PHASE=; DEVICE=; GROUP=; JOB_UID=1879113727; ALSO=(); ALLOW=(); EVIDENCE=
while [ $# -gt 0 ]; do
  case $1 in
    --phase) PHASE=$2; shift 2;;
    --device) DEVICE=$2; shift 2;;
    --job-device-group) GROUP=$2; shift 2;;
    --job-uid) JOB_UID=$2; shift 2;;
    --also-account) ALSO+=("$2"); shift 2;;
    --allow-holder) ALLOW+=("$2"); shift 2;;
    --evidence) EVIDENCE=$2; shift 2;;
    *) echo "unknown argument $1" >&2; exit 64;;
  esac
done
case $PHASE in nobody|oneiron-only) ;; *) echo "--phase nobody|oneiron-only" >&2; exit 64;; esac
[ -n "$DEVICE" ] && [ -n "$GROUP" ] || { echo "--device and --job-device-group are required" >&2; exit 64; }
TEST=after_the_handoff_no_other_ordinary_account_can_open_the_card
[ "$PHASE" = nobody ] && TEST=before_the_grant_no_ordinary_account_can_open_the_card
. "$(dirname "$0")/card.sh"
EVIDENCE=${EVIDENCE:-/etc/oneiron/device-handoff-$DEVICE-$PHASE.txt}

unproven() { echo "## TEST $TEST UNPROVEN $1"; exit 77; }
[ "$(id -u)" = 0 ] || unproven "not-root"
[ -d "$NVIDIA_PROC/gpus" ] || unproven "no-nvidia-driver ($NVIDIA_PROC/gpus)"
command -v nvidia-smi > /dev/null || unproven "no-nvidia-smi"
command -v python3 > /dev/null || unproven "no-python3 (the open probe)"
command -v setpriv > /dev/null || unproven "no-setpriv (the open as a job)"
group_gid=$(getent group "$GROUP" | cut -d: -f3)
[ -n "$group_gid" ] || unproven "no-job-device-group-$GROUP"
# The job's uid: a number of the job range's kind (65536 up) that no account or group has (review r9 R9-09).
[[ "$JOB_UID" =~ ^[0-9]+$ ]] && (( JOB_UID >= 65536 && JOB_UID < 2147483648 )) || unproven "job-uid-$JOB_UID-not-a-job-range-id"
! getent passwd "$JOB_UID" > /dev/null && ! getent group "$JOB_UID" > /dev/null || unproven "job-uid-$JOB_UID-has-an-account-or-group"

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

# The accounts to try: every ordinary one and the named ones. A job is tried on its own, as a uid of the node's range.
uid_min=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null); uid_min=${uid_min:-1000}
uid_max=$(awk '$1 == "UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null); uid_max=${uid_max:-60000}
mapfile -t OTHERS < <({ getent passwd | awk -F: -v lo="$uid_min" -v hi="$uid_max" '$3 >= lo && $3 <= hi { print $1 }'
  [ ${#ALSO[@]} -eq 0 ] || printf '%s\n' "${ALSO[@]}"; } | grep -v '^$' | sort -u)
say "## EVIDENCE accounts tried=[${OTHERS[*]}] job_device_group=$GROUP gid=$group_gid job_uid=$JOB_UID"

# Whether <account> gets past the permission check of <file>: `closed` for EACCES or EPERM, else what the open gave
# (`opened`, or an errno past the permission check, such as ENXIO on a fixture's node with no driver behind it).
OPEN_PROBE='
import errno, os, sys
try:
    os.close(os.open(sys.argv[1], os.O_RDWR))
    print("opened")
except OSError as e:
    print("closed" if e.errno in (errno.EACCES, errno.EPERM) else errno.errorcode.get(e.errno, str(e.errno)))
'
open_as() { runuser -u "$1" -- python3 -c "$OPEN_PROBE" "$2" 2>&1 | tail -1; }
ACL_PROBE='
import os, sys
try:
    os.getxattr(sys.argv[1], "system.posix_acl_access", follow_symlinks=False)
    print("acl")
except OSError:
    print("none")
'
# The same open as a job: the job uid, its own gid, and the job device group as its one supplementary group.
open_as_job() {
  setpriv --reuid="$JOB_UID" --regid="$JOB_UID" --groups="$group_gid" -- python3 -c "$OPEN_PROBE" "$1" 2>&1 | tail -1
}

# 1. Each file of the card: owner, group and mode; no bit for others; the group is the job device group, with no
#    account in it (oneiron-only), or no ordinary account's (nobody).
members_of_gid() { # the accounts whose primary or supplementary group is <gid>
  { getent passwd | awk -F: -v g="$1" '$4 == g { print $1 }'
    getent group "$1" | awk -F: '{ gsub(",", "\n", $4); print $4 }'; } | grep -v '^$' | sort -u
}
for f in "${CARD[@]}" "${CARD_SIDE[@]}"; do
  [ -e "$f" ] && say "## EVIDENCE file $(stat -c '%n owner=%U group=%G gid=%g mode=%a' "$f")"
done
# The job device group itself has no account in it, in both phases (review r9 R9-15).
members=$(members_of_gid "$group_gid" | tr '\n' ' ')
if [ -n "$members" ]; then check job-device-group-members FAIL "group $GROUP (gid $group_gid) holds [${members% }]: each could open every card outside any unit"
else check job-device-group-members PASS "group $GROUP (gid $group_gid) holds no account"; fi
for f in "${CARD[@]}"; do
  [ -e "$f" ] || { check "file-$(basename "$f")" FAIL "missing"; continue; }
  mode=$(stat -c %a "$f"); gid=$(stat -c %g "$f"); owner=$(stat -c %u "$f")
  acl=$(python3 -c "$ACL_PROBE" "$f" 2>&1 | tail -1)
  others=$(members_of_gid "$gid" | tr '\n' ' ')
  why="owner=$owner mode=$mode gid=$gid acl=$acl other_members=[${others% }]"
  # Root owns it and no access ACL names another account (review r9 R9-10).
  if [ "$owner" != 0 ]; then check "file-$(basename "$f")" FAIL "$why: owned by uid $owner, not root"
  elif [ "$acl" != none ]; then check "file-$(basename "$f")" FAIL "$why: an access ACL can open it to other accounts"
  elif (( 8#$mode & 8#007 )); then check "file-$(basename "$f")" FAIL "$why: open to every account"
  elif [ -n "$others" ] && (( 8#$mode & 8#070 )); then check "file-$(basename "$f")" FAIL "$why: open to the group's other members"
  elif [ "$PHASE" = oneiron-only ] && { [ "$gid" != "$group_gid" ] || ! (( (8#$mode & 8#060) == 8#060 )); }; then
    check "file-$(basename "$f")" FAIL "$why: the job device group $group_gid cannot read and write it"
  elif [ "$PHASE" = nobody ] && [ "$gid" = "$group_gid" ] && (( 8#$mode & 8#070 )); then
    check "file-$(basename "$f")" FAIL "$why: still open to the job device group"
  else check "file-$(basename "$f")" PASS "$why"; fi
done

# 2. Persistent: the driver makes /dev/nvidia* itself (ModifyDeviceFiles=1) with the mode and group of a modprobe
#    options line, so a reboot or a reload makes them the same way again.
param() { awk -F': *' -v k="$1" '$1 == k { print $2 }' "$NVIDIA_PROC/params" 2>/dev/null; }
p_modify=$(param ModifyDeviceFiles); p_gid=$(param DeviceFileGID); p_mode=$(param DeviceFileMode)
options=$(grep -rhs 'NVreg_DeviceFile' /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d | grep -v '^\s*#' | tr '\n' ' ')
say "## EVIDENCE driver ModifyDeviceFiles=$p_modify DeviceFileGID=$p_gid DeviceFileMode=$p_mode options=[${options% }]"
want_gid=0; [ "$PHASE" = oneiron-only ] && want_gid=$group_gid
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

# 3. An open under every other account fails at the permission check; a job's succeeds only in oneiron-only.
for account in "${OTHERS[@]}"; do
  id -u "$account" > /dev/null 2>&1 || { check "open-as-$account" FAIL "no such account"; continue; }
  got=""; for f in "${CARD[@]}"; do [ -e "$f" ] && got="$got $(basename "$f")=$(open_as "$account" "$f")"; done
  if grep -qvE '=closed$' <<< "$(tr ' ' '\n' <<< "${got# }")"; then check "open-as-$account" FAIL "${got# }"
  else check "open-as-$account" PASS "${got# }"; fi
done
got="$(basename "${CARD[0]}")=$(open_as_job "${CARD[0]}") $(basename "${CARD[1]}")=$(open_as_job "${CARD[1]}")"
if [ "$PHASE" = oneiron-only ]; then
  # Only an open, or a fixture node's ENXIO (no driver behind it, past the permission check), passes (review r9 R9-09).
  if grep -qvE '=(opened|ENXIO)$' <<< "$(tr ' ' '\n' <<< "$got")"; then check "open-as-job" FAIL "$got: a job holding the job device group cannot open the card"
  else check "open-as-job" PASS "$got"; fi
else
  if grep -qvE '=closed$' <<< "$(tr ' ' '\n' <<< "$got")"; then check "open-as-job" FAIL "$got: open before the grant"
  else check "open-as-job" PASS "$got"; fi
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

if [ ${#FAILED[@]} -eq 0 ]; then say "## TEST $TEST PASS phase=$PHASE evidence=$EVIDENCE"; exit 0; fi
say "## TEST $TEST FAIL phase=$PHASE failed=[${FAILED[*]}] evidence=$EVIDENCE"
exit 1
