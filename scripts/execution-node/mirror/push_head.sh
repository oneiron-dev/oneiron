#!/usr/bin/env bash
# Push one commit into an execution node's template mirror before a work order names it (the node never fetches:
# crates/oneiron-server/src/gpu_execution_node/jobs/staging.rs). Runs on the booking host (sel), as the account that holds
# the push key. docs/ops/execution-node-mirror-and-check.md.
#
# usage: push_head.sh [--repo <clone>] [--key <file>] [--vendor] <node host> <mirror name> <full sha>
#   --repo    a clone that holds <full sha> (default: the current directory)
#   --key     the push key (default $ONEIRON_MIRROR_PUSH_KEY, else /home/lexi/.ssh/oneiron_mirror_push)
#   --vendor  also make sure the node's vendor root holds every crate Cargo.lock locks at <full sha> (the oneiron-check
#             template). Missing crates come from a fleet job on the node, vendor_job.sh: cargo never runs here (the
#             Engine's ACCEPT, 28 Nov 15:47: no cargo on sel). FIX [NODE-VENDOR-ONEIRON-JOB] moves that job into Oneiron.
#
# The commit lands as refs/pins/<full sha>, so it stays referenced while orders name it; the mirror runs no gc
# (install_mirror_account.sh). Prints `## MIRROR-PUSH rc=<n> ...` and, with --vendor, `## VENDOR rc=<n> ...`; exits with
# the first non-zero rc.
set -u -o pipefail

repo=. key=${ONEIRON_MIRROR_PUSH_KEY:-/home/lexi/.ssh/oneiron_mirror_push} vendor=
while [ $# -gt 0 ]; do
  case $1 in
    --repo) repo=${2:?}; shift 2;;
    --key) key=${2:?}; shift 2;;
    --vendor) vendor=1; shift;;
    --) shift; break;;
    -*) echo "push_head.sh: unknown option $1" >&2; exit 2;;
    *) break;;
  esac
done
[ $# -eq 3 ] || { sed -n '5,10p' "$0" >&2; exit 2; }
node=$1 mirror=$2 sha=$3
here=$(cd "$(dirname "$0")" && pwd)
# The fleet job's booking (vendor_job.sh): each figure is a setting. The defaults are chosen by OPUS-COORD-E2E (28 Nov)
# for a cargo vendor of the whole lock (1287 crate dirs on main 30f5a84067ed), a download and a copy with no compile.
vendor_fleet=${ONEIRON_VENDOR_FLEET:-fleet}
vendor_mem=${ONEIRON_VENDOR_MEM:-4G}
vendor_disk=${ONEIRON_VENDOR_DISK:-12G}
vendor_timeout=${ONEIRON_VENDOR_TIMEOUT:-45m}

[[ $node =~ ^[A-Za-z0-9.-]+$ ]] || { echo "push_head.sh: the node host is not a host name" >&2; exit 2; }
[[ $mirror =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]] || { echo "push_head.sh: the mirror name is not a template name" >&2; exit 2; }
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "push_head.sh: the commit is not 40 lower hex" >&2; exit 2; }
[ -r "$key" ] || { echo "push_head.sh: no push key at $key" >&2; exit 2; }
git -C "$repo" cat-file -e "${sha}^{commit}" 2>/dev/null || { echo "push_head.sh: $repo holds no commit $sha (fetch it first)" >&2; exit 2; }

remote="oneiron-mirror@$node:/srv/oneiron-mirrors/$mirror.git"
ssh_opts=(-i "$key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes)
export GIT_SSH_COMMAND="ssh ${ssh_opts[*]}"

t0=$(date +%s)
git -C "$repo" push --porcelain "$remote" "$sha:refs/pins/$sha" > /dev/null; rc=$?
if [ "$rc" -eq 0 ]; then
  answer=$(git -C "$repo" ls-remote "$remote" "refs/pins/$sha"); rc=$?
  [ "$rc" -eq 0 ] && [ "$answer" != "$(printf '%s\trefs/pins/%s' "$sha" "$sha")" ] && rc=3
fi
echo "## MIRROR-PUSH rc=$rc node=$node mirror=$mirror head=${sha:0:12} secs=$(( $(date +%s) - t0 ))"
[ "$rc" -eq 0 ] || exit "$rc"
[ -n "$vendor" ] || exit 0

# The crate dirs Cargo.lock locks (registry and git sources; cargo vendor --versioned-dirs names them <name>-<version>),
# less the ones the node's vendor root holds.
locked_dirs() {
  git -C "$repo" show "$sha:Cargo.lock" | awk '
    function value(line) { sub(/^[a-z]+ = "/, "", line); sub(/"[[:space:]]*$/, "", line); return line }
    function flush() { if (in_package && source != "") print name "-" version; in_package = 0 }
    /^\[\[package\]\]/ { flush(); in_package = 1; name = version = source = ""; next }
    /^\[/ { flush(); next }
    in_package && /^name = "/ { name = value($0) }
    in_package && /^version = "/ { version = value($0) }
    in_package && /^source = "/ { source = value($0) }
    END { flush() }' | sort -u
}
missing_dirs() {
  local present
  present=$(ssh "${ssh_opts[@]}" "oneiron-mirror@$node" vendor-list < /dev/null) || return 1
  comm -23 <(locked_dirs) <(printf '%s\n' "$present" | sort -u)
}

missing=$(missing_dirs) || { echo "## VENDOR rc=4 node=$node (vendor-list did not answer)"; exit 4; }
count=$(printf '%s' "$missing" | grep -c .)
if [ "$count" -eq 0 ]; then
  echo "## VENDOR rc=0 node=$node head=${sha:0:12} missing=0"
  exit 0
fi
echo "## VENDOR-JOB node=$node head=${sha:0:12} missing=$count first=$(printf '%s\n' "$missing" | head -1)"
"$vendor_fleet" run --who oneiron-vendor --goal "vendor $count crates of ${sha:0:12} into $node's oneiron-check vendor root" \
  --need any --host "$node" --mem "$vendor_mem" --threads 2 --disk "$vendor_disk" --timeout "$vendor_timeout" \
  --sync "$here" -- bash vendor_job.sh "/srv/oneiron-mirrors/$mirror.git" "$sha"
jrc=$?
missing=$(missing_dirs) || { echo "## VENDOR rc=4 node=$node (vendor-list did not answer)"; exit 4; }
left=$(printf '%s' "$missing" | grep -c .)
rc=0; [ "$jrc" -ne 0 ] && rc=$jrc; [ "$left" -ne 0 ] && [ "$rc" -eq 0 ] && rc=5
first=; [ "$left" -ne 0 ] && first=" first=$(printf '%s\n' "$missing" | head -1)"
echo "## VENDOR rc=$rc node=$node head=${sha:0:12} job_rc=$jrc sent=$(( count - left )) missing=$left$first"
exit "$rc"
