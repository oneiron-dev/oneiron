#!/usr/bin/env bash
# Fill an execution node's vendor root with the crates one commit's Cargo.lock locks and the root lacks. A fleet job ON
# the node, booked by push_head.sh --vendor (docs/ops/execution-node-mirror-and-check.md). It has the network; the
# oneiron-check job that reads the crates later has none.
#
# usage: vendor_job.sh <mirror path> <full sha>
# - The source is the commit as the node's mirror holds it (push_head.sh pushed it first). The mirror is world-readable,
#   so the job reads it without the push account.
# - `cargo vendor --locked --versioned-dirs` with the node's own toolchain ($ONEIRON_CHECK_TOOLCHAINS/rust-<channel>,
#   default /opt/oneiron/toolchains), into a temporary dir. It downloads and builds nothing.
# - Each crate dir the root lacks goes to the push account with `vendor-receive` over ssh to localhost, with the
#   vendor-only key ($ONEIRON_VENDOR_PUSH_KEY, default ~/.ssh/oneiron_vendor_push). oneiron-vendor-receive checks every
#   file against .cargo-checksum.json and never replaces a present dir.
# Prints `## VENDOR-JOB rc=<n> sent=<n> present=<n>`; exit 0 when every locked crate is in the root.
set -u -o pipefail
mirror=${1:?usage: vendor_job.sh <mirror path> <full sha>}
sha=${2:?usage: vendor_job.sh <mirror path> <full sha>}
key=${ONEIRON_VENDOR_PUSH_KEY:-$HOME/.ssh/oneiron_vendor_push}
toolchains=${ONEIRON_CHECK_TOOLCHAINS:-/opt/oneiron/toolchains}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo "## VENDOR-JOB rc=2 (the commit is not 40 lower hex)"; exit 2; }
[ -r "$key" ] || { echo "## VENDOR-JOB rc=2 (no vendor key at $key)"; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/oneiron-vendor.XXXXXX") || exit 9
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
ssh_opts=(-i "$key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
  -o ControlMaster=auto -o "ControlPath=$work/ssh-control" -o ControlPersist=120)
to_node() { ssh "${ssh_opts[@]}" oneiron-mirror@localhost "$@"; }

mkdir -p "$work/src" "$work/cargo-home"
git -c safe.directory="$mirror" --git-dir="$mirror" archive --format=tar "$sha" | tar -x -C "$work/src" \
  || { echo "## VENDOR-JOB rc=3 (the mirror $mirror gives no commit $sha)"; exit 3; }
channel=$(sed -n -E 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$work/src/rust-toolchain.toml" 2>/dev/null | head -1)
tc=$toolchains/rust-$channel
[ -n "$channel" ] && [ -x "$tc/bin/cargo" ] || { echo "## VENDOR-JOB rc=4 (no toolchain rust-$channel under $toolchains)"; exit 4; }

t0=$(date +%s)
( cd "$work/src" && env CARGO_HOME="$work/cargo-home" PATH="$tc/bin:/usr/bin:/bin" \
    cargo vendor --locked --versioned-dirs "$work/vendor" > /dev/null 2> "$work/vendor.err" ); vrc=$?
[ "$vrc" -eq 0 ] || { tail -20 "$work/vendor.err"; echo "## VENDOR-JOB rc=$vrc (cargo vendor failed)"; exit "$vrc"; }
echo "## VENDOR-MADE crates=$(ls "$work/vendor" | wc -l) secs=$(( $(date +%s) - t0 ))"

present=$(to_node vendor-list < /dev/null) || { echo "## VENDOR-JOB rc=5 (vendor-list did not answer)"; exit 5; }
sent=0 kept=0 rc=0
while IFS= read -r dir; do
  [ -n "$dir" ] || continue
  if printf '%s\n' "$present" | grep -qxF -- "$dir"; then kept=$((kept + 1)); continue; fi
  if tar -C "$work/vendor" -cf - -- "$dir" | to_node "vendor-receive $dir"; then
    sent=$((sent + 1))
  else
    echo "## VENDOR-REFUSED $dir"; rc=6
  fi
done < <(ls "$work/vendor")
ssh "${ssh_opts[@]}" -O exit oneiron-mirror@localhost 2>/dev/null
echo "## VENDOR-JOB rc=$rc sent=$sent present=$kept head=${sha:0:12}"
exit "$rc"
