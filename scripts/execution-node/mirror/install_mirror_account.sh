#!/usr/bin/env bash
# Set up an execution node's push account, its template mirrors and the oneiron-check vendor root. Run as root on the
# node, once at enrolment, and again to add a mirror or a key (idempotent). docs/ops/execution-node-mirror-and-check.md.
#
# usage: install_mirror_account.sh --push-key <public key file> [--vendor-key <public key file>] [--dry-run] <mirror>...
#   e.g. install_mirror_account.sh --push-key /root/oneiron_mirror_push.pub --vendor-key /root/oneiron_vendor_push.pub oneiron-check
#
# What it makes:
# - the system account `oneiron-mirror` (locked password, shell /bin/sh, home /var/lib/oneiron-mirror 0700). It is in
#   no group of the engine (`oneiron`) or of the jobs (`oneiron-job`).
# - /srv/oneiron-mirrors root:root 0755. In it, one bare mirror <mirror>.git per name, owned by the push account: files
#   0644 and dirs 0755, so the engine account reads it for staging and nobody else writes it. Settings:
#   receive.fsckObjects (each pushed object is checked); gc.auto=0 and receive.autogc=false (no repack ever removes an
#   object while a staging reads it, jobs/staging.rs:22-24); core.sharedRepository=0644. An existing mirror is checked
#   and never overwritten. A mirror the account does not own (mel's root-made ones) is left as it is.
# - /srv/oneiron-check root:root 0755, with vendor/ and vendor-incoming/ owned by the push account, 0755. They are on one
#   file system, so a received crate dir lands by one rename.
# - /usr/local/libexec/oneiron-mirror-shell and oneiron-vendor-receive, root:root 0755, from this folder.
# - /var/lib/oneiron-mirror/.ssh/authorized_keys, root:root 0644 in a root-owned 0755 dir, so the account cannot change
#   its own keys. Each key runs only the forced command:
#     restrict,command="/usr/local/libexec/oneiron-mirror-shell" <push key>                (sel's pushes)
#     restrict,command="/usr/local/libexec/oneiron-mirror-shell --vendor-only" <vendor key> (vendor_job.sh on the node)
# The file is written whole from the keys given in this run.
set -u -o pipefail

ACCOUNT=oneiron-mirror
ACCOUNT_HOME=/var/lib/oneiron-mirror
MIRROR_ROOT=/srv/oneiron-mirrors
CHECK_ROOT=/srv/oneiron-check
LIBEXEC=/usr/local/libexec
ENGINE_ACCOUNT=oneiron

push_key= vendor_key= dry=
names=()
while [ $# -gt 0 ]; do
  case $1 in
    --push-key) push_key=${2:?}; shift 2;;
    --vendor-key) vendor_key=${2:?}; shift 2;;
    --dry-run) dry=1; shift;;
    -*) echo "install_mirror_account.sh: unknown option $1" >&2; exit 2;;
    *) names+=("$1"); shift;;
  esac
done
here=$(cd "$(dirname "$0")" && pwd)
[ -n "$push_key" ] && [ ${#names[@]} -gt 0 ] || { sed -n '5,6p' "$0" >&2; exit 2; }
for name in "${names[@]}"; do
  [[ $name =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]] || { echo "install_mirror_account.sh: $name is not a template name" >&2; exit 2; }
done

key_line() { # <file>: the one public key in it, checked by ssh-keygen
  local file=$1 line
  [ -f "$file" ] || { echo "install_mirror_account.sh: no key file $file" >&2; return 1; }
  [ "$(grep -c . "$file")" -eq 1 ] || { echo "install_mirror_account.sh: $file must hold exactly one key" >&2; return 1; }
  line=$(grep . "$file")
  [[ $line =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\ [A-Za-z0-9+/=]+(\ .*)?$ ]] \
    || { echo "install_mirror_account.sh: $file is not one public key with no options" >&2; return 1; }
  ssh-keygen -l -f "$file" > /dev/null || return 1
  printf '%s\n' "$line"
}
push_line=$(key_line "$push_key") || exit 2
vendor_line=; [ -n "$vendor_key" ] && { vendor_line=$(key_line "$vendor_key") || exit 2; }

run() { # print the step; run it unless --dry-run
  printf '+ %s\n' "$*"
  [ -n "$dry" ] || "$@"
}
[ -n "$dry" ] || [ "$(id -u)" -eq 0 ] || { echo "install_mirror_account.sh: run as root (or with --dry-run)" >&2; exit 2; }
umask 022

# The account.
if ! getent passwd "$ACCOUNT" > /dev/null; then
  run useradd --system --user-group --home-dir "$ACCOUNT_HOME" --create-home --shell /bin/sh "$ACCOUNT"
fi
run passwd -l "$ACCOUNT"
run chmod 0700 "$ACCOUNT_HOME"
for group in "$ENGINE_ACCOUNT" oneiron-job; do
  if id -nG "$ACCOUNT" 2>/dev/null | tr ' ' '\n' | grep -qx -- "$group"; then
    echo "install_mirror_account.sh: $ACCOUNT is in the group $group; take it out first" >&2; exit 3
  fi
done

# The forced command and its receiver.
run install -o root -g root -m 0755 "$here/oneiron-mirror-shell" "$here/oneiron-vendor-receive" "$LIBEXEC/"

# The roots.
run install -d -o root -g root -m 0755 "$MIRROR_ROOT" "$CHECK_ROOT"
run install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0755 "$CHECK_ROOT/vendor" "$CHECK_ROOT/vendor-incoming"

# The mirrors.
as_account() { run runuser -u "$ACCOUNT" -- "$@"; }
for name in "${names[@]}"; do
  mirror=$MIRROR_ROOT/$name.git
  if [ -e "$mirror" ] || [ -L "$mirror" ]; then
    [ -d "$mirror" ] && [ ! -L "$mirror" ] || { echo "install_mirror_account.sh: $mirror is not a dir; inspect it" >&2; exit 3; }
    owner=$(stat -c %U "$mirror")
    if [ "$owner" != "$ACCOUNT" ]; then
      echo "## MIRROR $mirror is owned by $owner, not $ACCOUNT: left as it is (pushes to it are refused)"; continue
    fi
    echo "## MIRROR $mirror present: settings checked, nothing overwritten"
  else
    as_account git init -q --bare "$mirror"
  fi
  for setting in receive.fsckObjects=true gc.auto=0 receive.autogc=false core.sharedRepository=0644; do
    as_account git --git-dir="$mirror" config "${setting%%=*}" "${setting#*=}"
  done
  if [ -z "$dry" ]; then
    [ ! -e "$mirror/objects/info/alternates" ] || { echo "install_mirror_account.sh: $mirror borrows objects (objects/info/alternates); staging refuses it" >&2; exit 3; }
    if getent passwd "$ENGINE_ACCOUNT" > /dev/null; then
      runuser -u "$ENGINE_ACCOUNT" -- git -c "safe.directory=$mirror" --git-dir="$mirror" rev-parse --git-dir > /dev/null \
        || { echo "install_mirror_account.sh: the engine account $ENGINE_ACCOUNT cannot read $mirror" >&2; exit 3; }
    fi
  fi
  echo "## MIRROR-OK $mirror"
done

# The keys: a root-owned file in a root-owned dir (sshd's StrictModes accepts root as owner).
keys="restrict,command=\"$LIBEXEC/oneiron-mirror-shell\" $push_line"
[ -n "$vendor_line" ] && keys="$keys
restrict,command=\"$LIBEXEC/oneiron-mirror-shell --vendor-only\" $vendor_line"
run install -d -o root -g root -m 0755 "$ACCOUNT_HOME/.ssh"
printf '+ write %s (%s key line(s))\n' "$ACCOUNT_HOME/.ssh/authorized_keys" "$(printf '%s\n' "$keys" | grep -c .)"
if [ -z "$dry" ]; then
  next=$(mktemp "$ACCOUNT_HOME/.ssh/.authorized_keys.XXXXXX") || exit 3
  printf '%s\n' "$keys" > "$next" && chown root:root "$next" && chmod 0644 "$next" && mv -T -- "$next" "$ACCOUNT_HOME/.ssh/authorized_keys" \
    || { rm -f -- "$next"; exit 3; }
fi
echo "## MIRROR-ACCOUNT-OK account=$ACCOUNT mirrors=${names[*]} vendor_key=$([ -n "$vendor_line" ] && echo yes || echo no) dry_run=$([ -n "$dry" ] && echo yes || echo no)"
