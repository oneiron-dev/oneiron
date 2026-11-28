#!/usr/bin/env bash
# The push account's forced command and its crate receiver (oneiron-mirror-shell, oneiron-vendor-receive), on a
# temporary tree: no root, no network, no node. Needs bash, git, tar and python3 3.12 or later.
# usage: bash scripts/execution-node/mirror/test_mirror_shell.sh    (exit 0 when every case passes)
set -u -o pipefail
here=$(cd "$(dirname "$0")" && pwd)
shell=$here/oneiron-mirror-shell
receive=$here/oneiron-vendor-receive
T=$(mktemp -d)
trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/mirrors" "$T/vendor" "$T/incoming" "$T/build"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
  GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
git init -q --bare "$T/mirrors/check.git"
opts=(--mirror-root "$T/mirrors" --vendor-root "$T/vendor" --incoming "$T/incoming" --receive "$receive")

pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
run_shell() { # <command> [more options]: stdin passes through
  local cmd=$1; shift
  SSH_ORIGINAL_COMMAND=$cmd bash "$shell" "${opts[@]}" "$@"
}
refused() { # <case> <command> [more options]; stdin from the caller
  local name=$1 cmd=$2 rc; shift 2
  run_shell "$cmd" "$@" > /dev/null 2> "$T/err"; rc=$?
  if [ "$rc" -eq 126 ] && grep -q 'refused' "$T/err"; then ok "$name"; else bad "$name (rc=$rc: $(head -c 200 "$T/err"))"; fi
}

# A push and a ref read through the shell, as git over ssh makes them: a stand-in ssh passes its last argument as
# SSH_ORIGINAL_COMMAND.
{
  printf '#!/bin/bash\nSSH_ORIGINAL_COMMAND="${@: -1}" exec bash %q' "$shell"
  printf ' %q' "${opts[@]}"
  printf '\n'
} > "$T/stand-in-ssh"
chmod +x "$T/stand-in-ssh"
git init -q "$T/src" && git -C "$T/src" commit -q --allow-empty -m one && sha=$(git -C "$T/src" rev-parse HEAD)
remote="oneiron-mirror@node:$T/mirrors/check.git"
if GIT_SSH_COMMAND="$T/stand-in-ssh" GIT_SSH_VARIANT=simple git -C "$T/src" push -q "$remote" "$sha:refs/pins/$sha" 2> "$T/err"; then
  ok "a push lands in an existing mirror"
else bad "a push lands in an existing mirror ($(head -c 300 "$T/err"))"; fi
git --git-dir="$T/mirrors/check.git" cat-file -e "${sha}^{commit}" 2>/dev/null && ok "the mirror holds the pushed commit" || bad "the mirror holds the pushed commit"
answer=$(GIT_SSH_COMMAND="$T/stand-in-ssh" GIT_SSH_VARIANT=simple git -C "$T/src" ls-remote "$remote" "refs/pins/$sha" 2>/dev/null)
[ "$answer" = "$(printf '%s\trefs/pins/%s' "$sha" "$sha")" ] && ok "a ref read answers the pin" || bad "a ref read answers the pin ($answer)"

# Commands the shell refuses.
refused "git-upload-archive is refused" "git-upload-archive '$T/mirrors/check.git'" < /dev/null
refused "a path outside the mirror root is refused" "git-receive-pack '/etc/check.git'" < /dev/null
refused "a '..' step is refused" "git-receive-pack '$T/mirrors/../mirrors/check.git'" < /dev/null
refused "an unknown mirror is refused" "git-receive-pack '$T/mirrors/none.git'" < /dev/null
refused "an unquoted path is refused" "git-receive-pack $T/mirrors/check.git" < /dev/null
refused "a name without .git is refused" "git-receive-pack '$T/mirrors/check'" < /dev/null
refused "the vendor-only key cannot push" "git-receive-pack '$T/mirrors/check.git'" --vendor-only < /dev/null
refused "any other command is refused" "rm -rf $T" < /dev/null
refused "an interactive login is refused" "" < /dev/null
git init -q --bare "$T/mirrors/borrows.git" && mkdir -p "$T/mirrors/borrows.git/objects/info" \
  && echo "$T/mirrors/check.git/objects" > "$T/mirrors/borrows.git/objects/info/alternates"
refused "a mirror that borrows objects is refused" "git-receive-pack '$T/mirrors/borrows.git'" < /dev/null
[ -d "$T" ] && ok "nothing was removed by a refused command" || bad "nothing was removed by a refused command"

# Vendored crate dirs.
make_crate() { # <name-version> [library text]: a crate dir in $T/build with its .cargo-checksum.json
  local dir=$T/build/$1
  rm -rf "$dir"; mkdir -p "$dir/src"
  printf '[package]\nname = "%s"\n' "${1%-*}" > "$dir/Cargo.toml"
  printf '%s\n' "${2:-pub fn f() {}}" > "$dir/src/lib.rs"
  python3 -I - "$dir" <<'PY'
import hashlib, json, os, sys
crate = sys.argv[1]
files = {}
for parent, _, names in os.walk(crate):
    for name in names:
        path = os.path.join(parent, name)
        with open(path, "rb") as handle:
            files[os.path.relpath(path, crate)] = hashlib.sha256(handle.read()).hexdigest()
with open(os.path.join(crate, ".cargo-checksum.json"), "w") as handle:
    json.dump({"files": files, "package": None}, handle)
PY
}
send() { tar -C "$T/build" -cf - "$1"; }

make_crate alpha-1.0.0
if send alpha-1.0.0 | run_shell "vendor-receive alpha-1.0.0" > "$T/out" 2> "$T/err"; then
  ok "a crate dir is received"
else bad "a crate dir is received ($(head -c 300 "$T/err"))"; fi
[ -f "$T/vendor/alpha-1.0.0/src/lib.rs" ] && [ "$(stat -c %a "$T/vendor/alpha-1.0.0/src/lib.rs")" = 644 ] \
  && [ "$(stat -c %a "$T/vendor/alpha-1.0.0")" = 755 ] && ok "it lands readable by the job account" || bad "it lands readable by the job account"
[ "$(run_shell vendor-list < /dev/null)" = alpha-1.0.0 ] && ok "vendor-list names it" || bad "vendor-list names it"
send alpha-1.0.0 | run_shell "vendor-receive alpha-1.0.0" > "$T/out" 2>&1 && grep -q '^present alpha-1.0.0' "$T/out" \
  && ok "the same dir again answers present" || bad "the same dir again answers present ($(head -c 200 "$T/out"))"
make_crate alpha-1.0.0 'pub fn g() {}'
send alpha-1.0.0 > "$T/build/sent.tar"; refused "a present dir is never replaced by other contents" "vendor-receive alpha-1.0.0" < "$T/build/sent.tar"
grep -q 'pub fn f' "$T/vendor/alpha-1.0.0/src/lib.rs" && ok "the present dir kept its contents" || bad "the present dir kept its contents"

make_crate beta-1.0.0 && echo extra > "$T/build/beta-1.0.0/src/unlisted.rs"
send beta-1.0.0 > "$T/build/sent.tar"; refused "a file .cargo-checksum.json does not list is refused" "vendor-receive beta-1.0.0" < "$T/build/sent.tar"
make_crate gamma-1.0.0 && echo changed >> "$T/build/gamma-1.0.0/src/lib.rs"
send gamma-1.0.0 > "$T/build/sent.tar"; refused "a file with another sha256 is refused" "vendor-receive gamma-1.0.0" < "$T/build/sent.tar"
make_crate delta-1.0.0
send delta-1.0.0 > "$T/build/sent.tar"; refused "a dir sent under another name is refused" "vendor-receive epsilon-1.0.0" < "$T/build/sent.tar"
refused "a crate name with a slash is refused" "vendor-receive ../x" < /dev/null
python3 -I - "$T/build/escape.tar" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w") as archive:
    data = b"x\n"
    info = tarfile.TarInfo("zeta-1.0.0/../../escaped")
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
PY
refused "a member that climbs out is refused" "vendor-receive zeta-1.0.0" < "$T/build/escape.tar"
python3 -I - "$T/build/link.tar" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], "w") as archive:
    info = tarfile.TarInfo("eta-1.0.0/passwd")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    archive.addfile(info)
PY
refused "a link that leaves the dir is refused" "vendor-receive eta-1.0.0" < "$T/build/link.tar"
leftover=$(find "$T/vendor" "$T/incoming" -mindepth 1 -maxdepth 1 ! -name alpha-1.0.0 | head -3)
[ -z "$leftover" ] && [ ! -e "$T/escaped" ] && ok "a refused tar leaves nothing behind" || bad "a refused tar leaves nothing behind ($leftover)"

echo "## TEST-MIRROR-SHELL pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
