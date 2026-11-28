#!/usr/bin/env bash
# oneiron_check.sh before cargo runs: the source replacement it writes from Cargo.lock, the vendor root check, the
# toolchain pick, its argument checks and its rc lines. The toolchain is a stand-in that records its calls, so no
# compiler runs and no network is needed. Needs bash, awk and sed.
# usage: bash scripts/execution-node/check/test_vendor_config.sh    (exit 0 when every case passes)
set -u -o pipefail
here=$(cd "$(dirname "$0")" && pwd)
check=$here/oneiron_check.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

lock() { # the fixture Cargo.lock: crates.io, two git sources (one with two crates), a path crate, an unused patch
  cat <<'LOCK'
version = 4

[[package]]
name = "alpha"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000001"

[[package]]
name = "beta"
version = "0.2.1"
source = "git+https://github.com/example/beta?rev=0123abc#0123abcdef0123abcdef0123abcdef0123abcd"

[[package]]
name = "beta-macros"
version = "0.2.1"
source = "git+https://github.com/example/beta?rev=0123abc#0123abcdef0123abcdef0123abcdef0123abcd"

[[package]]
name = "gamma"
version = "0.3.0"
source = "git+https://github.com/example/gamma?branch=main#89abcdef89abcdef89abcdef89abcdef89abcdef"

[[package]]
name = "localcrate"
version = "0.1.0"
dependencies = [
 "alpha",
]

[[patch.unused]]
name = "unused"
version = "9.9.9"
LOCK
}

setup() { # <channel>: a fresh job tree with the fixture lock, an empty vendor root and a stand-in toolchain
  rm -rf "$T/job"; mkdir -p "$T/job/src" "$T/job/out" "$T/job/home" "$T/job/vendor" "$T/job/toolchains/rust-1.100/bin"
  lock > "$T/job/src/Cargo.lock"
  echo 'pub fn a() {}' > "$T/job/src/lib.rs"; echo 'gone' > "$T/job/src/stale.rs"
  printf '[toolchain]\nchannel = "%s"\n' "$1" > "$T/job/src/rust-toolchain.toml"
  local bin=$T/job/toolchains/rust-1.100/bin
  printf '#!/bin/bash\necho "$*" >> "%s/cargo-calls"\necho "$PWD" >> "%s/cargo-dirs"\nif [ "$1" = check ] && [ "${STAND_IN_CHECK_RC:-0}" -ne 0 ]; then echo "error[E0001]: stand-in error"; exit "$STAND_IN_CHECK_RC"; fi\nexit 0\n' "$T/job" "$T/job" > "$bin/cargo"
  printf '#!/bin/bash\necho "rustc 1.100.0 (stand-in)"\n' > "$bin/rustc"
  cp "$bin/rustc" "$bin/rustfmt"; cp "$bin/rustc" "$bin/cargo-fmt"
  chmod +x "$bin"/*
}
fill_vendor() { local d; for d in alpha-1.0.0 beta-0.2.1 beta-macros-0.2.1 gamma-0.3.0; do
  mkdir -p "$T/job/vendor/$d"; : > "$T/job/vendor/$d/Cargo.toml"; echo '{"files":{}}' > "$T/job/vendor/$d/.cargo-checksum.json"; done; }
run_check() { # <args...>: as the job unit runs it, with a clean environment
  env -i PATH=/usr/bin:/bin HOME="$T/job/home" TMPDIR="$T/job/home" ONEIRON_JOB_OUT="$T/job/out" \
    ONEIRON_JOB_CHECKOUT="$T/job/src" ONEIRON_CHECK_TOOLCHAINS="$T/job/toolchains" ONEIRON_CHECK_VENDOR="$T/job/vendor" \
    STAND_IN_CHECK_RC="${STAND_IN_CHECK_RC:-0}" ${CACHE:+ONEIRON_JOB_CACHE=$CACHE} bash "$check" "$@" > "$T/job/stdout" 2>&1
}
expect() { # <case> <wanted rc> <grep pattern in stdout or ''> <grep pattern in verdict.json or ''>
  local name=$1 want=$2 out_pattern=$3 verdict_pattern=$4
  if [ "$rc" -ne "$want" ]; then bad "$name (rc=$rc, wanted $want: $(head -c 300 "$T/job/stdout"))"; return; fi
  if [ -n "$out_pattern" ] && ! grep -qE -- "$out_pattern" "$T/job/stdout"; then bad "$name (no '$out_pattern' in the log)"; return; fi
  if [ -n "$verdict_pattern" ] && ! grep -qE -- "$verdict_pattern" "$T/job/out/verdict.json" 2>/dev/null; then bad "$name (no '$verdict_pattern' in verdict.json)"; return; fi
  ok "$name"
}

setup 1.100
run_check packages=oneiron features=all; rc=$?
expect "an empty vendor root refuses before cargo" 2 '^## REFUSED vendor_incomplete alpha-1\.0\.0$' '"refused":"vendor_incomplete alpha-1\.0\.0"'
[ ! -e "$T/job/cargo-calls" ] && ok "no cargo ran on a refusal" || bad "no cargo ran on a refusal"

fill_vendor
run_check packages=oneiron,oneiron-server features=all fmt=1; rc=$?
expect "a full vendor root runs the check" 0 '^## CRATE rc=0 pkg=oneiron,oneiron-server$' '"crate_rc":0,"testcheck_rc":null,"fmt_rc":0'
config=$T/job/home/.cargo/config.toml
grep -qx 'replace-with = "oneiron-vendor"' "$config" && grep -qx "directory = \"$T/job/vendor\"" "$config" \
  && ok "crates-io reads the vendor root" || bad "crates-io reads the vendor root"
[ "$(grep -c '^\[source\."git+https://github.com/example/beta?rev=0123abc"\]$' "$config")" -eq 1 ] \
  && grep -qx 'git = "https://github.com/example/beta"' "$config" && grep -qx 'rev = "0123abc"' "$config" \
  && ok "a git source with two crates is replaced once, by its rev" || bad "a git source with two crates is replaced once, by its rev"
grep -qx '\[source\."git+https://github.com/example/gamma?branch=main"\]' "$config" && grep -qx 'branch = "main"' "$config" \
  && ok "a branch source is replaced by its branch" || bad "a branch source is replaced by its branch"
grep -qx 'offline = true' "$config" && ok "the config is offline" || bad "the config is offline"
grep -qx 'check --locked --offline -p oneiron -p oneiron-server --all-features' "$T/job/cargo-calls" \
  && grep -qx 'fmt --check -p oneiron -p oneiron-server' "$T/job/cargo-calls" \
  && ok "cargo gets --locked --offline and the packages" || bad "cargo gets --locked --offline and the packages ($(tr '\n' ';' < "$T/job/cargo-calls"))"

rm -f "$T/job/cargo-calls"
run_check packages=oneiron features=default tests=oneiron-server:lib,doors; rc=$?
expect "test files are checked under the test cfg" 0 '^## TESTCHECK rc=0 test=oneiron-server:lib,doors$' '"testcheck_rc":0'
grep -qx 'check --locked --offline -p oneiron' "$T/job/cargo-calls" && ok "features=default passes no --all-features" || bad "features=default passes no --all-features"
grep -q -- '--keep-going -p oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util --profile test --lib' "$T/job/cargo-calls" \
  && grep -q -- '--keep-going -p oneiron --all-features --test doors' "$T/job/cargo-calls" \
  && ok "a lib stem and a bare stem each get their package" || bad "a lib stem and a bare stem each get their package"

STAND_IN_CHECK_RC=101 run_check packages=oneiron; rc=$?
expect "a failing check exits with its code and keeps its errors" 101 '^## CRATE rc=101 pkg=oneiron$' '"crate_rc":101.*"errors":"error\[E0001\]: stand-in error'

run_check 'packages=a;b'; rc=$?; expect "a bad package list is refused" 2 'argument_invalid packages' ''
run_check packages=oneiron features=nightly; rc=$?; expect "a bad features value is refused" 2 'argument_invalid features' ''
run_check packages=oneiron extra=1; rc=$?; expect "an unknown argument is refused" 2 'argument_unknown extra' ''
setup 1.99; fill_vendor
run_check packages=oneiron; rc=$?; expect "a channel with no toolchain dir is refused" 2 'toolchain_missing 1\.99' '"toolchain":"1\.99"'
setup stable; fill_vendor
run_check packages=oneiron; rc=$?; expect "an unpinned channel is refused" 2 'toolchain_channel_not_pinned stable' ''
setup 1.100; fill_vendor
sed -i 's|git+https://github.com/example/gamma|git+ssh://git@example.invalid/gamma|' "$T/job/src/Cargo.lock"
run_check packages=oneiron; rc=$?; expect "a source it cannot replace is refused" 2 'source_unsupported git\+ssh' ''

# The kept cache (FIX [NODE-TEMPLATE-CACHE-DIR], default off): cargo builds a by-content copy of the checkout there.
setup 1.100; fill_vendor; mkdir -p "$T/cache"
CACHE=$T/cache run_check packages=oneiron; rc=$?
expect "a cache run builds in the cache's copy" 0 '^## CRATE rc=0 pkg=oneiron$' '"crate_rc":0'
[ "$(tail -1 "$T/job/cargo-dirs")" = "$T/cache/src" ] && cmp -s "$T/job/src/Cargo.lock" "$T/cache/src/Cargo.lock" \
  && grep -qx 'offline = true' "$T/cache/cargo-home/config.toml" && [ ! -e "$T/job/home/.cargo/config.toml" ] \
  && ok "cargo runs in the copy, with its home in the cache" || bad "cargo runs in the copy, with its home in the cache"
touch -d '2001-01-01 00:00:00' "$T/cache/src/lib.rs" "$T/cache/src/rust-toolchain.toml"
echo 'pub fn b() {}' > "$T/job/src/lib.rs"; touch -d '2000-01-01 00:00:00' "$T/job/src/lib.rs"; rm "$T/job/src/stale.rs"
CACHE=$T/cache run_check packages=oneiron; rc=$?
grep -q 'pub fn b' "$T/cache/src/lib.rs" && [ "$(stat -c %Y "$T/cache/src/lib.rs")" -gt "$(date -d '2001-01-02' +%s)" ] \
  && ok "a changed file is copied with a fresh time, though the checkout's time is older" \
  || bad "a changed file is copied with a fresh time, though the checkout's time is older"
[ "$(stat -c %Y "$T/cache/src/rust-toolchain.toml")" -eq "$(date -d '2001-01-01 00:00:00' +%s)" ] \
  && ok "an unchanged file keeps its time in the copy" || bad "an unchanged file keeps its time in the copy"
[ ! -e "$T/cache/src/stale.rs" ] && ok "a file the head removed leaves the copy" || bad "a file the head removed leaves the copy"
CACHE=$T/no-such-cache run_check packages=oneiron; rc=$?
expect "an unusable cache is refused" 2 'cache_unusable' ''

echo "## TEST-VENDOR-CONFIG pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
