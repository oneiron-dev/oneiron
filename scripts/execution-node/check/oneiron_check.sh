#!/bin/bash
# The `oneiron-check` template's entry: a cargo check of the pinned commit inside an Oneiron job unit
# (docs/ops/execution-node-mirror-and-check.md; FLEET-TOOL-PARITY kind 5).
#
# The unit gives no network (PrivateNetwork=yes), no .git (the checkout is `git archive` of the commit), HOME=TMPDIR=
# <payload>/tmp, and writes only to the payload's out, tmp and log (scope_systemd/prepare.rs exec_file). So cargo reads
# every crate from the vendored directory source $ONEIRON_CHECK_VENDOR and runs the toolchain at
# $ONEIRON_CHECK_TOOLCHAINS/rust-<channel of rust-toolchain.toml>, both read roots of the template. Nothing is fetched.
#
# Cold (no $ONEIRON_JOB_CACHE, the default): cargo builds the checkout in place, with CARGO_HOME and the targets in the
# payload's tmp, and the job leaves nothing behind. Kept cache ($ONEIRON_JOB_CACHE, a dir the unit gives one run at a
# time, FIX [NODE-TEMPLATE-CACHE-DIR], behind a setting): staging unpacks every file with the commit's time (the tar
# crate keeps each entry's mtime), so a kept target would take a changed file that is older than its last build as
# unchanged. The checkout is therefore copied by content (`rsync -rlc --delete`, no -t) into a fixed path in the cache,
# and cargo builds there, with CARGO_HOME and the targets in the cache too (the Engine's RELAY
# CHECK-SCRIPT-COPY-BY-CONTENT, 28 Nov 15:53).
#
# Arguments, each `name=value`, matched whole by the template's params:
#   packages=<pkg>[,<pkg>...]   the crates `cargo check -p` checks (required)
#   features=all|default        --all-features or the default features (default: all)
#   tests=[<pkg>:]<stem>[,...]  integration test files to check under `--cfg oneiron_test_support`; a bare stem is
#                               crates/oneiron's, the stem `lib` checks the package's lib unit tests (default: none)
#   fmt=0|1                     also `cargo fmt --check` the packages (default: 0)
#
# Output: `## CRATE rc=`, `## TESTCHECK rc=` and `## FMT rc=` lines on stdout (the job's log), and
# $ONEIRON_JOB_OUT/verdict.json. Exit 0 when every step passed; 2 when the check refused before cargo ran (the verdict's
# `refused` names why); else the first failing step's exit code.
set -u -o pipefail

PACKAGE_LIST_RE='^[a-z0-9_-]+(,[a-z0-9_-]+)*$'
TEST_LIST_RE='^([a-z0-9_-]+:)?[a-z0-9_]+(,([a-z0-9_-]+:)?[a-z0-9_]+)*$'
CHANNEL_RE='^[0-9]+\.[0-9]+(\.[0-9]+)?$'
SAFE_PATH_RE='^/[A-Za-z0-9._/-]+$'
GIT_URL_RE='^https://[A-Za-z0-9._/:@%+-]+$'
GIT_QUERY_RE='^(rev|branch|tag)=[A-Za-z0-9._-]+$'
CRATES_IO_SOURCE='registry+https://github.com/rust-lang/crates.io-index'
VENDOR_SOURCE_NAME=oneiron-vendor
# The server test files use oneiron/test-hooks and broker test-support items that --all-features never turns on in a
# dependency (the lanes' check_crate.sh, 27 Nov 06:0x).
SERVER_TEST_FEATURES=oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
ERRORS_KEPT_BYTES=65536

out=${ONEIRON_JOB_OUT:-}
checkout=${ONEIRON_JOB_CHECKOUT:-}
toolchains=${ONEIRON_CHECK_TOOLCHAINS:-}
vendor=${ONEIRON_CHECK_VENDOR:-}
cache=${ONEIRON_JOB_CACHE:-}
packages='' features=all tests='' fmt=0
channel='' rustc_version='' refused='' crate_rc=null testcheck_rc=null fmt_rc=null crate_minutes=null testcheck_minutes=null
work=''

json_str() { # one JSON string of $1: backslash, quote and control characters escaped, lines joined by \n
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
    | awk 'BEGIN { printf "\"" } NR > 1 { printf "\\n" } { printf "%s", $0 } END { printf "\"" }'
}

json_or_null() { if [ -n "$1" ]; then json_str "$1"; else printf 'null'; fi; }

write_verdict() { # <errors text>
  [ -n "$out" ] && [ -d "$out" ] || return 0
  {
    printf '{"template":"oneiron-check","packages":%s,"features":%s,"tests":%s,"fmt":%s,' \
      "$(json_or_null "$packages")" "$(json_str "$features")" "$(json_or_null "$tests")" "$fmt"
    printf '"toolchain":%s,"rustc":%s,"refused":%s,' \
      "$(json_or_null "$channel")" "$(json_or_null "$rustc_version")" "$(json_or_null "$refused")"
    printf '"crate_rc":%s,"testcheck_rc":%s,"fmt_rc":%s,"crate_minutes":%s,"testcheck_minutes":%s,"errors":%s}\n' \
      "$crate_rc" "$testcheck_rc" "$fmt_rc" "$crate_minutes" "$testcheck_minutes" "$(json_str "$1")"
  } > "$out/verdict.json"
}

refuse() { # <reason> [detail]: the check ends before cargo runs
  refused="$1${2:+ $2}"
  echo "## REFUSED $refused"
  write_verdict ""
  exit 2
}

errors_of() { # <cargo output file>...: each error with its code frame, at most ERRORS_KEPT_BYTES in all
  grep -h -E '^error' -A 14 "$@" 2>/dev/null | head -c "$ERRORS_KEPT_BYTES"
}

for arg in "$@"; do
  case $arg in
    packages=*) packages=${arg#packages=};;
    features=*) features=${arg#features=};;
    tests=*) tests=${arg#tests=};;
    fmt=*) fmt=${arg#fmt=};;
    *) refuse argument_unknown "${arg%%=*}";;
  esac
done
[[ $packages =~ $PACKAGE_LIST_RE ]] || refuse argument_invalid packages
[[ $features == all || $features == default ]] || refuse argument_invalid features
[ -z "$tests" ] || [[ $tests =~ $TEST_LIST_RE ]] || refuse argument_invalid tests
[[ $fmt == 0 || $fmt == 1 ]] || refuse argument_invalid fmt
[ -n "$out" ] && [ -d "$out" ] || refuse environment_missing ONEIRON_JOB_OUT
[ -n "$checkout" ] && [ -f "$checkout/Cargo.lock" ] || refuse checkout_has_no_cargo_lock
[[ $toolchains =~ $SAFE_PATH_RE ]] || refuse environment_missing ONEIRON_CHECK_TOOLCHAINS
[[ $vendor =~ $SAFE_PATH_RE ]] && [ -d "$vendor" ] || refuse vendor_root_missing "$vendor"
[ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ] || refuse environment_missing HOME

# The toolchain: the channel rust-toolchain.toml pins, from the read root. No rustup and no download.
channel=$(sed -n -E 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$checkout/rust-toolchain.toml" 2>/dev/null | head -1)
[[ $channel =~ $CHANNEL_RE ]] || refuse toolchain_channel_not_pinned "${channel:-none}"
tc=$toolchains/rust-$channel
[ -x "$tc/bin/cargo" ] && [ -x "$tc/bin/rustc" ] || refuse toolchain_missing "$channel"
export PATH=$tc/bin:/usr/local/bin:/usr/bin:/bin
unset RUSTUP_TOOLCHAIN RUSTUP_HOME RUSTC RUSTC_WRAPPER RUSTFLAGS CARGO_TARGET_DIR
rustc_version=$(rustc --version 2>&1 | head -1)

# Where cargo builds: the checkout in place (cold), or its by-content copy in the kept cache (see the header).
if [ -n "$cache" ]; then
  [[ $cache =~ $SAFE_PATH_RE ]] && [ -d "$cache" ] && [ -w "$cache" ] || refuse cache_unusable "$cache"
  command -v rsync > /dev/null || refuse cache_copy_tool_missing rsync
  mkdir -p "$cache/src" "$cache/cargo-home" || refuse cache_unusable "$cache"
  rsync -rlc --delete -- "$checkout/" "$cache/src/" || refuse cache_copy_failed
  build_dir=$cache/src target_dir=$cache/target test_target_dir=$cache/target-test-support
  export CARGO_HOME=$cache/cargo-home
else
  build_dir=$checkout target_dir=$HOME/target test_target_dir=$HOME/target-test-support
  export CARGO_HOME=$HOME/.cargo CARGO_INCREMENTAL=0
fi

# Cargo's own home holds only the source replacement, written at each run. crates-io and every git source of
# Cargo.lock read from the vendored directory source; a locked crate the vendor root lacks refuses here, before cargo.
export CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
work=$HOME/oneiron-check
mkdir -p "$CARGO_HOME" "$work" || refuse payload_tmp_unwritable
locked=$(awk '
  function value(line) { sub(/^[a-z]+ = "/, "", line); sub(/"[[:space:]]*$/, "", line); return line }
  function flush() { if (in_package && source != "") print name "\t" version "\t" source; in_package = 0 }
  /^\[\[package\]\]/ { flush(); in_package = 1; name = version = source = ""; next }
  /^\[/ { flush(); next }
  in_package && /^name = "/ { name = value($0) }
  in_package && /^version = "/ { version = value($0) }
  in_package && /^source = "/ { source = value($0) }
  END { flush() }
' "$checkout/Cargo.lock") || refuse cargo_lock_unreadable
{
  printf '[source.crates-io]\nreplace-with = "%s"\n\n[source.%s]\ndirectory = "%s"\n' \
    "$VENDOR_SOURCE_NAME" "$VENDOR_SOURCE_NAME" "$vendor"
} > "$CARGO_HOME/config.toml"
git_sources=''
missing=''
while IFS=$'\t' read -r name version source; do
  [ -n "$name" ] || continue
  case $source in
    "$CRATES_IO_SOURCE") ;;
    git+*)
      key=${source%%#*}
      case $'\n'"$git_sources"$'\n' in *$'\n'"$key"$'\n'*) ;; *)
        git_sources=$git_sources$'\n'$key
        url=${key#git+}; query=''
        case $url in *\?*) query=${url#*\?}; url=${url%%\?*};; esac
        [[ $url =~ $GIT_URL_RE ]] || refuse source_unsupported "$key"
        [ -z "$query" ] || [[ $query =~ $GIT_QUERY_RE ]] || refuse source_unsupported "$key"
        {
          printf '\n[source."%s"]\ngit = "%s"\n' "$key" "$url"
          [ -n "$query" ] && printf '%s = "%s"\n' "${query%%=*}" "${query#*=}"
          printf 'replace-with = "%s"\n' "$VENDOR_SOURCE_NAME"
        } >> "$CARGO_HOME/config.toml"
      ;; esac;;
    *) refuse source_unsupported "$source";;
  esac
  if [ -z "$missing" ] && ! { [ -f "$vendor/$name-$version/Cargo.toml" ] && [ -f "$vendor/$name-$version/.cargo-checksum.json" ]; }; then
    missing=$name-$version
  fi
done <<< "$locked"
[ -z "$missing" ] || refuse vendor_incomplete "$missing"
printf '\n[net]\noffline = true\n' >> "$CARGO_HOME/config.toml"

echo "## ONEIRON-CHECK toolchain=$channel ($rustc_version) vendor=$vendor cache=${cache:-none} jobs=$CARGO_BUILD_JOBS packages=$packages features=$features tests=${tests:-none} fmt=$fmt"
cd "$build_dir" || refuse checkout_unreadable
package_flags=(); for p in ${packages//,/ }; do package_flags+=(-p "$p"); done
feature_flags=(); [ "$features" = all ] && feature_flags=(--all-features)

t0=$(date +%s)
echo "## COMMAND cargo check --locked --offline ${package_flags[*]} ${feature_flags[*]}"
CARGO_TARGET_DIR=$target_dir cargo check --locked --offline "${package_flags[@]}" "${feature_flags[@]}" > "$work/crate.out" 2>&1
crate_rc=$?
errors_of "$work/crate.out" | head -240
[ "$crate_rc" -ne 0 ] && tail -25 "$work/crate.out"
crate_minutes=$(( ($(date +%s) - t0) / 60 ))
echo "## CRATE-MINUTES $crate_minutes"
echo "## CRATE rc=$crate_rc pkg=$packages"

if [ -n "$tests" ]; then
  # One check per package, each with --keep-going, so one failing target hides no other target's errors.
  t0=$(date +%s); testcheck_rc=0; test_packages=''
  for s in ${tests//,/ }; do
    pk=oneiron; case $s in *:*) pk=${s%%:*};; esac
    case " $test_packages " in *" $pk "*) ;; *) test_packages="$test_packages $pk";; esac
  done
  for pk in $test_packages; do
    targets=()
    for s in ${tests//,/ }; do
      p=oneiron; st=$s; case $s in *:*) p=${s%%:*}; st=${s#*:};; esac
      [ "$p" = "$pk" ] || continue
      if [ "$st" = lib ]; then targets+=(--profile test --lib); else targets+=(--test "$st"); fi
    done
    extra=(); [ "$pk" = oneiron-server ] && extra=(--features "$SERVER_TEST_FEATURES")
    echo "## COMMAND RUSTFLAGS=\"--cfg oneiron_test_support\" cargo check --locked --offline --keep-going -p $pk --all-features ${extra[*]} ${targets[*]}"
    RUSTFLAGS="--cfg oneiron_test_support" CARGO_TARGET_DIR=$test_target_dir \
      cargo check --locked --offline --keep-going -p "$pk" --all-features "${extra[@]}" "${targets[@]}" > "$work/testcheck-$pk.out" 2>&1
    rc=$?
    errors_of "$work/testcheck-$pk.out" | head -200
    [ "$rc" -ne 0 ] && tail -25 "$work/testcheck-$pk.out"
    echo "## TESTCHECK-PKG rc=$rc pkg=$pk"
    [ "$rc" -ne 0 ] && [ "$testcheck_rc" -eq 0 ] && testcheck_rc=$rc
  done
  testcheck_minutes=$(( ($(date +%s) - t0) / 60 ))
  echo "## TESTCHECK-MINUTES $testcheck_minutes"
  echo "## TESTCHECK rc=$testcheck_rc test=$tests"
fi

if [ "$fmt" = 1 ]; then
  echo "## COMMAND cargo fmt --check ${package_flags[*]}"
  if [ -x "$tc/bin/cargo-fmt" ] && [ -x "$tc/bin/rustfmt" ]; then
    cargo fmt --check "${package_flags[@]}" > "$work/fmt.out" 2>&1
    fmt_rc=$?
  else
    echo "the toolchain $channel has no rustfmt" > "$work/fmt.out"
    fmt_rc=127
  fi
  head -120 "$work/fmt.out"
  echo "## FMT rc=$fmt_rc pkg=$packages"
fi

error_files=("$work/crate.out"); [ -n "$tests" ] && error_files+=("$work"/testcheck-*.out)
write_verdict "$(errors_of "${error_files[@]}")"
for rc in "$crate_rc" "$testcheck_rc" "$fmt_rc"; do
  [ "$rc" != null ] && [ "$rc" -ne 0 ] && exit "$rc"
done
exit 0
