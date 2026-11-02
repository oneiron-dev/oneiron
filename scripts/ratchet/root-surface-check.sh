#!/usr/bin/env bash
# Root-surface pin: the `oneiron` crate root re-exports EXACTLY the names in
# scripts/ratchet/root-surface.txt. The list is the curated public surface
# (the 2,549 -> 281 curation, the 281 -> 288 signature closure, and every
# reviewed --regen since: 370 names as of 2026-09-08 — `wc -l` the file for
# the live count); any
# drift — growth OR shrinkage — fails this check, so every root-surface
# change is an explicit, reviewed decision.
#
# To move the pin on a real, reviewed surface change: run
#   scripts/ratchet/root-surface-check.sh --regen
# in the same PR that changes lib.rs, and say why in the PR description —
# never regenerate just to make the check pass.
#
# Extraction contract (matches the curation audit that produced the pin):
# the surface is the name set of every top-level `pub use crate::...;`
# statement in crates/oneiron/src/lib.rs — flat brace groups only,
# cfg-gated statements included, `pub mod` lines excluded (modules are
# namespace, not root surface). A top-level `pub use <module>::...;`
# re-export of a module declared in the same file counts the same way,
# normalized to the `crate::` form before `emit`.
#
# Fails CLOSED: a missing lib.rs or baseline, an empty extraction, an
# unterminated statement, a nested brace group, a `{self, ...}` group, a
# top-level `pub use` in any form other than `pub use crate::...;` or a
# declared module's `pub use <module>::...;` re-export, or any
# token that is not a plain identifier is ROOT-SURFACE-ERROR (exit 1),
# never a silent pass.
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "ROOT-SURFACE-ERROR: cannot cd to repo root"; exit 1; }
LIB="crates/oneiron/src/lib.rs"
BASE="scripts/ratchet/root-surface.txt"

die() { echo "ROOT-SURFACE-ERROR: $1"; exit 1; }

[ -f "$LIB" ] && [ -r "$LIB" ] || die "missing/unreadable $LIB"

extract() {
  awk '
    function fail(msg) {
      printf "EXTRACT-ERROR: %s\n", msg > "/dev/stderr"; failed = 1; exit 3
    }
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    function check_print(name) {
      if (name == "self" || name == "super" || name == "crate")
        fail("path keyword in a group pins the wrong name — write `pub use crate::<module>;` on its own line instead of `{" name ", ...}`")
      if (name !~ /^[A-Za-z_][A-Za-z0-9_]*$/) fail("not a plain identifier: [" name "]")
      print name
    }
    function emit(stmt,   n, parts, i, name, opens) {
      sub(/^pub use crate::/, "", stmt)
      sub(/;[[:space:]]*$/, "", stmt)
      opens = gsub(/\{/, "&", stmt)
      if (opens > 1) fail("nested brace group: " stmt)
      if (opens == 1) {
        if (stmt !~ /\}[[:space:]]*$/) fail("malformed group: " stmt)
        sub(/^[^{]*\{/, "", stmt)
        sub(/\}[[:space:]]*$/, "", stmt)
        n = split(stmt, parts, ",")
        for (i = 1; i <= n; i++) {
          name = trim(parts[i])
          if (name != "") check_print(name)
        }
      } else {
        n = split(stmt, parts, "::")
        check_print(trim(parts[n]))
      }
    }
    function countable(stmt,   line, m) {
      line = stmt
      if (line ~ /^pub use crate::/) return line
      if (line ~ /^pub use [A-Za-z_][A-Za-z0-9_]*::/) {
        m = line; sub(/^pub use /, "", m); sub(/::.*$/, "", m)
        if (m in mods) {
          sub(/^pub use [A-Za-z_][A-Za-z0-9_]*::/, "pub use crate::" m "::", line)
          return line
        }
      }
      return ""
    }
    FNR == NR {
      if ($0 ~ /^(pub(\([^)]*\))? )?mod [A-Za-z_][A-Za-z0-9_]*;/) {
        m = $0; sub(/^.*mod /, "", m); sub(/;.*$/, "", m); mods[m] = 1
      }
      next
    }
    inblk {
      stmt = stmt " " $0
      if ($0 ~ /;[[:space:]]*$/) { emit(stmt); inblk = 0 }
      next
    }
    /^pub use / {
      rewrite = countable($0)
      if (rewrite == "") fail("unsupported top-level pub use form (only `pub use crate::...;` and a declared module re-export of form `pub use <module>::...;` are countable): " $0)
      if (rewrite ~ /;[[:space:]]*$/) emit(rewrite)
      else { stmt = rewrite; inblk = 1 }
      next
    }
    END {
      if (failed) exit 3
      if (inblk) { printf "EXTRACT-ERROR: unterminated pub use statement\n" > "/dev/stderr"; exit 3 }
    }
  ' "$LIB" "$LIB"
}

current="$(extract | LC_ALL=C sort -u)"
st=$?
[ "$st" -eq 0 ] || die "extraction failed (see EXTRACT-ERROR above)"
[ -n "$current" ] || die "extraction produced no names"
count=$(printf '%s\n' "$current" | wc -l | tr -d ' ')

if [ "${1:-}" = "--regen" ]; then
  printf '%s\n' "$current" > "$BASE" || die "cannot write $BASE"
  echo "ROOT-SURFACE-REGEN: wrote $count names to $BASE"
  exit 0
fi

[ -f "$BASE" ] && [ -s "$BASE" ] || die "baseline $BASE missing/empty"
if ! d=$(diff -u "$BASE" <(printf '%s\n' "$current")); then
  printf '%s\n' "$d"
  echo "ROOT-SURFACE-FAIL: crate-root re-export set drifted from $BASE ($count names now)"
  exit 1
fi
echo "ROOT-SURFACE-OK ($count names)"
