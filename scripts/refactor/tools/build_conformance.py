#!/usr/bin/env python3
"""Assemble ../conformance.sh from THIS directory's rustlex.py + driver.py (the
committed source of truth — NOT the ephemeral job tmp). The python payload is
embedded verbatim; bash adds the check-7 gate.

Usage: build_conformance.py           # (re)build ../conformance.sh
       build_conformance.py --check   # assert the shipped script is fresh (else exit 1)

`--check` closes the D-2 class: it bit twice (a stale conformance.sh silently ran an
old driver). Wire it into the gate / a selftest so drift hard-fails."""
import os
import sys

SELF = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(SELF, "..", "conformance.sh"))

rustlex = open(os.path.join(SELF, "rustlex.py")).read()
driver = open(os.path.join(SELF, "driver.py")).read()

# strip rustlex CLI trailer (keep only library code)
i = rustlex.index("\ndef main(argv):")
rustlex_core = rustlex[:i].rstrip() + "\n"

# strip the driver's module docstring/import shim header up to the GLOBAL_FORBID def,
# and drop its `try: import rustlex` block (rustlex is prepended into this module).
mark = "# Guard zone (in-flight"
j = driver.index(mark)
driver_core = ("\n\n# ==== driver (checks 1-6) ====\n"
               "import collections\nimport glob\n"
               "R = sys.modules[__name__]\n\n") + driver[j:]

payload = rustlex_core + driver_core

BASH = r'''#!/usr/bin/env bash
# GPS refactor-wave conformance gate. Single source of truth: REFACTOR-MOVE-MAP-DESIGN.md D6.
#
# Usage: scripts/refactor/conformance.sh <stage-id> <base-rev>
#   <base-rev> = the commit the stage branch was cut from.
#
# Runs, in order, first failure exits non-zero (no override flag):
#   1 forbidden-zone + allowed-files      (git diff)
#   2 surface inventory: pub decls + impl headers  (widened, F3)
#   3 moved-block rustfmt byte equivalence (cfg/container disambiguated, F2)
#   4 frozen anchors
#   5 name-uniqueness across api/*.rs (api stages)
#   6 error-literal inventory (codec stages)
#   7 WORKFLOW.md gate (cargo fmt/clippy/nextest/doctest/doc/nextest-sync)
#
# Checks 1-6 are a self-contained embedded python program (no deps beyond
# python3 + rustfmt + rg/git/awk). Check 7 shells out to cargo.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <stage-id> <base-rev>" >&2
  exit 2
fi
STAGE="$1"
BASE="$2"

ROOT="$(git rev-parse --show-toplevel)"
MOVES="$ROOT/scripts/refactor/moves"
if [ ! -f "$MOVES/$STAGE.tsv" ]; then
  echo "no manifest: $MOVES/$STAGE.tsv" >&2
  exit 2
fi

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
PAYLOAD="$TMPD/conformance_checks.py"
# extract the embedded python payload (between the PYEOF markers below)
sed -n '/^#PYEOF_BEGIN$/,/^#PYEOF_END$/p' "$0" | sed '1d;$d' | sed 's/^#>//' > "$PAYLOAD"

echo "== conformance $STAGE (base $BASE) =="
python3 "$PAYLOAD" checks "$ROOT" "$STAGE" "$BASE" "$MOVES"

# ---- check 7: the WORKFLOW.md gate (WORKFLOW.md:44-49, de-rtk'd) ----
echo "== check 7: WORKFLOW.md gate =="
cd "$ROOT"
export CARGO_TARGET_DIR="$ROOT/target"
run() { echo "+ $*"; "$@"; }
run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features -- -D warnings
run cargo nextest run --workspace --all-features --profile full
run cargo test --doc --workspace --exclude oneiron-bench --all-features
run env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
run cargo nextest run -p oneiron --features sync --profile full
echo "OK check 7 (WORKFLOW gate)"

echo "== CONFORMANCE GREEN for $STAGE =="
exit 0

# The python payload is stored below, each line prefixed with '#>' so bash never
# parses it. conformance.sh extracts + de-prefixes it at run time.
#PYEOF_BEGIN
__PAYLOAD__
#PYEOF_END
'''

# prefix every payload line with '#>' so bash ignores it; guard against a
# payload line that is exactly a marker.
pref = "\n".join("#>" + ln for ln in payload.split("\n"))
script = BASH.replace("__PAYLOAD__", pref)


def _embedded_payload(text):
    lines = text.split("\n")
    try:
        a = lines.index("#PYEOF_BEGIN") + 1
        b = lines.index("#PYEOF_END")
    except ValueError:
        return None
    return "\n".join(ln[2:] if ln.startswith("#>") else ln for ln in lines[a:b])


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        cur = open(OUT).read() if os.path.exists(OUT) else ""
        if _embedded_payload(cur) != payload:
            print(f"STALE: {OUT} does not embed the current rustlex.py+driver.py — "
                  f"run build_conformance.py and commit.", file=sys.stderr)
            sys.exit(1)
        print("FRESH: conformance.sh embeds the current rustlex+driver payload")
        sys.exit(0)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(script)
    os.chmod(OUT, 0o755)
    print(f"wrote {OUT} ({len(script)} bytes, payload {payload.count(chr(10))} lines)")
