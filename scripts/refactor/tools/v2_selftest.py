#!/usr/bin/env python3
"""Synthetic proof of the v2 conformance checks (edit / check8 / comment /
flat-name / HEAD-src removal / exhaustion / filemove) on constructed trees."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R
import driver as D

# --- BASE tree ---
BASE = {}
BASE["crates/oneiron/src/types.rs"] = '''\
//! types
use crate::foo::Bar;

pub const ENTITY_TYPE_CLAIM: u8 = 1;

// orphan interstitial comment
// spanning two lines
pub const ENTITY_TYPE_TURN: u8 = 2;

pub struct Foo {
    pub a: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo_is_fine() {
        assert_eq!(ENTITY_TYPE_CLAIM, 1);
    }
}
'''

BASE["crates/oneiron/src/affect.rs"] = '''\
//! affect
use crate::x::Y;

pub struct Vad {
    pub v: f32,
}

impl Vad {
    pub fn zero() -> Self {
        Self { v: 0.0 }
    }
}

#[cfg(test)]
mod tests;
'''

BASE["crates/oneiron/src/consumer.rs"] = '''\
//! consumer
pub fn use_it() -> u8 {
    crate::types::ENTITY_TYPE_CLAIM
}
'''

BASE["crates/oneiron/src/lib.rs"] = '''\
//! lib
pub mod types;
pub mod affect;
pub mod consumer;

pub use crate::types::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN, Foo};
pub use crate::affect::Vad;
'''

# --- HEAD tree: registry.rs new; ENTITY_TYPE_* + comment moved there; Foo -> affect.rs;
#     consumer re-pointed; lib re-pointed. ---
HEAD = dict(BASE)
HEAD["crates/oneiron/src/registry.rs"] = '''\
//! registry
pub const ENTITY_TYPE_CLAIM: u8 = 1;

// orphan interstitial comment
// spanning two lines
pub const ENTITY_TYPE_TURN: u8 = 2;
'''

HEAD["crates/oneiron/src/types.rs"] = '''\
//! types
use crate::foo::Bar;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo_is_fine() {
        assert_eq!(crate::registry::ENTITY_TYPE_CLAIM, 1);
    }
}
'''

HEAD["crates/oneiron/src/affect.rs"] = '''\
//! affect
use crate::x::Y;

pub struct Vad {
    pub v: f32,
}

impl Vad {
    pub fn zero() -> Self {
        Self { v: 0.0 }
    }
}

pub struct Foo {
    pub a: u32,
}

#[cfg(test)]
mod tests;
'''

HEAD["crates/oneiron/src/consumer.rs"] = '''\
//! consumer
pub fn use_it() -> u8 {
    crate::registry::ENTITY_TYPE_CLAIM
}
'''

HEAD["crates/oneiron/src/lib.rs"] = '''\
//! lib
pub mod types;
pub mod affect;
pub mod consumer;
pub mod registry;

pub use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
pub use crate::affect::{Foo, Vad};
'''

TSV = """\
const\t-\tENTITY_TYPE_CLAIM\t-\tcrates/oneiron/src/types.rs\tcrates/oneiron/src/registry.rs\tno
const\t-\tENTITY_TYPE_TURN\t-\tcrates/oneiron/src/types.rs\tcrates/oneiron/src/registry.rs\tno
struct\t-\tFoo\t-\tcrates/oneiron/src/types.rs\tcrates/oneiron/src/affect.rs\tno
"""

DECLS = """\
## crate
crates/oneiron
## allowed
crates/oneiron/src/types.rs
crates/oneiron/src/registry.rs
crates/oneiron/src/affect.rs
crates/oneiron/src/consumer.rs
crates/oneiron/src/lib.rs
## decl
- pub use crate :: types :: { ENTITY_TYPE_CLAIM , ENTITY_TYPE_TURN , Foo }
- pub use crate :: affect :: Vad
+ pub use crate :: registry :: { ENTITY_TYPE_CLAIM , ENTITY_TYPE_TURN }
+ pub use crate :: affect :: { Foo , Vad }
+ pub mod registry
## edit
crates/oneiron/src/consumer.rs\tcrate::types::ENTITY_TYPE_CLAIM\tcrate::registry::ENTITY_TYPE_CLAIM
## comment
crates/oneiron/src/types.rs:6-7\tcrates/oneiron/src/registry.rs
## add
crates/oneiron/src/registry.rs\t//! registry
"""


def run():
    import os
    d = "/Users/olety/.claude-pink/jobs/0b1ef39f/tmp/v2moves"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/synth.tsv", "w").write(TSV)
    open(f"{d}/synth.decls", "w").write(DECLS)

    D.base_file = lambda root, base, path: BASE.get(path)
    D.head_file = lambda root, path: HEAD.get(path)
    D.changed_files = lambda root, base: sorted(set(BASE) | set(HEAD))
    import glob as _g
    D.glob.glob = lambda pat: []
    try:
        for line in D.run_checks("/root", "synth", "BASE", d):
            print("  ", line)
        print("  ==> synth: PASSED")
        return True
    except D.Violation as v:
        print(f"  ==> synth FAILED at check {v.check}:\n{v}")
        return False


def edit_props():
    """edit_delta_ok boundary properties (comment-interior frag-edit class,
    #423 comment-atomic residual): interiors obey the same strict path rules;
    marker changes and non-path deltas still fail."""
    cases = [
        # the code-level re-point class is untouched by the wrapper
        (R.edit_delta_ok("crate::types::EntityId", "crate::entity_id::EntityId"),
         "code path re-point still legal"),
        # the ForeignWorldId doctest class: interior path re-point is legal
        (R.edit_delta_ok("/// use oneiron::types::{EntityId, ForeignWorldId};",
                         "/// use oneiron::entity_id::{EntityId, ForeignWorldId};"),
         "doc-comment interior path re-point legal"),
        # interior delta that is not a pure path segment stays illegal
        (not R.edit_delta_ok("/// use oneiron::types::{EntityId};",
                             "/// use oneiron::entity_id::{Other};"),
         "doc-comment non-path interior delta rejected"),
        # comment-marker change is not a legal declared edit
        (not R.edit_delta_ok("/// use oneiron::types::EntityId;",
                             "// use oneiron::entity_id::EntityId;"),
         "comment-marker change rejected"),
        # a no-op comment edit is still not a valid declared edit
        (not R.edit_delta_ok("/// same text", "/// same text"),
         "no-op comment edit rejected"),
        # comment text may not smuggle a widening: `pub` insertion inside a
        # comment interior is still not path-shaped
        (not R.edit_delta_ok("/// fn f()", "/// pub fn f()"),
         "interior pub insertion rejected"),
        # code-line exceptions must NOT leak into comment interiors
        # (Qodo/Codex on #426): string swaps and vis promotion are code
        # classes; comment deltas are path re-points ONLY
        (not R.edit_delta_ok('/// "old"', '/// "new"'),
         "interior string-literal swap rejected"),
        (not R.edit_delta_ok("///", "/// pub(crate)"),
         "interior pub(crate) promotion rejected"),
        # ...while both exceptions stay legal on real code lines
        (R.edit_delta_ok('include_str!("../a.md")', 'include_str!("../../a.md")'),
         "code string-literal swap still legal"),
        (R.edit_delta_ok("fn f()", "pub(crate) fn f()"),
         "code pub(crate) promotion still legal"),
    ]
    ok = True
    for good, name in cases:
        print("  ", "ok" if good else "FAIL", "edit:", name)
        ok = ok and good
    return ok


def check6_props():
    """check 6 combined-multiset properties: a literal MOVING between listed
    files (dst may be new) nets out; a changed literal still fails."""
    lit = 'Error::InvariantViolation("structural edges are append-only")'
    moved_base = {"src.rs": f"fn a() {{ {lit}; }}", "dst.rs": None}
    moved_head = {"src.rs": "fn a() {}", "dst.rs": f"fn b() {{ {lit}; }}"}
    changed_head = {"src.rs": "fn a() {}",
                    "dst.rs": 'fn b() { Error::InvariantViolation("reworded"); }'}
    saved = (D.base_file, D.head_file)
    ok = True
    try:
        decls = {"error-literal": ["src.rs", "dst.rs"]}
        D.base_file = lambda r, b, p: moved_base.get(p)
        D.head_file = lambda r, p: moved_head.get(p)
        try:
            D.check6("/r", "B", decls)
            good = True
        except D.Violation:
            good = False
        print("  ", "ok" if good else "FAIL", "check6: moved literal nets to zero")
        ok = ok and good
        D.head_file = lambda r, p: changed_head.get(p)
        try:
            D.check6("/r", "B", decls)
            good = False
        except D.Violation:
            good = True
        print("  ", "ok" if good else "FAIL", "check6: reworded literal still fails")
        ok = ok and good
    finally:
        D.base_file, D.head_file = saved
    return ok


def canon_props():
    """Canon boundary properties (#421 fallback hardening): the reflow
    tolerance must not equate semantically distinct token streams."""
    cases = [
        # rustfmt vertical reflow still invisible (trailing comma at EOL)
        (R.canon("foo(a, b)") == R.canon("foo(\n    a,\n    b,\n)"),
         "vertical-reflow trailing comma tolerated"),
        # same-line one-tuple comma is semantic: (y,) != (y)
        (R.canon("let x = (y,);") != R.canon("let x = (y);"),
         "same-line one-tuple comma kept"),
        # a // comment cannot swallow the next line when streams are joined
        (R.canon("foo(); // note\nbar();") != R.canon("foo(); // note bar();"),
         "line-comment boundary kept"),
        # comment text never matches a code-token stream (check E old-line probe)
        (" " + R.canon("let x = crate::types::Foo;") + " " not in
         " " + R.canon("/// let x = crate::types::Foo;\nlet x = crate::registry::Foo;") + " ",
         "doc-comment text is not code"),
        # single-arg CALL vertical reflow tolerated (rustfmt adds the comma)
        (R.canon("f(x)") == R.canon("f(\n    x,\n)"),
         "single-arg call vertical reflow tolerated"),
        # vertically-wrapped one-TUPLE comma is semantic (non-call parens)
        (R.canon("let t = (\n    y,\n);") != R.canon("let t = (\n    y\n);"),
         "vertical one-tuple comma kept"),
        # keyword before parens = expression position, comma semantic
        (R.canon("return (\n    y,\n);") != R.canon("return (y);"),
         "keyword-position tuple comma kept"),
        # single-element bracket list reflow still tolerated
        (R.canon("vec![x]") == R.canon("vec![\n    x,\n]"),
         "single-element vec! reflow tolerated"),
        # macro-call arg list reflow tolerated (`!` is call position)
        (R.canon('m!("a", b)') == R.canon('m!(\n    "a",\n    b,\n)'),
         "macro-call reflow tolerated"),
        # nested block comments lex atomically — interior never leaks as code
        (" " + R.canon("let x = (y,);") + " " not in
         " " + R.canon("/* o /* i */ let x = (y,); */\nfn f() {}") + " ",
         "nested block comment does not leak code"),
        # a \-newline continuation inside a string must not desync quote
        # pairing: code tokens AFTER the string stay visible as code (T4)
        (" a :: B :: AssignedTo " in
         " " + R.canon('assert_eq!(x, "a \\\n b"); h(a::B::AssignedTo, &d);') + " ",
         "string line-continuation does not swallow code"),
    ]
    ok = True
    for good, name in cases:
        print("  ", "ok" if good else "FAIL", "canon:", name)
        ok = ok and good
    return ok


if __name__ == "__main__":
    import subprocess
    # D-2 freshness guard: the shipped conformance.sh must embed the CURRENT
    # rustlex.py + driver.py (a stale gate silently ran an old driver — twice).
    print("### freshness: conformance.sh embeds current rustlex+driver")
    fr = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__),
                        "build_conformance.py"), "--check"])
    print("### canon boundary properties (reflow-fallback hardening):")
    cp = canon_props()
    print("### edit_delta_ok boundary properties (comment-interior frag-edits):")
    ep = edit_props()
    print("### check 6 combined-multiset properties (move-into-new-file netting):")
    c6 = check6_props()
    print("### v2 synthetic (move-to-new-file + insertion + edit + comment + flat-name):")
    ok = cp and ep and c6 and run() and fr.returncode == 0
    print("\nRESULT:", "PASS" if ok else "PROBLEM")
    sys.exit(0 if ok else 1)
