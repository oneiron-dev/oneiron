"""split_check.py must accept a move-only file split and reject every drift class.

Each test builds a throwaway git repo with a base file committed, applies a
split into a directory module in the working tree, and runs the checker as a
subprocess. Needs `git` and `rustfmt` (or `RUSTFMT_BIN`) on PATH.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts/refactor/tools/split_check.py"
OLD = "src/big.rs"
NEW = "src/big"

pytestmark = pytest.mark.skipif(
    shutil.which(os.environ.get("RUSTFMT_BIN", "rustfmt")) is None,
    reason="rustfmt not on PATH",
)

BASE = textwrap.dedent('''\
    //! Big module docs.
    #![allow(dead_code)]

    use std::collections::HashMap;

    /// Alpha docs.
    #[derive(Debug, Clone)]
    pub struct Alpha {
        pub id: u64,
        name: String,
    }

    impl Alpha {
        /// Make one.
        pub fn new(id: u64, name: &str) -> Self {
            Self {
                id,
                name: name.to_string(),
            }
        }

        pub(crate) fn name(&self) -> &str {
            &self.name
        }
    }

    pub enum Kind {
        A,
        B,
    }

    const LIMIT: usize = 3;

    #[cfg(feature = "extra")]
    pub fn extra() -> usize {
        LIMIT + 1
    }

    pub fn count(map: &HashMap<u64, Alpha>) -> usize {
        map.len().min(LIMIT)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn counts() {
            let map = HashMap::new();
            assert_eq!(count(&map), 0);
        }
    }
''')

MOD_RS = textwrap.dedent('''\
    //! Big module docs.
    #![allow(dead_code)]

    mod alpha;
    mod kinds;
    #[cfg(test)]
    mod tests;

    pub use alpha::Alpha;
    #[cfg(feature = "extra")]
    pub use kinds::extra;
    pub use kinds::{count, Kind};
    pub(crate) use kinds::LIMIT;
''')

ALPHA_RS = textwrap.dedent('''\
    /// Alpha docs.
    #[derive(Debug, Clone)]
    pub struct Alpha {
        pub id: u64,
        name: String,
    }

    impl Alpha {
        /// Make one.
        pub fn new(id: u64, name: &str) -> Self {
            Self {
                id,
                name: name.to_string(),
            }
        }

        pub(crate) fn name(&self) -> &str {
            &self.name
        }
    }
''')

KINDS_RS = textwrap.dedent('''\
    use std::collections::HashMap;

    use super::Alpha;

    pub enum Kind {
        A,
        B,
    }

    const LIMIT: usize = 3;

    #[cfg(feature = "extra")]
    pub fn extra() -> usize {
        LIMIT + 1
    }

    pub fn count(map: &HashMap<u64, Alpha>) -> usize {
        map.len().min(LIMIT)
    }
''')

TESTS_RS = textwrap.dedent('''\
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn counts() {
        let map = HashMap::new();
        assert_eq!(count(&map), 0);
    }
''')

SPLIT = {"mod.rs": MOD_RS, "alpha.rs": ALPHA_RS, "kinds.rs": KINDS_RS, "tests.rs": TESTS_RS}

# --- nested directory modules: a bodied `mod seam { .. }` in the base --------

NESTED_BASE = textwrap.dedent('''\
    //! Nested docs.

    /// Seam docs.
    mod seam {
        pub(super) fn open() -> u8 {
            helper() + 1
        }

        fn helper() -> u8 {
            2
        }

        pub(super) struct Handle {
            pub(super) id: u8,
        }
    }

    pub fn run() -> u8 {
        seam::open()
    }
''')

NESTED_MOD_RS = textwrap.dedent('''\
    //! Nested docs.

    /// Seam docs.
    mod seam;

    pub fn run() -> u8 {
        seam::open()
    }
''')

SEAM_MOD_RS = textwrap.dedent('''\
    mod handle;
    mod open;

    pub(super) use handle::Handle;
    pub(super) use open::open;
''')

SEAM_OPEN_RS = textwrap.dedent('''\
    use super::handle::helper;

    pub(super) fn open() -> u8 {
        helper() + 1
    }
''')

# `helper` is promoted private -> pub(super) so open.rs can reach it
SEAM_HANDLE_RS = textwrap.dedent('''\
    pub(super) fn helper() -> u8 {
        2
    }

    pub(super) struct Handle {
        pub(super) id: u8,
    }
''')


def _git(repo, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout


def make_repo(tmp_path, base_text, extra=None):
    """Throwaway repo with base_text committed at src/big.rs (plus any `extra`
    {relpath: text} files); returns (path, base_sha)."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / OLD).write_text(base_text)
    for rel, text in (extra or {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    return repo, _git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path, BASE)


def apply_split(repo, files, remove_old=True):
    """files: {relative path under NEW: text}; nested paths create subdirs."""
    if remove_old:
        (repo / OLD).unlink()
    (repo / NEW).mkdir(exist_ok=True)
    for name, text in files.items():
        (repo / NEW / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / NEW / name).write_text(text)


def run_check(repo, base_sha, old=OLD, new=NEW):
    return subprocess.run(
        [sys.executable, str(TOOL), base_sha, old, new],
        cwd=repo, capture_output=True, text=True,
    )


def fails(result):
    return [ln for ln in result.stdout.splitlines() if ln.startswith("FAIL")]


def test_inner_visibility_promotion_is_not_a_body_change(repo):
    """A split routinely promotes a private field or method to pub(super) so a
    sibling child can reach it; that must pass (vis only), never FAIL body."""
    path, sha = repo
    alpha = ALPHA_RS.replace("    name: String,", "    pub(super) name: String,")
    alpha = alpha.replace("pub(crate) fn name(", "pub(super) fn name(")
    assert alpha != ALPHA_RS
    apply_split(path, {**SPLIT, "alpha.rs": alpha})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not [ln for ln in r.stdout.splitlines() if ln.startswith("FAIL")]


# --- nested directory modules -------------------------------------------------



# --- pre-existing children, 2018-layout directories, decl placement, modes ----


# --- string literals are compared byte-for-byte ------------------------------

sys.path.insert(0, str(TOOL.parent))
import split_check as sc  # noqa: E402


def _literal_base(literal):
    """One test in an inline `mod tests` holding `literal` (a multi-line
    string; its continuation lines sit wherever the literal puts them, the
    code around it at the usual 4 / 8)."""
    return (
        "pub fn lines(s: &str) -> usize {\n    s.lines().count()\n}\n\n"
        "#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn fixture_lines() {\n"
        "        let text = " + literal + ";\n        assert_eq!(lines(text), 3);\n    }\n}\n"
    )


def _literal_tests_rs(literal):
    return ("use super::*;\n\n#[test]\nfn fixture_lines() {\n    let text = " + literal
            + ";\n    assert_eq!(lines(text), 3);\n}\n")


def _reindent_continuation(literal, by):
    """The literal with every line after its first shifted by `by` spaces
    (negative = stripped): what a mover's blanket re-indent does to it."""
    first, *rest = literal.split("\n")
    out = [first]
    for ln in rest:
        if by >= 0:
            out.append(" " * by + ln)
        else:
            assert ln.startswith(" " * -by), ln
            out.append(ln[-by:])
    return "\n".join(out)


RAW_YAML = 'r#"\nresults:\n  - id: a\n    nested:\n      - id: b\n"#'
PLAIN_TEXT = '"alpha\n    beta\ngamma"'
RAW_TWO_HASHES = 'r##"{"a": "#",\n"b": "x"#y"}"##'
LITERAL_MOD_RS = "#[cfg(test)]\nmod tests;\n\npub fn lines(s: &str) -> usize {\n    s.lines().count()\n}\n"
LITERAL_INLINE_MOD_RS = "#[cfg(test)]\nmod fixtures;\n\npub fn lines(s: &str) -> usize {\n    s.lines().count()\n}\n"
LITERAL_FAIL = ["FAIL body fn fixture_lines (in tests) differs:"]


@pytest.mark.parametrize("literal", [RAW_YAML, PLAIN_TEXT, RAW_TWO_HASHES], ids=["raw", "plain", "raw-two-hashes"])
def test_string_literal_content_is_byte_exact(tmp_path, literal):
    """(a) the literal's continuation lines gained 4 spaces on the move ->
    FAIL body, in both landing shapes: a child that keeps an inline
    `mod tests` (both sides go through the mod-body dedent, which used to
    equalise them: the beam YAML case) and a top-level tests.rs; (b) the
    same moves with the content byte-identical while the code around it
    re-indents -> OK. (c) a plain "..\\n.." string and (d) an r##".."##
    raw string holding `"#` run through the same four checks."""
    base = _literal_base(literal)
    path, sha = make_repo(tmp_path, base)
    inline = base[base.index("#[cfg(test)]"):]  # the base mod verbatim, inside a child
    shifted = _reindent_continuation(literal, 4)
    # inline-mod child, content identical -> OK
    apply_split(path, {"mod.rs": LITERAL_INLINE_MOD_RS, "fixtures.rs": inline})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 2 children (2 items)"
    # inline-mod child, content re-indented -> FAIL
    apply_split(path, {"fixtures.rs": inline.replace(literal, shifted)}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == LITERAL_FAIL
    (path / NEW / "fixtures.rs").unlink()
    # tests.rs, code re-indented by -4, content identical -> OK
    apply_split(path, {"mod.rs": LITERAL_MOD_RS, "tests.rs": _literal_tests_rs(literal)}, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    # tests.rs, content re-indented too -> FAIL, and the diff shows the literal lines
    apply_split(path, {"tests.rs": _literal_tests_rs(shifted)}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == LITERAL_FAIL
    second = literal.split("\n")[1]  # may be the closing line, followed by `;`
    lines = r.stdout.splitlines()
    assert any(ln.startswith("  -" + second) for ln in lines)
    assert any(ln.startswith("  +    " + second) for ln in lines)


# --- unrecognised blocks: byte-identical twins in the base --------------------

def _chunk(canon, where, line):
    return (canon, canon.splitlines()[0], where, line)


def test_identical_base_twins_land_once_each():
    """Two byte-identical unrecognised blocks in the base (the tails of two
    `proptest!` invocations) may land one per child: not a duplicate."""
    base = [_chunk(");", OLD, 10), _chunk(");", OLD, 40)]
    new = [_chunk(");", f"{NEW}/a.rs", 5), _chunk(");", f"{NEW}/b.rs", 7)]
    assert sc.compare_chunks(base, new) == []


# --- items that share one key: anonymous `const _` asserts --------------------

TWIN_ASSERT_BASE = textwrap.dedent('''\
    pub struct A;
    pub struct B;

    const _: () = assert!(std::mem::size_of::<A>() == 0);
    const _: () = assert!(std::mem::size_of::<B>() == 0);
''')
TWIN_ASSERT_MOD_RS = "mod a;\nmod b;\n\npub use a::A;\npub use b::B;\n"
TWIN_ASSERT_A_RS = "pub struct A;\n\nconst _: () = assert!(std::mem::size_of::<A>() == 0);\n"
TWIN_ASSERT_B_RS = "pub struct B;\n\nconst _: () = assert!(std::mem::size_of::<B>() == 0);\n"


def test_same_key_items_pair_by_body(tmp_path):
    """Two `const _` compile-time asserts share one item key; each lands in
    the child of the type it guards. Paired by body, in any order."""
    path, sha = make_repo(tmp_path, TWIN_ASSERT_BASE)
    apply_split(path, {"mod.rs": TWIN_ASSERT_MOD_RS, "a.rs": TWIN_ASSERT_A_RS, "b.rs": TWIN_ASSERT_B_RS})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert fails(r) == []


# --- a promoted method whose longer signature rustfmt reflows -----------------

REFLOW_BASE = textwrap.dedent('''\
    pub enum WindowSyncMode {
        Unbound,
        Bound,
    }

    pub struct ProtocolError;

    pub struct ConnState {
        mode: WindowSyncMode,
    }

    impl ConnState {
        fn bind_window_sync_mode(&mut self, mode: WindowSyncMode) -> Result<(), ProtocolError> {
            self.mode = mode;
            Ok(())
        }
    }
''')
REFLOW_MOD_RS = "mod conn_state;\nmod types;\n\npub use conn_state::ConnState;\npub use types::{ProtocolError, WindowSyncMode};\n"
REFLOW_TYPES_RS = "pub enum WindowSyncMode {\n    Unbound,\n    Bound,\n}\n\npub struct ProtocolError;\n"
REFLOW_CONN_STATE_RS = textwrap.dedent('''\
    use super::types::{ProtocolError, WindowSyncMode};

    pub struct ConnState {
        mode: WindowSyncMode,
    }

    impl ConnState {
        pub(super) fn bind_window_sync_mode(
            &mut self,
            mode: WindowSyncMode,
        ) -> Result<(), ProtocolError> {
            self.mode = mode;
            Ok(())
        }
    }
''')


def test_promoted_method_reflowed_by_rustfmt_is_a_vis_change_only(tmp_path):
    """`pub(super)` pushes the method signature past the width limit, so the
    new side is reflowed onto four lines. Visibility is stripped before the
    fragment is formatted, so both sides format identically."""
    path, sha = make_repo(tmp_path, REFLOW_BASE)
    apply_split(path, {"mod.rs": REFLOW_MOD_RS, "types.rs": REFLOW_TYPES_RS, "conn_state.rs": REFLOW_CONN_STATE_RS})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert fails(r) == []


def test_base_declared_directory_child_is_plumbing(tmp_path):
    """The base file already mounted `mod step;` -> src/big/step/mod.rs. The
    split's mod.rs must keep that decl (walk_dir demands it) and the decl must
    not read as an extra mod. A directory the base never had stays extra."""
    step = "pub fn step() -> u8 {\n    2\n}\n"
    path, sha = make_repo(tmp_path, BASE + "mod step;\n", extra={"src/big/step/mod.rs": step})
    apply_split(path, {**SPLIT, "mod.rs": MOD_RS + "mod step;\n"})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert fails(r) == []
    assert f"INFO skipped {NEW}/step/mod.rs (pre-existing, unchanged)" in r.stdout.splitlines()
    # dropping the decl is still a missing declaration
    apply_split(path, {**SPLIT, "mod.rs": MOD_RS}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL {NEW}/mod.rs does not declare `mod step;`"]
    # a directory child the base never had is still an extra mod
    apply_split(path, {**SPLIT, "mod.rs": MOD_RS + "mod step;\nmod fresh;\n", "fresh/mod.rs": "//! fresh\n"},
                remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL extra mod fresh in {NEW}/mod.rs"]



# --- same-scope literal includes preserve `tests_regressions::recall::<test>` ---

INCLUDED_BASE = textwrap.dedent('''\
    //! Scope docs.

    fn marker() -> u8 {
        7
    }

    #[test]
    fn remains_at_parent_scope() {
        assert_eq!(marker(), 7);
    }
''')
INCLUDED_MOD = '//! Scope docs.\n\ninclude!("fixture.rs");\ninclude!("cases.rs");\n'
INCLUDED_FIXTURE = 'fn marker() -> u8 {\n    7\n}\n'
INCLUDED_CASES = '#[test]\nfn remains_at_parent_scope() {\n    assert_eq!(marker(), 7);\n}\n'
