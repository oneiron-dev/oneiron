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

# the same module flattened into one file; the mod doc travels as `//!`
SEAM_FLAT_RS = textwrap.dedent('''\
    //! Seam docs.

    pub(super) fn open() -> u8 {
        helper() + 1
    }

    fn helper() -> u8 {
        2
    }

    pub(super) struct Handle {
        pub(super) id: u8,
    }
''')

NESTED_DIR_SPLIT = {
    "mod.rs": NESTED_MOD_RS,
    "seam/mod.rs": SEAM_MOD_RS,
    "seam/open.rs": SEAM_OPEN_RS,
    "seam/handle.rs": SEAM_HANDLE_RS,
}


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


@pytest.fixture
def nested_repo(tmp_path):
    return make_repo(tmp_path, NESTED_BASE)


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


def test_clean_split_ok(repo):
    path, sha = repo
    apply_split(path, SPLIT)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert fails(r) == []
    # Alpha, impl Alpha, Kind, LIMIT, extra, count, tests::counts
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 4 children (7 items)"


def test_missing_item_fails(repo):
    path, sha = repo
    kinds = KINDS_RS.replace(
        '#[cfg(feature = "extra")]\npub fn extra() -> usize {\n    LIMIT + 1\n}\n\n', "")
    assert kinds != KINDS_RS
    apply_split(path, {**SPLIT, "kinds.rs": kinds})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f'FAIL missing fn extra #[cfg(feature = "extra")] (base {OLD}) not found in any child']
    assert r.stdout.splitlines()[-1].startswith(f"SPLIT-CHECK FAIL {OLD}: 1 problem")


def test_extra_non_plumbing_item_fails(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "kinds.rs": KINDS_RS + "\npub fn sneaky() -> u8 {\n    7\n}\n"})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL extra fn sneaky in {NEW}/kinds.rs"]


def test_extra_plumbing_is_allowed(repo):
    path, sha = repo
    kinds = (
        "#![allow(clippy::all)]\n//! kinds docs\n\n#[cfg(test)]\nuse std::fmt::Debug;\n"
        "pub(super) use super::Alpha as AlphaAlias;\nmod inner;\n" + KINDS_RS
    )
    apply_split(path, {**SPLIT, "kinds.rs": kinds})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr


def test_body_drift_fails_with_diff(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "kinds.rs": KINDS_RS.replace("LIMIT + 1", "LIMIT + 2")})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == ['FAIL body fn extra #[cfg(feature = "extra")] differs:']
    assert "  -    LIMIT + 1" in r.stdout.splitlines()
    assert "  +    LIMIT + 2" in r.stdout.splitlines()


def test_doc_comment_drift_fails(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "alpha.rs": ALPHA_RS.replace("/// Alpha docs.", "/// Alpha docs, reworded.")})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == ["FAIL body struct Alpha differs:"]


def test_visibility_change_is_info_not_fail(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "kinds.rs": KINDS_RS.replace("const LIMIT", "pub(crate) const LIMIT")})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO vis const LIMIT: private -> pub ( crate ) ({NEW}/kinds.rs)" in r.stdout.splitlines()


def test_old_file_still_present_fails(repo):
    path, sha = repo
    apply_split(path, SPLIT, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL old file still present: {OLD}"]


def test_mod_rs_missing_child_decl_fails(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "mod.rs": MOD_RS.replace("mod kinds;\n", "")})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL {NEW}/mod.rs does not declare `mod kinds;`"]


def test_mod_rs_missing_fails(repo):
    path, sha = repo
    apply_split(path, {k: v for k, v in SPLIT.items() if k != "mod.rs"})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL {NEW}/mod.rs missing"]


def test_inline_tests_moved_to_tests_rs(repo):
    path, sha = repo
    # dropping the moved test is a missing item in the tests scope
    apply_split(path, {**SPLIT, "tests.rs": "use super::*;\n"})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL missing fn counts (in tests) (base {OLD}) not found in any child"]
    # a body edit inside the moved test is caught too
    apply_split(path, {**SPLIT, "tests.rs": TESTS_RS.replace("0);", "1);")}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == ["FAIL body fn counts (in tests) differs:"]


def test_inline_tests_kept_inline_in_child(repo):
    path, sha = repo
    kinds = KINDS_RS + textwrap.dedent('''
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
    files = {k: v for k, v in SPLIT.items() if k != "tests.rs"}
    files["kinds.rs"] = kinds
    files["mod.rs"] = MOD_RS.replace("#[cfg(test)]\nmod tests;\n", "")
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 3 children (7 items)"


def test_duplicate_landing_fails(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "alpha.rs": ALPHA_RS + "\npub enum Kind {\n    A,\n    B,\n}\n"})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL duplicate enum Kind lands in {NEW}/alpha.rs, {NEW}/kinds.rs"]


def test_impl_block_split_across_children(repo):
    path, sha = repo
    alpha = ALPHA_RS.replace(
        "\n    pub(crate) fn name(&self) -> &str {\n        &self.name\n    }\n", "")
    assert alpha != ALPHA_RS
    named = "use super::Alpha;\n\nimpl Alpha {\n    pub(crate) fn name(&self) -> &str {\n        &self.name\n    }\n}\n"
    files = {**SPLIT, "alpha.rs": alpha, "named.rs": named,
             "mod.rs": MOD_RS.replace("mod kinds;", "mod kinds;\nmod named;")}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    # a method added to one part is still an extra
    files["named.rs"] = named.replace("}\n}\n", "}\n\n    fn hidden(&self) {}\n}\n")
    apply_split(path, files, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL extra method hidden of impl Alpha in {NEW}/named.rs"]


def test_unrecognised_extra_block_fails(repo):
    path, sha = repo
    apply_split(path, {**SPLIT, "kinds.rs": KINDS_RS + "\nthread_local! {\n    static X: u8 = 0;\n}\n"})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL extra unrecognised block in {NEW}/kinds.rs:21 ('thread_local! {{')"]


def test_bad_base_rev_fails_closed(repo):
    path, sha = repo
    apply_split(path, SPLIT)
    r = run_check(path, "deadbeef")
    assert r.returncode == 1
    assert r.stdout.splitlines()[-1].startswith("SPLIT-CHECK-ERROR")


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

def test_nested_mod_to_subdir_ok(nested_repo):
    """(a) bodied `mod seam` -> seam/{mod.rs, open.rs, handle.rs}; one private ->
    pub(super) promotion inside the nested mod is INFO, never FAIL."""
    path, sha = nested_repo
    apply_split(path, NESTED_DIR_SPLIT)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert f"INFO vis fn helper (in seam): private -> pub ( super ) ({NEW}/seam/handle.rs)" in lines
    assert not [ln for ln in lines if ln.startswith("INFO doc")]
    # seam::open, seam::helper, seam::Handle, run
    assert lines[-1] == f"SPLIT-CHECK OK {OLD} -> 4 children (4 items)"
    # a tests file inside the nested module is skipped (INFO) when the base
    # mod had no inline `mod tests`, exactly like the top level
    files = {**NESTED_DIR_SPLIT, "seam/mod.rs": SEAM_MOD_RS + "#[cfg(test)]\nmod tests;\n",
             "seam/tests.rs": "use super::*;\n"}
    apply_split(path, files, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO skipped {NEW}/seam/tests.rs (base mod seam had no inline `mod tests`)" in r.stdout.splitlines()


def test_nested_mod_to_flat_file_ok(nested_repo):
    """(b) bodied `mod seam` -> a single seam.rs; its `///` doc moves to `//!`
    at the top of that file, which is accepted without an INFO."""
    path, sha = nested_repo
    files = {"mod.rs": NESTED_MOD_RS.replace("/// Seam docs.\n", ""), "seam.rs": SEAM_FLAT_RS}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert not [ln for ln in lines if ln.startswith("INFO")]
    assert lines[-1] == f"SPLIT-CHECK OK {OLD} -> 2 children (4 items)"


def test_nested_mod_body_drift_fails(nested_repo):
    """(c) a fn body edited inside the nested mod is a body FAIL in scope seam."""
    path, sha = nested_repo
    apply_split(path, {**NESTED_DIR_SPLIT, "seam/open.rs": SEAM_OPEN_RS.replace("helper() + 1", "helper() + 2")})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == ["FAIL body fn open (in seam) differs:"]


def test_nested_mod_missing_item_fails(nested_repo):
    """(d) a nested item dropped on the way is missing in scope seam."""
    path, sha = nested_repo
    handle = SEAM_HANDLE_RS.replace("\npub(super) struct Handle {\n    pub(super) id: u8,\n}\n", "")
    assert handle != SEAM_HANDLE_RS
    apply_split(path, {**NESTED_DIR_SPLIT, "seam/handle.rs": handle})
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f"FAIL missing struct Handle (in seam) (base {OLD}) not found in any child"]


def test_nested_mod_cfg_dropped_fails(tmp_path):
    """(e) `#[cfg(feature = "sync")]` on the base mod must be on the new decl."""
    path, sha = make_repo(tmp_path, NESTED_BASE.replace("mod seam {", '#[cfg(feature = "sync")]\nmod seam {'))
    apply_split(path, NESTED_DIR_SPLIT)
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [f'FAIL cfg on mod seam differs: #[cfg(feature = "sync")] -> none ({NEW}/mod.rs)']
    # the same cfg on the decl is a clean split
    apply_split(path, {**NESTED_DIR_SPLIT, "mod.rs": NESTED_MOD_RS.replace(
        "mod seam;", '#[cfg(feature = "sync")]\nmod seam;')}, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr


def test_nested_mod_with_inline_tests_to_tests_rs_ok(tmp_path):
    """(f) base `mod seam { .. mod tests { .. } }` -> seam/mod.rs + seam/tests.rs."""
    inline_tests = (
        "\n    #[cfg(test)]\n    mod tests {\n        use super::*;\n\n        #[test]\n"
        "        fn opens() {\n            assert_eq!(open(), 3);\n        }\n    }\n}\n")
    base = NESTED_BASE.replace("        pub(super) id: u8,\n    }\n}\n", "        pub(super) id: u8,\n    }\n" + inline_tests)
    assert base != NESTED_BASE
    path, sha = make_repo(tmp_path, base)
    files = {**NESTED_DIR_SPLIT, "seam/mod.rs": SEAM_MOD_RS + "\n#[cfg(test)]\nmod tests;\n",
             "seam/tests.rs": "use super::*;\n\n#[test]\nfn opens() {\n    assert_eq!(open(), 3);\n}\n"}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 5 children (5 items)"
    # the moved test is compared 1:1 in scope seam::tests
    apply_split(path, {**files, "seam/tests.rs": files["seam/tests.rs"].replace("3);", "4);")}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == ["FAIL body fn opens (in seam::tests) differs:"]


def test_two_level_nesting_ok(tmp_path):
    """(g) base `mod a { mod b { fn f() {} } }` -> a/mod.rs declaring `mod b;` + a/b.rs."""
    path, sha = make_repo(tmp_path, "mod a {\n    mod b {\n        fn f() {}\n    }\n}\n")
    files = {"mod.rs": "mod a;\n", "a/mod.rs": "mod b;\n", "a/b.rs": "fn f() {}\n"}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 3 children (1 items)"
    # the nested mod.rs must declare its child, and the base `mod b` record
    # then has no counterpart
    apply_split(path, {**files, "a/mod.rs": "//! a\n"}, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [
        f"FAIL {NEW}/a/mod.rs does not declare `mod b;`",
        f"FAIL missing mod b (in a) (base {OLD}) not found in any child",
    ]


def test_nested_mod_extra_and_doc_drift(nested_repo):
    """A new-side module the base never had is FAIL extra; a reworded mod doc
    that is neither on the decl nor at the top of the module file is INFO."""
    path, sha = nested_repo
    files = {**NESTED_DIR_SPLIT, "mod.rs": NESTED_MOD_RS.replace("/// Seam docs.", "/// Seam docs, reworded.")}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO doc on mod seam moved/changed ({NEW}/mod.rs)" in r.stdout.splitlines()
    files = {**NESTED_DIR_SPLIT, "mod.rs": NESTED_MOD_RS.replace("mod seam;", "mod seam;\nmod extra;"),
             "extra/mod.rs": "//! nothing here\n",
             "seam/open.rs": SEAM_OPEN_RS + "\nmod hidden {\n    fn h() {}\n}\n"}
    apply_split(path, files, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == [
        f"FAIL extra mod extra in {NEW}/mod.rs",
        f"FAIL extra mod hidden (in seam) in {NEW}/seam/open.rs",
        f"FAIL extra fn h (in seam::hidden) in {NEW}/seam/open.rs",
    ]



# --- pre-existing children, 2018-layout directories, decl placement, modes ----

OLD_RS = "pub fn old_fn() -> u8 {\n    1\n}\n"


def test_pre_existing_child(tmp_path):
    """A child that already existed at base: unchanged -> skipped (INFO) and
    exempt from the declaration check; re-plumbed -> INFO; an item moved into
    it from the old file is matched by the main compare; a body edit is a
    FAIL against its own base version."""
    base = BASE.replace("use std::collections::HashMap;", "mod old;\n\nuse std::collections::HashMap;")
    path, sha = make_repo(tmp_path, base, extra={f"{NEW}/old.rs": OLD_RS})
    files = {**SPLIT, "mod.rs": MOD_RS.replace("mod alpha;", "mod alpha;\nmod old;")}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert f"INFO skipped {NEW}/old.rs (pre-existing, unchanged)" in lines
    assert lines[-1] == f"SPLIT-CHECK OK {OLD} -> 5 children (7 items)"
    # no declaration needed: it was declared before the split
    apply_split(path, SPLIT, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    # imports re-plumbed only
    (path / NEW / "old.rs").write_text("use super::Alpha;\n\n" + OLD_RS)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO pre-existing child re-plumbed: {NEW}/old.rs" in r.stdout.splitlines()
    # an item of the old file landing in the pre-existing child is still 1:1
    kinds = KINDS_RS.replace("pub enum Kind {\n    A,\n    B,\n}\n\n", "")
    assert kinds != KINDS_RS
    apply_split(path, {**files, "kinds.rs": kinds, "old.rs": OLD_RS + "\npub enum Kind {\n    A,\n    B,\n}\n"},
                remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO pre-existing child re-plumbed: {NEW}/old.rs (+1 items moved in)" in r.stdout.splitlines()
    # a body edit inside the pre-existing child
    apply_split(path, {**files, "old.rs": OLD_RS.replace("1\n", "2\n")}, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 1
    assert fails(r) == ["FAIL body fn old_fn differs:"]


def test_subdir_owned_by_sibling_file(repo):
    """Rust-2018 layout: `tests.rs` owns `tests/regressions.rs` (no mod.rs);
    its files are children of that module in the owner's scope and must be
    declared from the owner. A directory with neither a mod.rs nor a sibling
    file is an orphan."""
    path, sha = repo
    files = {**SPLIT, "tests.rs": "use super::*;\n\nmod regressions;\n",
             "tests/regressions.rs": TESTS_RS}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 5 children (7 items)"
    apply_split(path, {**files, "tests.rs": "use super::*;\n"}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL {NEW}/tests.rs does not declare `mod regressions;`"]
    apply_split(path, {**files, "orphan/x.rs": "fn x() {}\n"}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL orphan directory {NEW}/orphan (no mod.rs and no sibling orphan.rs)"]


def test_decl_in_any_file_and_path_attr(repo):
    """A sibling counts as declared by a `#[path = "x.rs"] mod y;` or a plain
    `mod x;` in any file of the directory, not only mod.rs."""
    path, sha = repo
    files = {**SPLIT, "mod.rs": MOD_RS.replace("mod kinds;\n", ""),
             "alpha.rs": '#[path = "kinds.rs"]\nmod kinds_mounted;\n\n' + ALPHA_RS}
    apply_split(path, files)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    apply_split(path, {**files, "alpha.rs": "mod kinds;\n\n" + ALPHA_RS}, remove_old=False)
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr


def test_single_file_mode(repo):
    """The last argument may be one `.rs` file: the old file is compared
    against it 1:1 with no mod.rs / sibling checks."""
    path, sha = repo
    (path / OLD).unlink()
    (path / "src/moved").mkdir()
    new = "src/moved/big_moved.rs"
    body = BASE.replace("//! Big module docs.\n#![allow(dead_code)]\n\n", "")
    (path / new).write_text("//! moved\n#![allow(dead_code)]\n\nuse crate::Nothing;\n" + body)
    r = run_check(path, sha, new=new)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD} -> 1 children (7 items)"
    (path / new).write_text((path / new).read_text().replace("LIMIT + 1", "LIMIT + 2"))
    r = run_check(path, sha, new=new)
    assert fails(r) == ['FAIL body fn extra #[cfg(feature = "extra")] differs:']


def test_two_old_files_into_one_dir(tmp_path):
    """Comma-separated old files: one directory absorbs more than one base file."""
    other = "pub fn other() -> u8 {\n    9\n}\n"
    path, sha = make_repo(tmp_path, BASE, extra={"src/other.rs": other})
    (path / "src/other.rs").unlink()
    apply_split(path, {**SPLIT, "mod.rs": MOD_RS.replace("mod kinds;", "mod kinds;\nmod other;"), "other.rs": other})
    r = run_check(path, sha, old=f"{OLD},src/other.rs")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"SPLIT-CHECK OK {OLD},src/other.rs -> 5 children (8 items)"
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL extra fn other in {NEW}/other.rs"]


def test_base_child_module_absorbed(tmp_path):
    """A child module the old file mounted at base (`#[path = ".."] mod y;`)
    whose file is gone from the tree is part of the split's source; while the
    file is still there, its copy in the new dir is an extra."""
    public = "pub fn public_fn() -> u8 {\n    4\n}\n"
    base = BASE.replace("use std::collections::HashMap;",
                        '#[path = "big_public.rs"]\nmod public;\n\nuse std::collections::HashMap;')
    path, sha = make_repo(tmp_path, base, extra={"src/big_public.rs": public})
    files = {**SPLIT, "mod.rs": MOD_RS.replace("mod kinds;", "mod kinds;\nmod public;"), "public.rs": public}
    apply_split(path, files)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL extra fn public_fn in {NEW}/public.rs"]
    (path / "src/big_public.rs").unlink()
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert f"INFO absorbed src/big_public.rs (child module of {OLD} at base, gone from the tree)" in lines
    assert lines[-1] == f"SPLIT-CHECK OK {OLD} -> 5 children (8 items)"


LIFETIME_BASE = textwrap.dedent('''\
    pub struct S<'a> {
        pub s: &'a str,
    }

    impl<'a> S<'a> {
        fn f(&self) {}

        fn g(&self) {}
    }
''')


def test_impl_header_lifetime_elided(tmp_path):
    """`impl<'a> S<'a>` and `impl S<'_>` are the same header: a split part
    that uses the lifetime nowhere else must be written elided (the
    single_use_lifetimes lint), so the parts pair and the respelling is INFO."""
    path, sha = make_repo(tmp_path, LIFETIME_BASE)
    a = "pub struct S<'a> {\n    pub s: &'a str,\n}\n\nimpl<'a> S<'a> {\n    fn f(&self) {}\n}\n"
    b = "use super::S;\n\nimpl S<'_> {\n    fn g(&self) {}\n}\n"
    apply_split(path, {"mod.rs": "mod a;\nmod b;\n\npub use a::S;\n", "a.rs": a, "b.rs": b})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    assert f"INFO impl header lifetime elided: impl S < ' _ > ({NEW}/b.rs)" in lines
    assert lines[-1] == f"SPLIT-CHECK OK {OLD} -> 3 children (2 items)"
    # the whole impl respelled in one child pairs the same way
    one = a.replace("impl<'a> S<'a> {\n    fn f(&self) {}\n}\n", "impl S<'_> {\n    fn f(&self) {}\n\n    fn g(&self) {}\n}\n")
    assert one != a
    apply_split(path, {"mod.rs": "mod a;\n\npub use a::S;\n", "a.rs": one}, remove_old=False)
    (path / NEW / "b.rs").unlink()
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"INFO impl header lifetime elided: impl S < ' _ > ({NEW}/a.rs)" in r.stdout.splitlines()
    # a dropped method is still caught under the elided pairing
    apply_split(path, {"a.rs": one.replace("\n    fn g(&self) {}\n", "")}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == [f"FAIL missing method g of impl < ' a > S < ' a > (base {OLD}) not found in any child"]


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


def test_indented_literal_moved_with_the_code_fails(tmp_path):
    """A plain string whose continuation lines sit at the code's indentation
    (8, inside `mod tests`) moved to tests.rs: re-indenting them to 4 along
    with the code is FAIL body (the old dedent equalised both sides); keeping
    them at 8 is OK although the code around them moved to 0."""
    literal = '"alpha\n        beta\n        gamma"'
    path, sha = make_repo(tmp_path, _literal_base(literal))
    apply_split(path, {"mod.rs": LITERAL_MOD_RS, "tests.rs": _literal_tests_rs(literal)})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    apply_split(path, {"tests.rs": _literal_tests_rs(_reindent_continuation(literal, -4))}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == LITERAL_FAIL


def test_string_continuation_whitespace_is_not_content(tmp_path):
    """After a `\\`-newline in a non-raw string the compiler skips the next
    line's leading whitespace, so a mover re-indenting that line is not a
    change; a word added on it is."""
    path, sha = make_repo(tmp_path, _literal_base('"alpha \\\n        beta"'))
    apply_split(path, {"mod.rs": LITERAL_MOD_RS, "tests.rs": _literal_tests_rs('"alpha \\\n    beta"')})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    apply_split(path, {"tests.rs": _literal_tests_rs('"alpha \\\n    beta gamma"')}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == LITERAL_FAIL


LITERAL_IMPL_BASE = (
    "pub struct S;\n\nimpl S {\n    pub fn text(&self) -> &'static str {\n"
    "        \"line one\n    line two\"\n    }\n\n    pub fn n(&self) -> u8 {\n        1\n    }\n}\n"
)


def test_split_impl_method_literal_is_byte_exact(tmp_path):
    """The per-method compare of an impl split across children (rustfmt in
    a dummy impl + 4-space de-wrap) keeps a method's multi-line literal
    byte-exact: stripping the 4 spaces of its continuation line is FAIL."""
    path, sha = make_repo(tmp_path, LITERAL_IMPL_BASE)
    a = ("pub struct S;\n\nimpl S {\n    pub fn text(&self) -> &'static str {\n"
         "        \"line one\n    line two\"\n    }\n}\n")
    b = "use super::S;\n\nimpl S {\n    pub fn n(&self) -> u8 {\n        1\n    }\n}\n"
    apply_split(path, {"mod.rs": "mod a;\nmod b;\n\npub use a::S;\n", "a.rs": a, "b.rs": b})
    r = run_check(path, sha)
    assert r.returncode == 0, r.stdout + r.stderr
    apply_split(path, {"a.rs": a.replace("\n    line two\"", "\nline two\"")}, remove_old=False)
    r = run_check(path, sha)
    assert fails(r) == ["FAIL body method text of impl S differs:"]


def test_string_spans_and_placeholders():
    """The scanner finds raw strings with any `#` count (an inner `"#` does
    not close `r##`), byte strings with escapes and plain strings, and skips
    comments and the `'"'` char literal; placeholders round-trip and a lost
    one fails closed."""
    src = ('let a = r##"x "# y\n"z"##; let c = \'"\'; // "comment\n'
           'let b = b"q\\"w"; /* "no" */ let l: &\'a str = "ok\n  two";')
    assert [src[s:e] for s, e in sc.string_spans(src)] == ['r##"x "# y\n"z"##', 'b"q\\"w"', '"ok\n  two"']
    protected, lits = sc.protect_literals(src)
    assert protected == ('let a = "@@SPLIT-CHECK-LITERAL-0@@"; let c = \'"\'; // "comment\n'
                         'let b = "@@SPLIT-CHECK-LITERAL-1@@"; /* "no" */ let l: &\'a str = "@@SPLIT-CHECK-LITERAL-2@@";')
    assert sc.restore_literals(protected, lits) == src
    with pytest.raises(RuntimeError):
        sc.restore_literals(protected.replace('"@@SPLIT-CHECK-LITERAL-1@@"', '""'), lits)


def test_dedent_and_canon_keep_literals():
    """_dedent strips the code margin only; _canon keeps a raw string's
    interior (canon alone re-lexes it); literal_compare_form skips exactly
    the whitespace the compiler skips after a `\\`-newline."""
    body = '    fn f() {\n        let y = r#"\nresults:\n  - id: a\n"#;\n        let z = "a\n    b";\n    }\n'
    assert sc._dedent(body) == 'fn f() {\n    let y = r#"\nresults:\n  - id: a\n"#;\n    let z = "a\n    b";\n}\n'
    assert sc._canon('foo(r#"a  "b"\n c"#,\n)') == 'foo ( r#"a  "b"\n c"# )'
    assert sc.literal_compare_form('"a \\\n     b"') == '"a \\\nb"'
    assert sc.literal_compare_form('r"a \\\n     b"') == 'r"a \\\n     b"'
    assert sc.literal_compare_form('"a \\\\\n  b"') == '"a \\\\\n  b"'


# --- unrecognised blocks: byte-identical twins in the base --------------------

def _chunk(canon, where, line):
    return (canon, canon.splitlines()[0], where, line)


def test_identical_base_twins_land_once_each():
    """Two byte-identical unrecognised blocks in the base (the tails of two
    `proptest!` invocations) may land one per child: not a duplicate."""
    base = [_chunk(");", OLD, 10), _chunk(");", OLD, 40)]
    new = [_chunk(");", f"{NEW}/a.rs", 5), _chunk(");", f"{NEW}/b.rs", 7)]
    assert sc.compare_chunks(base, new) == []


def test_base_twins_landing_three_times_is_a_duplicate():
    base = [_chunk(");", OLD, 10), _chunk(");", OLD, 40)]
    new = [_chunk(");", f"{NEW}/a.rs", 5), _chunk(");", f"{NEW}/b.rs", 7), _chunk(");", f"{NEW}/c.rs", 9)]
    problems = sc.compare_chunks(base, new)
    assert problems[0].startswith("FAIL duplicate unrecognised block ');' lands in")
    assert problems[-1] == f"FAIL extra unrecognised block in {NEW}/c.rs:9 (');')"


def test_single_base_block_landing_twice_is_still_a_duplicate():
    base = [_chunk(");", OLD, 10)]
    new = [_chunk(");", f"{NEW}/a.rs", 5), _chunk(");", f"{NEW}/b.rs", 7)]
    problems = sc.compare_chunks(base, new)
    assert problems == [
        f"FAIL duplicate unrecognised block ');' lands in {NEW}/a.rs:5, {NEW}/b.rs:7",
        f"FAIL extra unrecognised block in {NEW}/b.rs:7 (');')",
    ]
