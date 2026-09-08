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


def make_repo(tmp_path, base_text):
    """Throwaway repo with base_text committed at src/big.rs; returns (path, base_sha)."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / OLD).write_text(base_text)
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


def run_check(repo, base_sha):
    return subprocess.run(
        [sys.executable, str(TOOL), base_sha, OLD, NEW],
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
