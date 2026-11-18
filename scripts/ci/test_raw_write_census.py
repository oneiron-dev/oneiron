"""Drive the raw core-write census (scripts/ratchet/raw_write_census.py) over a
disposable source tree: code that only a test build compiles (`#[cfg(test)]`,
`--cfg oneiron_test_support`) is left out of the count, and code that a release
build with some feature compiles stays in it."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ratchet/raw_write_census.py"


def load_census():
    spec = importlib.util.spec_from_file_location("raw_write_census", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_write(table):
    return f"pub fn write(v: &V) {{\n    v.store.{table}.put(&mut txn, &key, &bytes);\n}}\n"


# Each file holds raw writes on known lines; the comment names its fate.
TREE = {
    "lib.rs": """\
        //! Crate root.
        pub mod live;
        #[cfg(test)]
        mod unit_fixture;
        /// Doors from the integration tests. Not API.
        #[cfg(oneiron_test_support)]
        #[doc(hidden)]
        pub mod test_doors;
        #[cfg(any(test, oneiron_test_support))]
        pub(crate) mod either_test_build;
        #[cfg(all(oneiron_test_support, feature = "sync"))]
        mod synced_door;
        #[cfg(any(test, feature = "test-support", oneiron_test_support))]
        pub(crate) mod shipped_with_feature;
        #[cfg(not(oneiron_test_support))]
        mod release_only;
        #[cfg(feature = "sync")]
        mod synced;
        pub mod self_gated;
        """,
    # Counted: line 2. Both inline modules are masked.
    "live.rs": """\
        pub fn write(v: &V) {
            v.store.entities.put(&mut txn, &key, &bytes);
        }

        #[cfg(oneiron_test_support)]
        pub(crate) mod door {
            pub fn seed(v: &V) {
                v.store.edges_out.put(&mut txn, &key, &bytes);
            }
        }

        #[cfg(test)]
        #[allow(dead_code)]
        mod tests {
            fn wipe(v: &V) {
                v.store.type_index.delete(&mut txn, &key);
            }
        }
        """,
    "unit_fixture.rs": raw_write("entities"),
    "test_doors/mod.rs": "pub mod pins;\n" + raw_write("short_ids"),
    "test_doors/pins.rs": raw_write("edges_in"),
    "either_test_build.rs": raw_write("entities"),
    "synced_door.rs": raw_write("sync_state"),
    # Counted: `--all-features` turns `test-support` on in the release build.
    "shipped_with_feature.rs": raw_write("entities"),
    # Counted: compiled exactly when the test cfg is off.
    "release_only.rs": raw_write("entities"),
    # Counted: a feature, not a test build, decides.
    "synced.rs": raw_write("sync_state"),
    # Gated by its own inner attribute, and so is its child.
    "self_gated.rs": textwrap.dedent(
        """\
        //! A door file gated as a whole.
        #![cfg(oneiron_test_support)]
        mod child;
        """
    )
    + raw_write("entities"),
    "self_gated/child.rs": raw_write("type_index"),
}

COUNTED = [
    "crates/oneiron/src/live.rs:2",
    "crates/oneiron/src/release_only.rs:2",
    "crates/oneiron/src/shipped_with_feature.rs:2",
    "crates/oneiron/src/synced.rs:2",
]


class TestOnlyCfgPredicate(unittest.TestCase):
    def test_value_in_a_build_without_test_names(self):
        census = load_census()
        cases = {
            "test": False,
            "oneiron_test_support": False,
            "any(test, oneiron_test_support)": False,
            'all(oneiron_test_support, feature = "sync")': False,
            # `strip_comments_and_literals` blanks the literal.
            "all(oneiron_test_support, feature =       )": False,
            "all(unix, oneiron_test_support)": False,
            "all(test, any(target_os = \"linux\", target_os = \"macos\"))": False,
            "not(oneiron_test_support)": True,
            "not(not(test))": False,
            'any(test, feature = "test-support")': None,
            'any(test, feature = "test-support", oneiron_test_support)': None,
            'feature = "sync"': None,
            "unix": None,
            "not(unix)": None,
            "any()": False,
            "all()": True,
            # Text this scanner does not parse gates nothing.
            "any(test": None,
            "test oneiron_test_support": None,
            "not(test, unix)": None,
            "cfg_name(test)": None,
        }
        for predicate, expected in cases.items():
            with self.subTest(predicate=predicate):
                self.assertIs(census.cfg_value_without_test_names(predicate), expected)

    def test_attribute_runs(self):
        census = load_census()
        self.assertTrue(census.attributes_gate_test_only("#[cfg(test)]"))
        self.assertTrue(
            census.attributes_gate_test_only("#[cfg(oneiron_test_support)]#[doc(hidden)]")
        )
        self.assertTrue(census.attributes_gate_test_only("#[path=]#[cfg(oneiron_test_support)]"))
        # An inner attribute of the enclosing file gates nothing on the mount.
        self.assertFalse(census.attributes_gate_test_only("#![cfg(test)]"))
        self.assertTrue(census.attributes_gate_test_only("#![allow(dead_code)]#[cfg(test)]"))
        self.assertFalse(census.attributes_gate_test_only("#[cfg(feature=)]"))
        self.assertFalse(census.attributes_gate_test_only("#[doc(hidden)]"))
        self.assertFalse(census.attributes_gate_test_only("unsafe#[cfg(test)]"))
        self.assertFalse(census.attributes_gate_test_only(""))


class RawWriteCensusTree(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="raw-write-census-"))
        self.addCleanup(shutil.rmtree, self.repo)
        scripts = self.repo / "scripts/ratchet"
        scripts.mkdir(parents=True)
        shutil.copy(SCRIPT, scripts / SCRIPT.name)
        src = self.repo / "crates/oneiron/src"
        for rel, text in TREE.items():
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text), encoding="utf-8")

    def census(self, *args):
        return subprocess.run(
            [sys.executable, str(self.repo / "scripts/ratchet" / SCRIPT.name), *args],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def test_list_leaves_out_test_only_code(self):
        self.assertEqual(self.census("--list").splitlines(), COUNTED)

    def test_count_matches_list(self):
        self.assertEqual(self.census().strip(), str(len(COUNTED)))


if __name__ == "__main__":
    unittest.main()
