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
        #[cfg(oneiron_test_support)]
        #[path = "shared/mod.rs"]
        mod shared_probe;
        #[path = "shared/mod.rs"]
        mod shared_live;
        #[cfg(oneiron_test_support)]
        #[path = "path_shared.rs"]
        mod path_probe;
        #[ path = "path_shared.rs" ]
        mod path_live;
        #[cfg(test)]
        #[path = "path_dotted.rs"]
        mod dotted_probe;
        #[path = "shared/../path_dotted.rs"]
        mod dotted_live;
        #[cfg(test)]
        #[cfg_attr(feature = "sync", path = "elsewhere.rs")]
        mod gated_unread_path;
        #[cfg(all(any(oneiron_test_support, unix), not(unix)))]
        mod repeated_atom;
        #[cfg(all(any(oneiron_test_support, unix), not(unix)))]
        mod repeated_atom_inline {
            pub fn seed(v: &V) {
                v.store.edges_out.put(&mut txn, &key, &bytes);
            }
        }
        mod inner_gated {
            #![cfg(oneiron_test_support)]
            mod child;
            pub fn seed(v: &V) {
                v.store.edges_in.put(&mut txn, &key, &bytes);
            }
        }
        """,
    # Mounted both as a test door and as production code: production wins,
    # for the module and for the child it mounts without a test-only cfg.
    "shared/mod.rs": "mod writer;\n",
    "shared/writer.rs": raw_write("entities"),
    # The same, through a `#[path]` with spaces inside the brackets.
    "path_shared.rs": raw_write("entities"),
    # The same, through a `#[path]` with a `..` component.
    "path_dotted.rs": raw_write("short_ids"),
    # The cfg uses `unix` twice: false in every build without the test cfg.
    "repeated_atom.rs": raw_write("entities"),
    # Mounted inside an inline module gated by its own inner attribute.
    "inner_gated/child.rs": raw_write("entities"),
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
    "crates/oneiron/src/path_dotted.rs:2",
    "crates/oneiron/src/path_shared.rs:2",
    "crates/oneiron/src/release_only.rs:2",
    "crates/oneiron/src/shared/writer.rs:2",
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
            # An atom used twice takes one value in a build.
            "all(any(oneiron_test_support, unix), not(unix))": False,
            "any(all(test, unix), all(oneiron_test_support, not(unix)))": False,
            "all(any(oneiron_test_support, unix), not(windows))": None,
            "any(unix, not(unix))": True,
            'all(any(test, feature = "a"), not(feature = "a"))': False,
            'all(any(test, feature = "a"), not(feature = "b"))': None,
            'all(any(test, feature = "a b"), not(feature = "ab"))': None,
            # Two blanked literals may differ: each is its own atom.
            "all(any(test, feature =    ), not(feature =    ))": None,
            # Past the atom limit only the per-atom pass decides.
            "all(test, "
            + ", ".join(f"a{k}" for k in range(20))
            + ")": False,
            "all(any(test, a0), not(a0), "
            + ", ".join(f"a{k}" for k in range(1, 20))
            + ")": None,
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
        self.assertTrue(census.is_test_only_cfg(" cfg ( all ( test , unix ) ) "))
        self.assertTrue(census.inner_attributes_gate_test_only("\n # ! [ cfg(test) ]", 0))
        self.assertTrue(
            census.inner_attributes_gate_test_only("#![allow(x)]\n#![cfg(test)]", 0)
        )
        self.assertFalse(census.inner_attributes_gate_test_only("fn f() {}\n#![cfg(test)]", 0))


class CensusRepo(unittest.TestCase):
    tree = TREE

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="raw-write-census-"))
        self.addCleanup(shutil.rmtree, self.repo)
        scripts = self.repo / "scripts/ratchet"
        scripts.mkdir(parents=True)
        shutil.copy(SCRIPT, scripts / SCRIPT.name)
        src = self.repo / "crates/oneiron/src"
        for rel, text in self.tree.items():
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text), encoding="utf-8")

    def census(self, *args):
        return subprocess.run(
            [sys.executable, str(self.repo / "scripts/ratchet" / SCRIPT.name), *args],
            capture_output=True,
            text=True,
            check=True,
        )


class RawWriteCensusTree(CensusRepo):
    def test_list_leaves_out_test_only_code(self):
        run = self.census("--list")
        self.assertEqual(run.stdout.splitlines(), COUNTED)
        # The unread `#[path]` is on a test-only mount: no warning.
        self.assertEqual(run.stderr, "")

    def test_count_matches_list(self):
        self.assertEqual(self.census().stdout.strip(), str(len(COUNTED)))


class UnreadProductionPath(CensusRepo):
    # A production mount whose `#[path]` the census cannot read may name any
    # file, so no file is left out through a mount.
    tree = {
        "lib.rs": """\
            #[cfg(test)]
            mod unit_fixture;
            #[cfg_attr(feature = "sync", path = "elsewhere.rs")]
            mod chosen;
            """,
        "unit_fixture.rs": raw_write("entities"),
        "chosen.rs": raw_write("type_index"),
        "self_gated.rs": "#![cfg(test)]\n" + raw_write("entities"),
    }

    def test_every_mounted_file_stays_counted(self):
        run = self.census("--list")
        self.assertEqual(
            run.stdout.splitlines(),
            ["crates/oneiron/src/chosen.rs:2", "crates/oneiron/src/unit_fixture.rs:2"],
        )
        self.assertIn("RATCHET-WARNING", run.stderr)
        self.assertIn("crates/oneiron/src/lib.rs:4", run.stderr)


if __name__ == "__main__":
    unittest.main()
