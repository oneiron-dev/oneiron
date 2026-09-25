"""Forked third-party crates come from the org forks by rev, never from a vendored copy.

docs/ops/forked-dependencies.md records each fork, its branch and its patches. A change to a
forked crate is a fork commit plus a new `rev`; these tests keep the pin, the deny policy and
the removed vendor trees in agreement.
"""

from pathlib import Path
import re
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
FORK_ORG = "https://github.com/oneiron-dev/"
SUDACHI_FORK = "https://github.com/oneiron-dev/sudachi.rs"
SUDACHI_UPSTREAM = "https://github.com/WorksApplications/sudachi.rs"
# Vendor trees replaced by a fork pin. Nothing may point back into them.
REMOVED_VENDOR_TREES = ("crates/oneiron/vendor/sudachi-0.6.11",)
GIT_SOURCE = re.compile(
    r"git\+(?P<url>[^?#]+)\?rev=(?P<rev>[0-9a-f]{40})#(?P<commit>[0-9a-f]{40})"
)


def _lock_packages():
    return tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]


def _manifests():
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*Cargo.toml"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [ROOT / name for name in listed.split("\0") if name]


def _path_values(table):
    """Yield every `path = "..."` string in a parsed manifest, at any depth."""
    if isinstance(table, dict):
        for key, value in table.items():
            if key == "path" and isinstance(value, str):
                yield value
            else:
                yield from _path_values(value)
    elif isinstance(table, list):
        for item in table:
            yield from _path_values(item)


class VendorPinTests(unittest.TestCase):
    def test_sudachi_resolves_from_the_org_fork_by_rev(self):
        packages = [p for p in _lock_packages() if p["name"] == "sudachi"]
        self.assertEqual(len(packages), 1, packages)
        sudachi = packages[0]
        self.assertEqual(sudachi["version"], "0.6.11")
        match = GIT_SOURCE.fullmatch(sudachi.get("source", ""))
        self.assertIsNotNone(match, f"not a git source pinned by rev: {sudachi.get('source')}")
        self.assertEqual(match["url"], SUDACHI_FORK)
        self.assertEqual(match["rev"], match["commit"])

    def test_no_dependency_path_points_into_a_removed_vendor_tree(self):
        removed = [(ROOT / tree).resolve() for tree in REMOVED_VENDOR_TREES]
        for tree in removed:
            self.assertFalse(tree.exists(), tree)
        manifests = _manifests()
        self.assertIn(ROOT / "Cargo.toml", manifests)
        for manifest in manifests:
            parsed = tomllib.loads(manifest.read_text())
            paths = list(_path_values(parsed))
            paths += parsed.get("workspace", {}).get("exclude", [])
            paths += parsed.get("workspace", {}).get("members", [])
            for value in paths:
                target = (manifest.parent / value).resolve()
                for tree in removed:
                    self.assertFalse(
                        target == tree or target.is_relative_to(tree),
                        f"{manifest.relative_to(ROOT)} points into removed {tree}: {value}",
                    )

    def test_deny_allows_the_fork_git_sources_and_not_upstream_sudachi(self):
        sources = tomllib.loads((ROOT / "deny.toml").read_text())["sources"]
        self.assertEqual(sources["unknown-git"], "deny")
        allowed = sources.get("allow-git", [])
        self.assertIn(SUDACHI_FORK, allowed)
        self.assertNotIn(SUDACHI_UPSTREAM, allowed)
        for url in allowed:
            self.assertTrue(url.startswith(FORK_ORG), url)
        for package in _lock_packages():
            source = package.get("source", "")
            if source.startswith("git+"):
                match = GIT_SOURCE.fullmatch(source)
                self.assertIsNotNone(match, f"{package['name']}: git source without a rev: {source}")
                self.assertIn(match["url"], allowed, package["name"])


if __name__ == "__main__":
    unittest.main()
