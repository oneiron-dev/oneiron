"""Offline lock/ignore checks using cargo-deny 0.19.4 as the advisory oracle."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.ci.check_deny_policy import ROOT, find_stale_ignores


class DenyPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Cargo-deny's --metadata-path makes the fixture graph independent of
        # crate downloads while exercising the real local RustSec database.
        env = os.environ | {"PATH": f"{Path.home() / '.cargo/bin'}:{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=True,
        )
        cls.metadata = json.loads(result.stdout)

    def fixture(self, root: Path, advisory_id: str, package: str, version: str):
        """Give cargo-deny a tiny real-schema graph with one registry dependency."""
        metadata = self.metadata
        owner = copy.deepcopy(next(p for p in metadata["packages"] if p["name"] == "oneiron"))
        child = copy.deepcopy(next(p for p in metadata["packages"] if p["name"] == package))
        owner_node = copy.deepcopy(next(n for n in metadata["resolve"]["nodes"] if n["id"] == owner["id"]))
        child_node = copy.deepcopy(next(n for n in metadata["resolve"]["nodes"] if n["id"] == child["id"]))
        new_id = child["id"].replace(f"@{child['version']}", f"@{version}")
        child["id"] = child_node["id"] = new_id
        child["version"] = version
        child["dependencies"] = []
        child["features"] = {}
        child_node.update(deps=[], dependencies=[], features=[])
        owner["dependencies"] = [{
            "name": package, "source": child["source"], "req": f"={version}",
            "kind": None, "rename": None, "optional": False,
            "uses_default_features": True, "features": [], "target": None,
            "registry": None,
        }]
        owner["features"] = {}
        owner_node.update(
            deps=[{"name": package.replace("-", "_"), "pkg": new_id,
                   "dep_kinds": [{"kind": None, "target": None}]}],
            dependencies=[new_id], features=[],
        )
        fake = metadata | {
            "packages": [owner, child],
            "workspace_members": [owner["id"]],
            "workspace_default_members": [owner["id"]],
            "resolve": metadata["resolve"] | {
                "root": owner["id"], "nodes": [owner_node, child_node],
            },
        }
        metadata_path = root / "metadata.json"
        metadata_path.write_text(json.dumps(fake))
        deny = root / "deny.toml"
        deny.write_text(
            '[advisories]\ndb-path = "~/.cargo/advisory-db"\n'
            f'ignore = [{{id = "{advisory_id}", '
            f'reason = "{package}@{version} reviewed"}}]\n'
        )
        lock = root / "Cargo.lock"
        lock.write_text(f'[[package]]\nname = "{package}"\nversion = "{version}"\n')
        return deny, lock, metadata_path

    def test_every_advisory_ignore_names_a_locked_crate(self):
        self.assertEqual(find_stale_ignores(ROOT / "deny.toml", ROOT / "Cargo.lock"), [])

    def test_a_stale_ignore_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2024-0370"
            deny, lock, graph = self.fixture(root, advisory_id, "proc-macro-error", "1.0.4")
            lock.write_text('[[package]]\nname = "other-crate"\nversion = "1.0.4"\n')
            self.assertEqual(find_stale_ignores(deny, lock, graph), [advisory_id])
            lock.write_text('[[package]]\nname = "proc-macro-error"\nversion = "1.0.5"\n')
            self.assertEqual(find_stale_ignores(deny, lock, graph), [advisory_id])

    def test_locked_but_unaffected_version_is_stale(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2020-0019"
            # 0.12.3 is patched; 0.12.0 is vulnerable and must keep its ignore.
            for version, expected in (("0.12.3", [advisory_id]), ("0.12.0", [])):
                with self.subTest(version=version):
                    deny, lock, graph = self.fixture(root, advisory_id, "tokio-rustls", version)
                    self.assertEqual(find_stale_ignores(deny, lock, graph), expected)

    def test_zerocopy_prerelease_unaffected_by_real_advisory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2023-0074"
            deny, lock, graph = self.fixture(root, advisory_id, "zerocopy", "0.2.1-alpha")
            self.assertEqual(find_stale_ignores(deny, lock, graph), [advisory_id])

    def test_mixed_safe_and_affected_versions_require_reviewed_version_to_be_affected(self):
        # An ID-only check sees the advisory on 0.6.5 and the safe 0.7.35
        # in the lock separately. The reviewed package@version must match.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2023-0074"
            deny, lock, graph = self.fixture(root, advisory_id, "zerocopy", "0.7.35")
            data = json.loads(graph.read_text())
            safe = data["packages"][1]
            affected = copy.deepcopy(safe)
            affected["id"] = affected["id"].replace("@0.7.35", "@0.6.5")
            affected["version"] = "0.6.5"
            data["packages"].append(affected)
            node = copy.deepcopy(data["resolve"]["nodes"][1])
            node["id"] = affected["id"]
            data["resolve"]["nodes"].append(node)
            owner = data["packages"][0]
            dependency = copy.deepcopy(owner["dependencies"][0])
            dependency["req"] = "=0.6.5"
            dependency["rename"] = "zerocopy_affected"
            owner["dependencies"].append(dependency)
            owner_node = data["resolve"]["nodes"][0]
            owner_node["dependencies"].append(affected["id"])
            owner_node["deps"].append({
                "name": "zerocopy_affected", "pkg": affected["id"],
                "dep_kinds": [{"kind": None, "target": None}],
            })
            graph.write_text(json.dumps(data))
            lock.write_text(
                '[[package]]\nname = "zerocopy"\nversion = "0.7.35"\n'
                '[[package]]\nname = "zerocopy"\nversion = "0.6.5"\n'
            )
            self.assertEqual(find_stale_ignores(deny, lock, graph), [advisory_id])
            deny.write_text(deny.read_text().replace("zerocopy@0.7.35", "zerocopy@0.6.5"))
            self.assertEqual(find_stale_ignores(deny, lock, graph), [])

    def test_tokio_rustls_partial_bound_prerelease_is_unaffected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            advisory_id = "RUSTSEC-2020-0019"
            deny, lock, graph = self.fixture(
                root, advisory_id, "tokio-rustls", "0.12.0-alpha.1"
            )
            self.assertEqual(find_stale_ignores(deny, lock, graph), [advisory_id])


if __name__ == "__main__":
    unittest.main()
