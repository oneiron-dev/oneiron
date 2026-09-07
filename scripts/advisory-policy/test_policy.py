"""Deterministic policy and real cargo-deny tests. No network or Rust compilation.

The real-command fixtures disable ONLY the unrelated yanked-index check. Production
keeps yanked=deny and runs every check. A missing/wrong cargo-deny is a failure, not a skip.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("advisory_policy", HERE / "check.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
BEFORE = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
EXPECTED = {
    ("RUSTSEC-2024-0413", "atk", "0.18.2"),
    ("RUSTSEC-2024-0416", "atk-sys", "0.18.2"),
    ("RUSTSEC-2024-0412", "gdk", "0.18.2"),
    ("RUSTSEC-2024-0418", "gdk-sys", "0.18.2"),
    ("RUSTSEC-2024-0411", "gdkwayland-sys", "0.18.2"),
    ("RUSTSEC-2024-0417", "gdkx11", "0.18.2"),
    ("RUSTSEC-2024-0414", "gdkx11-sys", "0.18.2"),
    ("RUSTSEC-2024-0415", "gtk", "0.18.2"),
    ("RUSTSEC-2024-0420", "gtk-sys", "0.18.2"),
    ("RUSTSEC-2024-0419", "gtk3-macros", "0.18.2"),
    ("RUSTSEC-2024-0370", "proc-macro-error", "1.0.4"),
    ("RUSTSEC-2025-0081", "unic-char-property", "0.9.0"),
    ("RUSTSEC-2025-0075", "unic-char-range", "0.9.0"),
    ("RUSTSEC-2025-0080", "unic-common", "0.9.0"),
    ("RUSTSEC-2025-0100", "unic-ucd-ident", "0.9.0"),
    ("RUSTSEC-2025-0098", "unic-ucd-version", "0.9.0"),
    ("RUSTSEC-2026-0247", "bitmaps", "2.1.0"),
    ("RUSTSEC-2026-0248", "im", "15.1.0"),
    ("RUSTSEC-2026-0251", "sized-chunks", "0.6.5"),
}


def load_policy():
    return json.loads((HERE / "exceptions.json").read_text(encoding="utf-8"))


def fixture_lock(data):
    nodes = {}
    for entry in data["entries"]:
        nodes[entry["package"] + "@" + entry["version"]] = {
            "name": entry["package"], "version": entry["version"],
            "source": policy.REGISTRY, "dependencies": [],
        }
    for entry in data["entries"]:
        for parent in entry["parents"]:
            name, version = parent.split("@")
            node = nodes.setdefault(parent, {"name": name, "version": version,
                                             "source": policy.REGISTRY, "dependencies": []})
            node["dependencies"].append(entry["package"])
    for context in data["context"]:
        nodes[context["package"] + "@" + context["version"]] = {
            "name": context["package"], "version": context["version"], "source": policy.REGISTRY,
            "dependencies": [context["dependency"]],
        }
    return {"version": 3, "package": list(nodes.values())}


def write_advisory(database, entry, informational="unmaintained", extra=""):
    path = database / "crates" / entry["package"] / (entry["id"] + ".md")
    path.parent.mkdir(parents=True, exist_ok=True)
    classification = "" if informational is None else f'informational = "{informational}"\n'
    path.write_text(
        '```toml\n[advisory]\n'
        f'id = "{entry["id"]}"\npackage = "{entry["package"]}"\ndate = "2024-01-01"\n'
        + classification + extra + '\n[versions]\npatched = []\n```\n'
        '# Fixture maintenance risk\n\nNot a remediation.\n', encoding="utf-8")
    return path


class WorkflowTests(unittest.TestCase):
    def test_manual_dispatch_reaches_deny_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        # Pin the current simple YAML shape without adding a YAML dependency.
        self.assertRegex(workflow, r"(?m)^on:\n  workflow_dispatch:\n\n(?=\S)")
        job = re.search(r"(?m)^  deny:\n((?:    .*\n|\n)*)", workflow)
        self.assertIsNotNone(job)
        conditions = [line for line in job[1].splitlines() if line.startswith("    if:")]
        self.assertEqual(conditions, ["    if: github.event_name == 'workflow_dispatch'"])
        self.assertNotRegex(job[1], r"(?m)^    needs:")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.data = load_policy()
        self.lock = fixture_lock(self.data)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "db"
        for entry in self.data["entries"]:
            write_advisory(self.database, entry)
        self.config = (ROOT / "deny.toml").read_text(encoding="utf-8")

    def validate(self, now=BEFORE):
        entries = policy.validate_policy(self.data, self.lock, now)
        policy.validate_advisories(entries, self.database)

    def test_authority_exact19_and_allowed(self):
        self.assertEqual({(e["id"], e["package"], e["version"]) for e in self.data["entries"]}, EXPECTED)
        self.validate()
        # Also pin the real current lock, not the superseded baseline packet.
        policy.validate_policy(self.data, tomllib.loads((ROOT / "Cargo.lock").read_text()), BEFORE)

    def test_permanent_exceptions_preserved_and_no_new_ids(self):
        base = policy.validate_config(self.config)
        rendered = tomllib.loads(policy.accepted_config(self.config, self.data["entries"]))
        self.assertEqual(rendered["advisories"]["ignore"][19:], base["advisories"]["ignore"])
        self.assertEqual({e["id"] for e in base["advisories"]["ignore"]}, policy.EXISTING_IDS)
        for section in ("graph", "licenses", "bans", "sources"):
            self.assertEqual(rendered[section], base[section])
        altered = self.config.replace('ignore = [', 'ignore = [\n    { id = "RUSTSEC-2099-0001", reason = "new" },', 1)
        with self.assertRaises(policy.PolicyError):
            policy.validate_config(altered)

    def test_no_broad_classification_or_linux_filter(self):
        for old, new in [('[advisories]', '[advisories]\nunmaintained = "none"'),
                         ('all-features = true', 'all-features = true\ntargets = ["x86_64-pc-windows-msvc"]'),
                         ('yanked = "deny"', 'yanked = "allow"')]:
            with self.subTest(new=new), self.assertRaises(policy.PolicyError):
                policy.validate_config(self.config.replace(old, new))

    def test_each_locked_version_change_and_extra_version_fails(self):
        for entry in self.data["entries"]:
            for extra in (False, True):
                with self.subTest(entry=entry["id"], extra=extra):
                    lock = deepcopy(self.lock)
                    node = next(p for p in lock["package"] if p["name"] == entry["package"])
                    if extra:
                        node = deepcopy(node)
                        lock["package"].append(node)
                    node["version"] = "99.0.0"
                    with self.assertRaises(policy.PolicyError):
                        policy.validate_policy(self.data, lock, BEFORE)

    def test_missing_package_source_or_parent_change_fails(self):
        for change in ("missing", "source", "parent"):
            lock = deepcopy(self.lock)
            if change == "missing":
                lock["package"].pop(0)
            elif change == "source":
                lock["package"][0]["source"] = "git+https://example.invalid/fork"
            else:
                lock["package"].append({"name": "new-parent", "version": "1.0.0", "dependencies": ["atk"]})
            with self.subTest(change=change), self.assertRaises(policy.PolicyError):
                policy.validate_policy(self.data, lock, BEFORE)

    def test_each_id_reclassification_or_vulnerability_fails(self):
        for entry in self.data["entries"]:
            for classification in (None, "unsound", "notice"):
                write_advisory(self.database, entry, classification)
                with self.subTest(id=entry["id"], classification=classification), self.assertRaises(policy.PolicyError):
                    self.validate()
            write_advisory(self.database, entry)

    def test_security_metadata_and_affected_range_fail(self):
        entry = self.data["entries"][0]
        for extra in ('cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"\n',
                      'aliases = ["CVE-2026-0001"]\n', 'withdrawn = "2026-09-01"\n',
                      '[affected]\nos = ["linux"]\n'):
            write_advisory(self.database, entry, extra=extra)
            with self.subTest(extra=extra), self.assertRaises(policy.PolicyError):
                self.validate()
        path = write_advisory(self.database, entry)
        path.write_text(path.read_text().replace('patched = []', 'patched = [">=0.18.3"]'))
        with self.assertRaises(policy.PolicyError):
            self.validate()

    def test_missing_duplicate_package_identity_and_malformed_advisory_fail(self):
        entry = self.data["entries"][0]
        path = write_advisory(self.database, entry)
        original = path.read_text()
        for text in ('not toml', '```toml\n[advisory]', original.replace('package = "atk"', 'package = "other"')):
            path.write_text(text)
            with self.subTest(text=text), self.assertRaises(policy.PolicyError):
                self.validate()
        path.unlink()
        with self.assertRaises(policy.PolicyError):
            self.validate()
        write_advisory(self.database, entry)
        write_advisory(self.database, dict(entry, package="other"))
        with self.assertRaises(policy.PolicyError):
            self.validate()

    def test_expiry_boundary_review_and_no_renewal(self):
        expiry = policy.utc_time(policy.EXPIRY)
        self.validate(expiry - timedelta(microseconds=1))
        for now in (expiry, expiry + timedelta(seconds=1)):
            with self.subTest(now=now), self.assertRaises(policy.PolicyError):
                self.validate(now)
        self.data["review"]["post_wave_at"] = "2026-09-08T00:00:00Z"
        self.validate()
        with self.assertRaises(policy.PolicyError):
            self.validate(policy.utc_time(self.data["review"]["post_wave_at"]))
        self.data["review"]["automatic_renewal"] = True
        with self.assertRaises(policy.PolicyError):
            self.validate()
        self.data = load_policy()
        self.data["expires"] = "2026-11-07T00:00:00Z"
        with self.assertRaises(policy.PolicyError):
            self.validate()

    def test_policy_data_cannot_substitute_new_id_package_or_version(self):
        for field, value in (("id", "RUSTSEC-2026-9001"), ("package", "new-package"), ("version", "99.0.0")):
            data = deepcopy(self.data)
            data["entries"][0][field] = value
            with self.subTest(field=field), self.assertRaises(policy.PolicyError):
                policy.validate_policy(data, self.lock, BEFORE)

    def test_upstream_urlpattern_context_change_requires_review(self):
        next(p for p in self.lock["package"] if p["name"] == "tauri-utils")["version"] = "2.9.4"
        with self.assertRaises(policy.PolicyError):
            self.validate()

    def test_exact3_required_loro_chain_and_parent_changes_fail(self):
        parents = {
            "bitmaps": ["im@15.1.0", "sized-chunks@0.6.5"],
            "im": ["loro-internal@1.13.9"],
            "sized-chunks": ["im@15.1.0"],
        }
        self.assertEqual({e["package"]: e["parents"] for e in self.data["entries"][-3:]}, parents)
        self.assertEqual(self.data["context"][1:], [
            {"package": "loro", "version": "1.13.9", "dependency": "loro-internal 1.13.9"},
            {"package": "loro-internal", "version": "1.13.9", "dependency": "im 15.1.0"},
        ])
        for name in ("loro", "loro-internal"):
            for change in ("missing", "version", "source", "dependency"):
                lock = deepcopy(self.lock)
                node = next(p for p in lock["package"] if p["name"] == name)
                if change == "missing":
                    lock["package"].remove(node)
                elif change == "version":
                    node["version"] = "99.0.0"
                elif change == "source":
                    node["source"] = "git+https://example.invalid/fork"
                else:
                    node["dependencies"] = []
                with self.subTest(package=name, change=change), self.assertRaises(policy.PolicyError):
                    policy.validate_policy(self.data, lock, BEFORE)
        for name, expected_parents in parents.items():
            for parent in [None, *expected_parents]:
                lock = deepcopy(self.lock)
                if parent is None:
                    lock["package"].append({"name": "new-parent", "version": "1.0.0", "dependencies": [name]})
                else:
                    node = next(p for p in lock["package"] if f"{p['name']}@{p['version']}" == parent)
                    node["dependencies"] = [d for d in node["dependencies"] if d.split()[0] != name]
                with self.subTest(package=name, parent=parent), self.assertRaises(policy.PolicyError):
                    policy.validate_policy(self.data, lock, BEFORE)

    def test_exact3_missing_from_stale_database_stay_blocked(self):
        for entry in self.data["entries"][-3:]:
            path = self.database / "crates" / entry["package"] / (entry["id"] + ".md")
            path.unlink()
            with self.subTest(id=entry["id"]), self.assertRaisesRegex(policy.PolicyError, "missing"):
                self.validate()
            write_advisory(self.database, entry)
        self.validate()

    def test_empty_duplicate_and_ambiguous_database_fail(self):
        self.data["entries"][1] = self.data["entries"][0]
        with self.assertRaises(policy.PolicyError):
            self.validate()
        with self.assertRaises(policy.PolicyError):
            policy.database_root(Path(self.temp.name) / "db")


class ExecutionTests(unittest.TestCase):
    """The production entrypoint cannot turn an error or deadline into success."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = load_policy()
        self.lock = fixture_lock(self.data)
        directory = self.root / "scripts/advisory-policy"
        directory.mkdir(parents=True)
        (directory / "exceptions.json").write_text(json.dumps(self.data))
        # Only this TOML reader is mocked; policy, DB, config and control flow are real.
        (self.root / "Cargo.lock").write_text("fixture lock\n")
        self.cache = self.root / "cache"
        self.database = self.cache / "advisory-db-3157b0e258782691"
        for entry in self.data["entries"]:
            write_advisory(self.database, entry)
        base = (ROOT / "deny.toml").read_text()
        (self.root / "deny.toml").write_text(policy.cache_config(base, self.cache))
        real_loads = tomllib.loads
        def load_toml(text):
            return self.lock if text == "fixture lock\n" else real_loads(text)
        reader = patch.object(policy.tomllib, "loads", side_effect=load_toml)
        reader.start()
        self.addCleanup(reader.stop)
        clock = patch.object(policy, "datetime")
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.clock.now.return_value = BEFORE
        self.clock.fromisoformat.side_effect = datetime.fromisoformat
        self.calls = []
        self.exit_code = 0
        self.final_config = None

    def cargo(self, command, **kwargs):
        self.calls.append(command)
        if command == ["cargo", "deny", "--version"]:
            return subprocess.CompletedProcess(command, 0, "cargo-deny 0.19.4\n", "")
        self.assertIn("--offline", command)
        self.assertIn("--locked", command)
        self.assertIn("--disable-fetch", command)
        self.assertNotIn("--allow", command)
        self.assertNotIn("--target", command)
        self.final_config = Path(command[command.index("--config") + 1])
        config = tomllib.loads(self.final_config.read_text())
        self.assertEqual(len(config["advisories"]["ignore"]), 23)
        self.assertEqual(config["advisories"]["yanked"], "deny")
        private = Path(config["advisories"]["db-path"])
        self.assertNotEqual(private, self.cache)
        policy.validate_advisories(self.data["entries"], policy.database_root(private))
        return subprocess.CompletedProcess(command, self.exit_code)

    def test_effective_config_is_private_removed_and_failure_exit_is_preserved(self):
        self.exit_code = 7
        with patch.object(policy.subprocess, "run", side_effect=self.cargo):
            self.assertEqual(policy.execute(self.root, offline=True), 7)
        self.assertFalse(self.final_config.exists())
        self.assertEqual(len(tomllib.loads((self.root / "deny.toml").read_text())["advisories"]["ignore"]), 4)

    def test_expiry_prevents_even_version_probe(self):
        self.clock.now.return_value = policy.utc_time(policy.EXPIRY)
        with patch.object(policy.subprocess, "run") as run, self.assertRaises(policy.PolicyError):
            policy.execute(self.root, offline=True)
        run.assert_not_called()

    def test_deadline_crossed_during_check_blocks_success(self):
        expiry = policy.utc_time(policy.EXPIRY)
        self.clock.now.side_effect = [BEFORE, BEFORE, expiry]
        with patch.object(policy.subprocess, "run", side_effect=self.cargo), self.assertRaises(policy.PolicyError):
            policy.execute(self.root, offline=True)
        self.assertFalse(self.final_config.exists())

    def test_reclassification_stops_before_effective_command(self):
        write_advisory(self.database, self.data["entries"][0], None)
        with patch.object(policy.subprocess, "run", side_effect=self.cargo), self.assertRaises(policy.PolicyError):
            policy.execute(self.root, offline=True)
        self.assertEqual(self.calls, [["cargo", "deny", "--version"]])


class EffectiveCommandTests(unittest.TestCase):
    """Exercise real 0.19.4 ignoring semantics against a local Git advisory DB."""

    def setUp(self):
        self.assertIsNotNone(shutil.which("cargo"), "install cargo and cargo-deny 0.19.4")
        result = subprocess.run(["cargo", "deny", "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "cargo-deny " + policy.CARGO_DENY_VERSION)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.cache = self.work / "advisory-db"
        # cargo-deny 0.19.4's cache key for the configured RustSec URL, inspected locally.
        self.database = self.cache / "advisory-db-3157b0e258782691"
        self.data = load_policy()
        for entry in self.data["entries"]:
            write_advisory(self.database, entry)
        # Include the old vulnerability decision too: this work must not alter it.
        self.legacy = {"id": "RUSTSEC-2023-0071", "package": "rsa", "version": "0.9.10"}
        write_advisory(self.database, self.legacy, None)
        self.git("init", "--quiet")
        self.git("remote", "add", "origin", policy.DB_URL)
        self.commit_database()
        self.lock = fixture_lock(self.data)
        self.metadata = self.write_metadata(self.data["entries"] + [self.legacy])
        self.config_text = (ROOT / "deny.toml").read_text(encoding="utf-8")
        policy.validate_config(self.config_text)

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=Policy fixture", "-c", "user.email=policy@example.invalid",
                        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                       cwd=self.database, check=True, capture_output=True, text=True)

    def commit_database(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "--allow-empty", "-m", "local advisory fixture")

    def write_metadata(self, entries):
        # cargo-deny consumes cargo metadata directly: no resolver, build, index, or network needed.
        manifest = self.work / "Cargo.toml"
        manifest.write_text('[package]\nname = "policy-fixture"\nversion = "0.1.0"\nedition = "2021"\n'
                            + '[lib]\npath = "lib.rs"\n[dependencies]\n' + "".join(
                                f'{e["package"]} = "={e["version"]}"\n' for e in entries))
        (self.work / "lib.rs").write_text("// Metadata fixture only; never compiled.\n")
        root_id = f"path+{self.work.as_uri()}#policy-fixture@0.1.0"
        nodes, packages = [], []
        for name, version, package_id, source in [
            ("policy-fixture", "0.1.0", root_id, None),
            *[(e["package"], e["version"], f"{policy.REGISTRY}#{e['package']}@{e['version']}", policy.REGISTRY)
              for e in entries],
        ]:
            package_manifest = manifest
            if source is not None:
                package_manifest = self.work / "crates" / f"{name}-{version}" / "Cargo.toml"
                package_manifest.parent.mkdir(parents=True, exist_ok=True)
                package_manifest.write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n'
                                            '[lib]\npath = "lib.rs"\n')
                (package_manifest.parent / "lib.rs").write_text("// Offline metadata fixture.\n")
            packages.append({
                "name": name, "version": version, "id": package_id, "source": source,
                "license": "MIT", "license_file": None, "description": "offline fixture",
                "dependencies": [], "targets": [{"kind": ["lib"], "crate_types": ["lib"],
                    "name": name.replace("-", "_"), "src_path": str(package_manifest.parent / "lib.rs"),
                    "edition": "2021", "doc": True, "doctest": True, "test": True}],
                "features": {}, "manifest_path": str(package_manifest), "metadata": {},
                "publish": None, "authors": [], "categories": [], "keywords": [],
                "readme": None, "repository": None, "homepage": None, "documentation": None,
                "edition": "2021", "links": None, "default_run": None, "rust_version": None,
            })
            nodes.append({"id": package_id, "dependencies": [], "deps": [], "features": []})
        for package in packages[1:]:
            nodes[0]["dependencies"].append(package["id"])
            nodes[0]["deps"].append({"name": package["name"].replace("-", "_"), "pkg": package["id"],
                                     "dep_kinds": [{"kind": None, "target": None}]})
            packages[0]["dependencies"].append({"name": package["name"], "source": policy.REGISTRY,
                "req": "=" + package["version"], "kind": None, "rename": None, "optional": False,
                "uses_default_features": True, "features": [], "target": None, "registry": None})
        lock_text = "version = 3\n"
        for package in packages:
            lock_text += (f'\n[[package]]\nname = "{package["name"]}"\n'
                          f'version = "{package["version"]}"\n')
            if package["source"] is not None:
                lock_text += f'source = "{package["source"]}"\n'
            else:
                lock_text += "dependencies = " + json.dumps([e["package"] for e in entries]) + "\n"
        (self.work / "Cargo.lock").write_text(lock_text)
        metadata = self.work / "metadata.json"
        metadata.write_text(json.dumps({"packages": packages, "workspace_members": [root_id],
            "workspace_default_members": [root_id], "resolve": {"nodes": nodes, "root": root_id},
            "target_directory": str(self.work / "target"), "build_directory": str(self.work / "target"), "version": 1,
            "workspace_root": str(self.work), "metadata": None}))
        return metadata

    def run_deny(self, accepted=True, unsafe_id_only=False):
        base = policy.cache_config(self.config_text, self.cache)
        if accepted:
            if not unsafe_id_only:
                policy.validate_policy(self.data, self.lock, BEFORE)
                policy.validate_advisories(self.data["entries"], self.database)
            base = policy.accepted_config(base, self.data["entries"])
        # Isolate advisories from yanked registry lookups in these synthetic offline fixtures.
        base = base.replace('yanked = "deny"', 'yanked = "allow"')
        effective = self.work / "deny.toml"
        effective.write_text(base)
        command = policy.check_command(effective, offline=True)
        command += ["--metadata-path", str(self.metadata), "advisories"]
        return subprocess.run(command, cwd=self.work, capture_output=True, text=True,
                              env=dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never"))

    def test_raw_deny_blocks_but_exact19_and_old_exception_are_accepted(self):
        raw = self.run_deny(accepted=False)
        self.assertNotEqual(raw.returncode, 0, raw.stdout + raw.stderr)
        self.assertIn("unmaintained", raw.stderr)
        accepted = self.run_deny()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_new_id_same_package_and_unlisted_package_stay_blocked(self):
        for name in ("atk", "new-unlisted-package"):
            with self.subTest(package=name):
                entry = {"id": "RUSTSEC-2026-9001", "package": name, "version": "0.18.2"}
                path = write_advisory(self.database, entry)
                self.commit_database()
                if name != "atk":
                    self.metadata = self.write_metadata(self.data["entries"] + [self.legacy, entry])
                result = self.run_deny()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(entry["id"], result.stderr)
                path.unlink()

    def test_new_vulnerability_on_accepted_package_stays_blocked(self):
        entry = {"id": "RUSTSEC-2026-9002", "package": "atk"}
        write_advisory(self.database, entry, None)
        self.commit_database()
        result = self.run_deny()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(entry["id"], result.stderr)
        self.assertIn("vulnerability", result.stderr)

    def test_new_notice_and_unsound_on_accepted_package_stay_blocked(self):
        for classification in ("notice", "unsound"):
            with self.subTest(classification=classification):
                entry = {"id": "RUSTSEC-2026-9003", "package": "atk"}
                write_advisory(self.database, entry, classification)
                self.commit_database()
                result = self.run_deny()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(entry["id"], result.stderr)
                self.assertIn(f"error[{classification}]", result.stderr)

    def test_same_id_vulnerability_cannot_reach_id_ignore(self):
        write_advisory(self.database, self.data["entries"][0], None)
        self.commit_database()
        # Prove why a bare ID ignore is unsafe with the installed tool, not a mock.
        unsafe = self.run_deny(unsafe_id_only=True)
        self.assertEqual(unsafe.returncode, 0, unsafe.stdout + unsafe.stderr)
        with self.assertRaises(policy.PolicyError):
            self.run_deny()

    def test_changed_version_cannot_reach_id_ignore(self):
        entries = deepcopy(self.data["entries"])
        entries[0]["version"] = "99.0.0"
        self.metadata = self.write_metadata(entries + [self.legacy])
        next(p for p in self.lock["package"] if p["name"] == "atk")["version"] = "99.0.0"
        unsafe = self.run_deny(unsafe_id_only=True)
        self.assertEqual(unsafe.returncode, 0, unsafe.stdout + unsafe.stderr)
        with self.assertRaises(policy.PolicyError):
            self.run_deny()


if __name__ == "__main__":
    unittest.main()
