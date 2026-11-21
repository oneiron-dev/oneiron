"""A rebuilt exllamav3 extension (`ONEIRON_HOUSE_EXL3_EXT_DIR`, build-exl3-ext.sh):
the launcher puts its directory first on PYTHONPATH and names it to the
server, and the server takes the SHA-256 of the module it loaded from there,
or refuses to start when the module came from anywhere else; unset, the
server refuses a rebuilt module (one with the recipe's record beside it).
The recipe refuses an output directory that already exists. CPU only, with
the stand-ins of `test_exl3_reply_limits`; no model is loaded, the launcher
runs a stand-in interpreter, and the recipe stops before it builds. Run from
this folder: `python3 -m unittest test_exl3_rebuilt_extension`."""
import hashlib
import os
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import test_exl3_reply_limits  # noqa: F401  (stands in for the GPU modules the server imports)

import exl3_server

HERE = Path(__file__).resolve().parent
MODULE = "exllamav3_ext.cpython-312-x86_64-linux-gnu.so"


class RebuiltExtensionDigest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ext_dir = Path(self.dir.name) / "ext"
        self.ext_dir.mkdir()
        self.module = self.ext_dir / MODULE
        self.module.write_bytes(b"a rebuilt extension")

    def tearDown(self):
        self.dir.cleanup()

    def loaded_from(self, path):
        return mock.patch.object(exl3_server, "exllamav3_ext", types.SimpleNamespace(__file__=str(path)))

    def test_no_directory_names_no_extension(self):
        self.assertIsNone(exl3_server.rebuilt_extension_digest(None))
        self.assertIsNone(exl3_server.rebuilt_extension_digest(""))

    def test_the_module_loaded_from_the_directory_is_digested(self):
        with self.loaded_from(self.module):
            digest = exl3_server.rebuilt_extension_digest(str(self.ext_dir))
        self.assertEqual(digest, hashlib.sha256(b"a rebuilt extension").hexdigest())

    def test_a_module_loaded_elsewhere_refuses_the_launch(self):
        installed = Path(self.dir.name) / "site-packages" / MODULE
        installed.parent.mkdir()
        installed.write_bytes(b"the installed extension")
        with self.loaded_from(installed), self.assertRaises(RuntimeError):
            exl3_server.rebuilt_extension_digest(str(self.ext_dir))
        with mock.patch.object(exl3_server, "exllamav3_ext", types.SimpleNamespace()), \
                self.assertRaises(RuntimeError):
            exl3_server.rebuilt_extension_digest(str(self.ext_dir))

    def test_no_directory_keeps_the_installed_module(self):
        installed = Path(self.dir.name) / "site-packages" / MODULE
        installed.parent.mkdir()
        installed.write_bytes(b"the installed extension")
        with self.loaded_from(installed):
            self.assertIsNone(exl3_server.rebuilt_extension_digest(None))

    def test_no_directory_refuses_a_rebuilt_module(self):
        # the record build-exl3-ext.sh writes beside its module
        (self.ext_dir / "exllamav3_ext.build.json").write_text("{}\n")
        link = Path(self.dir.name) / "linked" / MODULE
        link.parent.mkdir()
        link.symlink_to(self.module)
        for path in (self.module, link):
            for ext_dir in (None, ""):
                with self.subTest(path=path, ext_dir=ext_dir), self.loaded_from(path), \
                        self.assertRaisesRegex(RuntimeError, "rebuilt extension"):
                    exl3_server.rebuilt_extension_digest(ext_dir)
        with self.loaded_from(self.module):
            self.assertEqual(exl3_server.rebuilt_extension_digest(str(self.ext_dir)),
                             hashlib.sha256(b"a rebuilt extension").hexdigest())


class Launcher(unittest.TestCase):
    """serve-exl3.sh with a stand-in interpreter that prints what it was given."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.python = root / "python"
        self.python.write_text('#!/bin/sh\necho "PYTHONPATH=${PYTHONPATH:-}"\nfor a in "$@"; do echo "ARG $a"; done\n')
        self.python.chmod(0o755)
        self.ext_dir = root / "ext"
        self.ext_dir.mkdir()

    def tearDown(self):
        self.dir.cleanup()

    def launch(self, **env):
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ONEIRON_HOUSE_PYTHON": str(self.python)}
        return subprocess.run(["bash", str(HERE / "serve-exl3.sh")], env=dict(base, **env),
                              capture_output=True, text=True, timeout=30)

    def test_unset_leaves_the_installed_extension(self):
        run = self.launch()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("PYTHONPATH=\n", run.stdout)
        self.assertNotIn("--exllamav3-ext-dir", run.stdout)

    def test_a_directory_goes_first_on_the_path_and_to_the_server(self):
        (self.ext_dir / MODULE).write_bytes(b"x")
        run = self.launch(ONEIRON_HOUSE_EXL3_EXT_DIR=str(self.ext_dir), PYTHONPATH="/elsewhere")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"PYTHONPATH={self.ext_dir}:/elsewhere\n", run.stdout)
        self.assertIn(f"ARG --exllamav3-ext-dir\nARG {self.ext_dir}\n", run.stdout)

    def test_a_directory_without_the_module_is_refused(self):
        run = self.launch(ONEIRON_HOUSE_EXL3_EXT_DIR=str(self.ext_dir))
        self.assertEqual(run.returncode, 2)
        self.assertIn("holds no exllamav3_ext module", run.stderr)
        self.assertEqual(run.stdout, "")


class BuildRecipe(unittest.TestCase):
    """build-exl3-ext.sh stops before it fetches or builds anything."""

    def test_an_existing_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            published = Path(root) / "ext"
            published.mkdir()
            (published / MODULE).write_bytes(b"a published module")
            for arg in (str(published), f"{published}/"):
                with self.subTest(arg=arg):
                    run = subprocess.run(["bash", str(HERE / "build-exl3-ext.sh"), arg],
                                         env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                                         capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.returncode, 1, run.stderr)
                    self.assertIn("exists", run.stderr)
                    self.assertEqual((published / MODULE).read_bytes(), b"a published module")
                    self.assertEqual(sorted(p.name for p in Path(root).iterdir()), ["ext"])


if __name__ == "__main__":
    unittest.main()
