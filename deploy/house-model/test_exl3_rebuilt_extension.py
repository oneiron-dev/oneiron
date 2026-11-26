"""A rebuilt exllamav3 extension (`ONEIRON_HOUSE_EXL3_EXT_DIR`, build-exl3-ext.sh).

The launcher resolves the directory, puts it first on PYTHONPATH and names it
to the server. The server takes the SHA-256 of the module it loaded from
exactly that directory, or refuses to start when the module came from
anywhere else or through a link. Unset, the server keeps only the installed
extension (the file an installed distribution's RECORD lists with its
SHA-256, or exllamav3's JIT build) and refuses any other module. The recipe
refuses an output directory that exists, stages its build in a directory of
its own and publishes it whole, and on a failure removes only what it made.

CPU only, with the stand-ins of `test_exl3_reply_limits`; no model is loaded,
the launcher runs a stand-in interpreter, and the recipe runs with stand-ins
for git, nvcc and the build. Run from this folder:
`python3 -m unittest test_exl3_rebuilt_extension`."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import test_exl3_reply_limits  # noqa: F401  (stands in for the GPU modules the server imports)

import exl3_server

HERE = Path(__file__).resolve().parent
MODULE = "exllamav3_ext.cpython-312-x86_64-linux-gnu.so"
STOCK_LINE = "#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ == 860)"
H_ACC_LINE = "#if defined(__CUDA_ARCH__) && (__CUDA_ARCH__ == 860 || __CUDA_ARCH__ == 890)"


def record_hash(data):
    """`data`'s digest as a wheel RECORD writes it."""
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class ExtensionCase(unittest.TestCase):
    """A rebuilt module in `ext_dir`; no installed distribution and no JIT build unless a test makes one."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name).resolve()
        self.ext_dir = self.root / "ext"
        self.ext_dir.mkdir()
        self.module = self.ext_dir / MODULE
        self.module.write_bytes(b"a rebuilt extension")
        jit = mock.patch.object(exl3_server, "jit_extension_dir", return_value=None, create=True)
        jit.start()
        self.addCleanup(jit.stop)

    def tearDown(self):
        self.dir.cleanup()

    def loaded_from(self, path):
        return mock.patch.object(exl3_server, "exllamav3_ext", types.SimpleNamespace(__file__=str(path)))

    def installed(self, data, listed=None):
        """The module `data` in a site directory first on sys.path, which an exllamav3 distribution's RECORD lists
        with `listed`'s digest (the module's own by default)."""
        site = self.root / "site-packages"
        site.mkdir()
        module = site / MODULE
        module.write_bytes(data)
        info = site / "exllamav3-1.6.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: exllamav3\nVersion: 1.6.0\n")
        (info / "RECORD").write_text(f"{MODULE},{record_hash(data if listed is None else listed)},{len(data)}\n"
                                     "exllamav3-1.6.0.dist-info/RECORD,,\n")
        path = mock.patch.object(sys, "path", [str(site)] + sys.path)
        path.start()
        self.addCleanup(path.stop)
        return module


class InstalledExtensionOnly(ExtensionCase):
    """No --exllamav3-ext-dir: only the installed extension runs."""

    def test_a_module_without_a_file_names_no_extension(self):
        with mock.patch.object(exl3_server, "exllamav3_ext", types.SimpleNamespace()):
            self.assertIsNone(exl3_server.rebuilt_extension_digest(None))
            self.assertIsNone(exl3_server.rebuilt_extension_digest(""))

    def test_the_module_a_distribution_lists_is_kept(self):
        with self.loaded_from(self.installed(b"the installed extension")):
            self.assertIsNone(exl3_server.rebuilt_extension_digest(None))

    def test_the_jit_build_is_kept(self):
        jit_dir = self.root / "torch_extensions" / "py312_cu128" / "exllamav3_ext"
        jit_dir.mkdir(parents=True)
        (jit_dir / "exllamav3_ext.so").write_bytes(b"the JIT build")
        with mock.patch.object(exl3_server, "jit_extension_dir", return_value=jit_dir, create=True), \
                self.loaded_from(jit_dir / "exllamav3_ext.so"):
            self.assertIsNone(exl3_server.rebuilt_extension_digest(None))

    def test_a_rebuilt_module_is_refused_however_it_is_reached(self):
        self.installed(b"the installed extension")
        hard = self.root / "hard" / MODULE
        hard.parent.mkdir()
        os.link(self.module, hard)
        soft = self.root / "soft" / MODULE
        soft.parent.mkdir()
        soft.symlink_to(self.module)
        for path in (self.module, hard, soft):
            for ext_dir in (None, ""):
                with self.subTest(path=path, ext_dir=ext_dir), self.loaded_from(path), \
                        self.assertRaisesRegex(RuntimeError, "not the installed extension"):
                    exl3_server.rebuilt_extension_digest(ext_dir)

    def test_an_overwritten_installed_module_is_refused(self):
        module = self.installed(b"a rebuilt extension", listed=b"the installed extension")
        with self.loaded_from(module), self.assertRaisesRegex(RuntimeError, "not the installed extension"):
            exl3_server.rebuilt_extension_digest(None)


class RebuiltExtensionDigest(ExtensionCase):
    """--exllamav3-ext-dir: the module from that directory, digested."""

    def test_the_module_loaded_from_the_directory_is_digested(self):
        with self.loaded_from(self.module):
            digest = exl3_server.rebuilt_extension_digest(str(self.ext_dir))
        self.assertEqual(digest, hashlib.sha256(b"a rebuilt extension").hexdigest())

    def test_a_module_loaded_elsewhere_refuses_the_launch(self):
        installed = self.installed(b"the installed extension")
        with self.loaded_from(installed), self.assertRaises(RuntimeError):
            exl3_server.rebuilt_extension_digest(str(self.ext_dir))
        with mock.patch.object(exl3_server, "exllamav3_ext", types.SimpleNamespace()), \
                self.assertRaises(RuntimeError):
            exl3_server.rebuilt_extension_digest(str(self.ext_dir))

    def test_a_directory_named_through_a_link_or_relatively_refuses_the_launch(self):
        link = self.root / "ext-link"
        link.symlink_to(self.ext_dir)
        for loaded, ext_dir in ((link / MODULE, link), (self.module, link), (self.module, Path("ext"))):
            with self.subTest(loaded=loaded, ext_dir=ext_dir), self.loaded_from(loaded), \
                    self.assertRaisesRegex(RuntimeError, "resolved absolute path"):
                exl3_server.rebuilt_extension_digest(str(ext_dir))

    def test_a_module_that_is_a_link_refuses_the_launch(self):
        other = self.root / "other"
        other.mkdir()
        (other / MODULE).symlink_to(self.module)
        with self.loaded_from(other / MODULE), self.assertRaisesRegex(RuntimeError, "not a link"):
            exl3_server.rebuilt_extension_digest(str(other))

    def test_a_link_switched_after_the_launch_changes_nothing(self):
        """The launcher resolves a link before the import; the server digests the build it imported."""
        build_b = self.root / "ext-b"
        build_b.mkdir()
        (build_b / MODULE).write_bytes(b"another rebuilt extension")
        link = self.root / "ext-current"
        link.symlink_to(self.ext_dir)
        resolved = Path(os.path.realpath(link))
        link.unlink()
        link.symlink_to(build_b)
        with self.loaded_from(resolved / MODULE):
            digest = exl3_server.rebuilt_extension_digest(str(resolved))
        self.assertEqual(digest, hashlib.sha256(b"a rebuilt extension").hexdigest())


class Launcher(unittest.TestCase):
    """serve-exl3.sh with a stand-in interpreter that prints what it was given."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name).resolve()
        self.root = root
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

    def test_a_link_is_resolved_before_the_server_starts(self):
        (self.ext_dir / MODULE).write_bytes(b"x")
        link = self.root / "ext-current"
        link.symlink_to(self.ext_dir)
        run = self.launch(ONEIRON_HOUSE_EXL3_EXT_DIR=f"{link}/")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"PYTHONPATH={self.ext_dir}\n", run.stdout)
        self.assertIn(f"ARG --exllamav3-ext-dir\nARG {self.ext_dir}\n", run.stdout)
        self.assertNotIn(str(link), run.stdout)

    def test_a_directory_without_the_module_is_refused(self):
        run = self.launch(ONEIRON_HOUSE_EXL3_EXT_DIR=str(self.ext_dir))
        self.assertEqual(run.returncode, 2)
        self.assertIn("holds no exllamav3_ext module", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_a_missing_directory_is_refused(self):
        run = self.launch(ONEIRON_HOUSE_EXL3_EXT_DIR=str(self.root / "absent"))
        self.assertEqual(run.returncode, 2)
        self.assertIn("is no directory", run.stderr)
        self.assertEqual(run.stdout, "")


class BuildRecipe(unittest.TestCase):
    """build-exl3-ext.sh with stand-ins: git checks out a GEMM header holding the stock line, nvcc reports 12.8,
    the interpreter reports torch 2.11.0+cu128 and builds a "module" that is the header as the recipe edited it,
    and the recipe's own Python steps (the line edit, the record) run in this interpreter."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name).resolve()
        bin_dir = self.root / "bin"
        (self.root / "cuda" / "bin").mkdir(parents=True)
        bin_dir.mkdir()
        self.write_tool(self.root / "cuda" / "bin" / "nvcc", 'echo "Cuda compilation tools, release 12.8, V12.8.93"\n')
        self.write_tool(bin_dir / "git", f"""dir=$2; shift 2
case "$1" in
  init) mkdir -p "$dir/$3" ;;
  fetch)
    # The test's gate: the build waits here until the test has set up what it races against.
    if [ -n "${{GATE:-}}" ]; then
      n=0; while [ ! -e "$GATE" ] && [ $n -lt 200 ]; do sleep 0.05; n=$((n + 1)); done
    fi ;;
  -c)
    mkdir -p "$dir/exllamav3/exllamav3_ext/quant"
    printf '%s\\n' 'header' '{STOCK_LINE}' 'body' > "$dir/exllamav3/exllamav3_ext/quant/exl3_gemm_inner.cuh" ;;
esac
""")
        self.write_tool(bin_dir / "python", f"""if [ "$1" = -c ]; then echo "2.11.0+cu128 12.8"; exit 0; fi
if [ "$1" = - ] && [ $# -eq 2 ]; then
  cat >/dev/null
  mkdir -p "$2/lib"
  cp exllamav3/exllamav3_ext/quant/exl3_gemm_inner.cuh "$2/lib/{MODULE}"
  exit 0
fi
if [ -n "${{FAIL_RECORD:-}}" ] && [ $# -eq 9 ]; then cat >/dev/null; exit 1; fi
exec "{sys.executable}" "$@"
""")
        self.env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                    "ONEIRON_HOUSE_PYTHON": str(bin_dir / "python"), "CUDA_HOME": str(self.root / "cuda"),
                    "TMPDIR": str(self.root)}
        self.out = self.root / "opt" / "ext-gemm-fp16-acc"

    def tearDown(self):
        self.dir.cleanup()

    @staticmethod
    def write_tool(path, body):
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)

    def build(self, arg, **env):
        return subprocess.Popen(["bash", str(HERE / "build-exl3-ext.sh"), arg], env=dict(self.env, **env),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def partial_dirs(self):
        return sorted(p.name for p in self.out.parent.iterdir() if ".partial." in p.name)

    def test_an_existing_directory_is_refused(self):
        self.out.mkdir(parents=True)
        (self.out / MODULE).write_bytes(b"a published module")
        for arg in (str(self.out), f"{self.out}/"):
            with self.subTest(arg=arg):
                run = subprocess.run(["bash", str(HERE / "build-exl3-ext.sh"), arg],
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                                     capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn("exists", run.stderr)
                self.assertEqual((self.out / MODULE).read_bytes(), b"a published module")
                self.assertEqual(sorted(p.name for p in self.out.parent.iterdir()), [self.out.name])

    def test_a_directory_beside_the_output_is_never_taken_or_removed(self):
        """Another build waits beside <out dir> under the name a PID-named stage of this run would take."""
        self.out.parent.mkdir(parents=True)
        gate = self.root / "gate"
        run = self.build(str(self.out), GATE=str(gate))
        other = self.out.parent / f"{self.out.name}.partial.{run.pid}"
        other.mkdir()
        (other / MODULE).write_bytes(b"another build")
        gate.touch()
        stdout, stderr = run.communicate(timeout=60)
        self.assertTrue((other / MODULE).is_file(), f"the other build was removed: {stderr}")
        self.assertEqual((other / MODULE).read_bytes(), b"another build")
        self.assertEqual(run.returncode, 0, stderr)
        self.assertEqual(self.partial_dirs(), [other.name])
        module = (self.out / MODULE).read_bytes()
        self.assertIn(H_ACC_LINE.encode(), module)
        self.assertNotIn((STOCK_LINE + "\n").encode(), module)
        record = json.loads((self.out / "exllamav3_ext.build.json").read_text())
        self.assertEqual(record["sha256"], hashlib.sha256(module).hexdigest())
        self.assertEqual(record["changed_line"], H_ACC_LINE)
        umask = os.umask(0)
        os.umask(umask)
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o777 & ~umask)
        self.assertIn(f"into {self.out}\n", stdout)

    def test_a_failed_build_removes_only_its_own_directory(self):
        self.out.parent.mkdir(parents=True)
        other = self.out.parent / f"{self.out.name}.partial.other"
        other.mkdir()
        (other / MODULE).write_bytes(b"another build")
        run = self.build(str(self.out), FAIL_RECORD="1")
        _, stderr = run.communicate(timeout=60)
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.partial_dirs(), [other.name])
        self.assertEqual((other / MODULE).read_bytes(), b"another build")


if __name__ == "__main__":
    unittest.main()
