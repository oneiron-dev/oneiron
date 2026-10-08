"""CLI and reader-contract regressions; no installed validators or Cargo build needed."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
RUNNER = HERE / "runner.py"
INSTALL_ENV = HERE / "install_env.sh"
OVERRIDES = (
    "SEAL_DSS_BIN", "SEAL_PDFBOX_BIN", "SEAL_PYHANKO_BIN",
    "SEAL_PDFIUM_BIN", "SEAL_PDFJS_BIN", "SEAL_QPDF_BIN",
)


def isolated_env(root):
    env = os.environ.copy()
    env.update(SEAL_INTEROP_HOME=str(root))
    for name in OVERRIDES:
        env.pop(name, None)
    return env


class RunnerTests(unittest.TestCase):

    def test_unmanaged_prefix_is_never_removed_for_repair(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root = base / "managed"
            root.mkdir()
            foreign = base / "foreign"
            foreign.mkdir()
            marker = foreign / "keep"
            marker.write_text("user data")
            command = 'warn() { printf "%s\\n" "$*" >&2; }; source "$1"; mamba_env "$2" "poppler=25.02.0"'
            result = subprocess.run(
                ["bash", "-c", command, "bash", str(INSTALL_ENV), str(foreign)],
                env={**os.environ, "ROOT": str(root), "MM": "/bin/true"},
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to remove unmanaged prefix", result.stderr)
            self.assertEqual(marker.read_text(), "user data")


if __name__ == "__main__":
    unittest.main()
