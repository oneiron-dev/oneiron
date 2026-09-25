"""CLI and reader-contract regressions; no installed validators or Cargo build needed."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import reader_util
import runner

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "runner.py"
PDFJS = HERE / "pdfjs.mjs"
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


def fake_reader(root, status="pass", exit_code=0):
    wrapper = root / "wrapper"
    payload = {"reader": "dss", "version": "6.5", "mode": "verify", "status": status, "detail": "fixture"}
    wrapper.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        f"print(json.dumps({payload!r}))\nsys.exit({exit_code})\n"
    )
    wrapper.chmod(0o755)
    return wrapper


class RunnerTests(unittest.TestCase):
    def run_matrix(self, root, *args, wrapper=None):
        pdf = root / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.4\n")
        env = isolated_env(root)
        if wrapper is not None:
            env["SEAL_DSS_BIN"] = str(wrapper)
        return subprocess.run(
            [sys.executable, str(RUNNER), *args, str(pdf)],
            env=env, text=True, capture_output=True, check=False,
        )

    def test_reader_emits_normalized_tsv_row(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = self.run_matrix(root, "--reader", "dss", wrapper=fake_reader(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            row = result.stdout.strip().split("\t")
            self.assertEqual(row[:2], ["dss", "6.5"])
            self.assertTrue(row[2].startswith("linux-" + runner.os_proxy().split("/")[0][6:] + "/"))
            self.assertEqual(row[3:5], ["verify", "pass"])

    def test_missing_wrapper_is_reported_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = self.run_matrix(root, "--reader", "dss")
            self.assertEqual(result.returncode, 77)
            row = result.stdout.strip().split("\t")
            self.assertEqual(row[:2], ["dss", "unavailable"])
            self.assertEqual(row[4], "unavailable")

    def test_all_unavailable_matrix_exits_77(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.run_matrix(Path(d))
            self.assertEqual(result.returncode, 77, result.stderr)
            rows = [line.split("\t") for line in result.stdout.splitlines()]
            self.assertEqual(len(rows), len(runner.ALL) + 1)
            self.assertTrue(all(row[4] == "unavailable" for row in rows[1:]))

    def test_all_unavailable_installed_wrappers_exit_77(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bin").mkdir()
            for name, (_, path) in runner.WRAPPERS.items():
                wrapper = root / "bin" / path.name
                mode = "verify" if name in ("dss", "pdfbox", "pyhanko") or name.startswith("poppler-") else ("check" if name == "qpdf" else "parse")
                payload = {"reader": name, "version": "unavailable", "mode": mode, "status": "unavailable"}
                wrapper.write_text(
                    "#!/usr/bin/env python3\nimport json,sys\n"
                    f"print(json.dumps({payload!r}))\nsys.exit(77)\n"
                )
                wrapper.chmod(0o755)
            result = self.run_matrix(root)
            self.assertEqual(result.returncode, 77, result.stderr)
            rows = [line.split("\t") for line in result.stdout.splitlines()[1:]]
            self.assertEqual(len(rows), len(runner.ALL))
            self.assertTrue(all(row[4] == "unavailable" for row in rows))

    def test_partial_matrix_is_explicit_not_full_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = self.run_matrix(root, wrapper=fake_reader(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [line.split("\t") for line in result.stdout.splitlines()[1:]]
            self.assertEqual(sum(row[4] == "pass" for row in rows), 1)
            self.assertEqual(sum(row[4] == "unavailable" for row in rows), len(runner.ALL) - 1)
            self.assertIn("PARTIAL-MATRIX", result.stderr)

    def test_failure_takes_priority_over_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = self.run_matrix(root, wrapper=fake_reader(root, status="fail", exit_code=1))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("PARTIAL-MATRIX", result.stderr)

    def test_os_proxy_uses_actual_architecture_in_both_reporters(self):
        for machine, expected in (("aarch64", "linux-aarch64/"), ("arm64", "linux-aarch64/"),
                                  ("x86_64", "linux-x86_64/"), ("AMD64", "linux-x86_64/")):
            with self.subTest(machine=machine), patch("platform.machine", return_value=machine):
                self.assertTrue(runner.os_proxy().startswith(expected))
                self.assertTrue(reader_util.os_proxy().startswith(expected))

    def test_incomplete_poppler_prefix_repairs_only_managed_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "logs").mkdir()
            prefix = root / "poppler" / "25.02.0"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "python").write_text("stale executable")
            (prefix / "bin" / "python").chmod(0o755)
            (prefix / "conda-meta").mkdir()
            fake_mamba = root / "micromamba"
            fake_mamba.write_text(
                "#!/usr/bin/env python3\nimport pathlib,sys\n"
                "prefix=pathlib.Path(sys.argv[sys.argv.index('-p')+1])\n"
                "(prefix/'bin').mkdir(parents=True)\n"
                "exe=prefix/'bin'/'pdfsig'\n"
                "exe.write_text('#!/bin/sh\\nexit 0\\n')\n"
                "exe.chmod(0o755)\n"
            )
            fake_mamba.chmod(0o755)
            command = 'warn() { printf "%s\\n" "$*" >&2; }; source "$1"; mamba_env "$2" "poppler=25.02.0"'
            result = subprocess.run(
                ["bash", "-c", command, "bash", str(INSTALL_ENV), str(prefix)],
                env={**os.environ, "ROOT": str(root), "MM": str(fake_mamba)},
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((prefix / "bin" / "pdfsig").is_file())
            self.assertFalse((prefix / "bin" / "python").exists())

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


@unittest.skipUnless(shutil.which("node"), "Node.js is absent; pdf.js probe unavailable")
class PdfJsScopeTests(unittest.TestCase):
    def run_pdfjs(self, content):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pdf = root / "sample.pdf"
            pdf.write_bytes(content)
            module = root / "pdfjs.mjs"
            module.write_text(
                'export const getDocument=()=>({promise:Promise.resolve({'
                'numPages:1,getFieldObjects:async()=>({Seal:[{type:"signature"}]}),'
                'destroy:async()=>{}})});\n'
            )
            package = root / "package.json"
            package.write_text('{"version":"5.4.394"}')
            env = {**os.environ, "SEAL_PDFJS_PACKAGE_JSON": str(package), "SEAL_PDFJS_MODULE": str(module)}
            result = subprocess.run(["node", str(PDFJS), str(pdf)], env=env,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "pass")
            self.assertIn("signature_fields=1", report["detail"])
            self.assertIn("ByteRange not inspected", report["detail"])
            self.assertNotIn("byte_range_covers_file", report["detail"])
            return report

    def test_missing_signature_range_cannot_be_spoofed_by_comment(self):
        # A fake range in unrelated text must never become a signature coverage claim.
        prefix = b"%PDF-1.4\n<< /FT /Sig /V << /FakeRange [0 0 0 0] >> >>\n% /ByteRange [0 0 0 "
        size = 0
        while True:
            content = prefix + str(size).encode() + b"]\n"
            if len(content) == size:
                break
            size = len(content)
        self.run_pdfjs(content)

    def test_harmless_range_looking_comment_does_not_reject_field_parse(self):
        # The real range reaches EOF, but an unrelated comment has bad numbers.
        content = (b"%PDF-1.4\n<< /FT /Sig /V << /ByteRange [0 12 22 0000000000] >> >>\n"
                   b"% /ByteRange [0 1 2 3]\n")
        content = content.replace(b"0000000000", f"{len(content)-22:010}".encode(), 1)
        self.run_pdfjs(content)


if __name__ == "__main__":
    unittest.main()
