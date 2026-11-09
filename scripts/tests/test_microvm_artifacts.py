"""Artifact recipe tests: no kernel compilation, VM, root privileges, or downloads."""
import argparse
import importlib.util
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("microvm_build", ROOT / "scripts/microvm/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class ArtifactRecipeTests(unittest.TestCase):

    def test_source_pin_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            archive = root / "source.tar"
            archive.write_bytes(b"not the selected release")
            args = argparse.Namespace(archive=archive, sha256="0" * 64, output=root / "new")
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                build.build_kernel(args)
            self.assertFalse(args.output.exists())

    def test_archive_rejects_escape_and_links(self):
        for member_name, kind in [("../escape", tarfile.REGTYPE), ("/escape", tarfile.REGTYPE),
                                  ("linux/link", tarfile.SYMTYPE), ("linux/device", tarfile.CHRTYPE)]:
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as name:
                root = pathlib.Path(name)
                archive = root / "source.tar"
                with tarfile.open(archive, "w") as tar:
                    member = tarfile.TarInfo(member_name)
                    member.type = kind
                    member.linkname = "/tmp/outside"
                    tar.addfile(member)
                with self.assertRaises(ValueError):
                    build.unpack_kernel(archive, root)
                self.assertFalse((root / "linux").exists())


if __name__ == "__main__":
    unittest.main()
