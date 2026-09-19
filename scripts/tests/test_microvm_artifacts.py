"""Artifact recipe tests: no kernel compilation, VM, root privileges, or downloads."""
import argparse
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("microvm_build", ROOT / "scripts/microvm/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class ArtifactRecipeTests(unittest.TestCase):
    def test_kernel_driver_fragment_is_required(self):
        fragment = (build.HERE / "kernel.config").read_text()
        build.verify_config(fragment, fragment)
        with self.assertRaisesRegex(ValueError, "CONFIG_VIRTIO_VSOCKETS"):
            build.verify_config(fragment.replace("CONFIG_VIRTIO_VSOCKETS=y", "# CONFIG_VIRTIO_VSOCKETS is not set"), fragment)
        self.assertEqual(build.config_values("# CONFIG_MODULES is not set\n"), {"CONFIG_MODULES": "n"})

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

    def test_kernel_archive_has_one_root_and_makefile(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as tar:
                member = tarfile.TarInfo("linux-pinned/Makefile")
                member.size = 5
                tar.addfile(member, io.BytesIO(b"hello"))
                link = tarfile.TarInfo("linux-pinned/Makefile.link")
                link.type = tarfile.SYMTYPE
                link.linkname = "Makefile"
                tar.addfile(link)
            source = build.unpack_kernel(archive, root)
            self.assertEqual((source / "Makefile").read_bytes(), b"hello")
            self.assertEqual((source / "Makefile.link").read_bytes(), b"hello")

    def test_library_paths_are_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as name:
            source = pathlib.Path(name) / "library"
            source.write_bytes(b"lib")
            self.assertEqual(build.library_spec(f"usr/lib/libc.so.6={source}"), ("usr/lib/libc.so.6", source))
            for destination in ["/lib/x", "lib/../../x", "sbin/init", "lib/sub/x", "lib/a b", "lib/x\nquit"]:
                with self.subTest(destination=destination), self.assertRaises(ValueError):
                    build.library_spec(f"{destination}={source}")

    def test_macos_binary_is_not_a_linux_guest_artifact(self):
        with tempfile.TemporaryDirectory() as name:
            binary = pathlib.Path(name) / "agent"
            binary.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(100))
            with self.assertRaisesRegex(ValueError, "x86-64 ELF"):
                build.elf_details(binary)

    def test_missing_dynamic_loader_and_transitive_dependency_refuse(self):
        with patch.object(build, "elf_details", return_value=("/lib64/ld-linux-x86-64.so.2", [])):
            with self.assertRaisesRegex(ValueError, "interpreter"):
                build.validate_libraries("agent", {})
        with patch.object(build, "elf_details", return_value=(None, ["libc.so.6"])):
            with self.assertRaisesRegex(ValueError, "dependency"):
                build.validate_libraries("agent", {})
        with patch.object(build, "elf_details", return_value=(None, ["libc.so.6"])):
            build.validate_libraries("agent", {"usr/lib/libc.so.6": "libc"})

    def test_rootfs_recipe_stages_init_and_pins_receipt_without_mount(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            agent = root / "agent"
            agent.write_bytes(b"fixture binary, not native execution")
            loader = root / "loader"
            loader.write_bytes(b"fixture interpreter")
            args = argparse.Namespace(agent=agent, sha256=build.sha256(agent),
                                      library=[f"lib64/ld-linux-x86-64.so.2={loader}"],
                                      output=root / "image", epoch=1_700_000_000, size_mib=32)
            with patch.object(build, "validate_libraries"), patch.object(build, "run", return_value="") as runner:
                build.build_rootfs(args)
            self.assertEqual((args.output / "tree/sbin/oneiron-guest").read_bytes(), agent.read_bytes())
            self.assertTrue((args.output / "tree/tmp").is_dir())
            self.assertEqual((args.output / "tree/lib64/ld-linux-x86-64.so.2").stat().st_mode & 0o777, 0o755)
            receipt = json.loads((args.output / "rootfs-receipt.json").read_text())
            self.assertEqual(receipt["rootfs_sha256"], build.sha256(args.output / "rootfs.ext4"))
            self.assertEqual(receipt["files"]["sbin/oneiron-guest"], args.sha256)
            self.assertEqual([call.args[0] for call in runner.call_args_list], ["mke2fs", "debugfs"])
            self.assertIn("set_inode_field /sbin/oneiron-guest uid 0", runner.call_args_list[1].kwargs["stdin"])
            with self.assertRaises(FileExistsError):
                build.new_output(args.output)


if __name__ == "__main__":
    unittest.main()
