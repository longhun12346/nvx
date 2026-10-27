"""Regression tests for the product EROFS stage build entry points."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import nvx
from nvx_tools import build, ubuntu
from nvx_tools.build_config import BuildConfig, InitramfsBuildConfig
from nvx_tools.build_constants import UbuntuBuildConstants
from nvx_tools.common import ScriptError
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/nvxd/tests"))
from runtime_assets import artifact_args


class StageRoutingTests(unittest.TestCase):
    def assert_stage_paths(self, config):
        full = BuildConfig.initramfs_config("ubuntu").output
        self.assertEqual(config.source, full)
        self.assertNotEqual(config.output, full)
        self.assertEqual(config.output.name, UbuntuBuildConstants.STAGE_INITRAMFS_NAME)

    def test_initramfs_command_keeps_full_image(self):
        with (
            patch.object(nvx, "build_initramfs") as full,
            patch.object(nvx, "build_stage_initramfs") as stage,
        ):
            args = nvx.parse_args(["build-initramfs", "--guest", "ubuntu"])
            args.handler(args)
        full.assert_called_once()
        stage.assert_called_once()
        self.assert_stage_paths(stage.call_args.args[0])

    def test_native_guest_build_keeps_full_image(self):
        with (
            patch.object(build, "build_kernel"),
            patch.object(build, "build_initramfs") as full,
            patch.object(build, "build_stage_initramfs") as stage,
        ):
            build.build_guest(BuildConfig(guest="ubuntu", native_guest=True))
        full.assert_called_once()
        stage.assert_called_once()
        self.assert_stage_paths(stage.call_args.args[0])

    def test_source_cannot_be_overwritten_even_through_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "full.cpio.gz"
            source.write_bytes(b"full image")
            alias = source.with_name("alias.cpio.gz")
            os.link(source, alias)
            for output in (source, alias):
                with (
                    self.subTest(output=output.name),
                    patch.object(build, "_require_linux"),
                    patch.object(build.subprocess, "Popen") as process,
                ):
                    with self.assertRaisesRegex(ScriptError, "source"):
                        build.build_stage_initramfs(
                            InitramfsBuildConfig(guest="ubuntu", source=source, output=output)
                        )
                    process.assert_not_called()
                    self.assertEqual(source.read_bytes(), b"full image")

    def test_gate_passes_external_distro_and_does_not_autodiscover(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            external = repo / "external image.erofs"
            external.write_bytes(b"selected")
            with patch.dict(os.environ, {"NVX_DISTRO": str(external)}):
                arguments = artifact_args(repo, repo / "stage.cpio.gz")
                self.assertNotIn("--repo", arguments)
                self.assertEqual(arguments[-2:], ["--distro", str(external.resolve())])
            with patch.dict(os.environ, {"NVX_DISTRO": ""}):
                (repo / "build").mkdir()
                (repo / "build/ubuntu-distro.erofs").write_bytes(b"unselected")
                arguments = artifact_args(repo, repo / "full.cpio.gz")
                self.assertNotIn("--repo", arguments)
                self.assertNotIn("--distro", arguments)
            with patch.dict(os.environ, {"NVX_DISTRO": str(repo / "missing")}):
                with self.assertRaisesRegex(ValueError, "missing"):
                    artifact_args(repo, repo / "stage.cpio.gz")


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux cpio")
class StageArchiveTests(unittest.TestCase):
    def test_root_builder_refuses_filesystems_that_ignore_chmod(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            ubuntu.require_posix_permissions(work)
            with patch.object(Path, "chmod"):
                with self.assertRaisesRegex(ScriptError, "POSIX permissions"):
                    ubuntu.require_posix_permissions(work)

    def test_real_archive_preserves_source_and_records_custom_output(self):
        for command in ("cpio", "gzip", "find", "sort"):
            if shutil.which(command) is None:
                self.skipTest(f"{command} unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            (source_root / "bin").mkdir(parents=True)
            (source_root / "bin" / "busybox").write_bytes(b"fixture busybox")
            (source_root / "bin" / "busybox").chmod(0o755)
            source = root / "full.cpio.gz"
            build._pack_initramfs(source_root, source)
            original = source.read_bytes()
            output = root / "custom-stage.cpio.gz"
            build.build_stage_initramfs(
                InitramfsBuildConfig(guest="ubuntu", source=source, output=output)
            )
            self.assertEqual(source.read_bytes(), original)
            manifest = json.loads(
                Path(str(output) + ".manifest.json").read_text()
            )
            self.assertEqual(manifest["artifact"], output.name)
            self.assertEqual(manifest["artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(manifest["source_artifact_sha256"], hashlib.sha256(original).hexdigest())
            unpacked = root / "unpacked"
            unpacked.mkdir()
            import gzip
            subprocess.run(
                ["cpio", "-idm", "--quiet"],
                input=gzip.decompress(output.read_bytes()), cwd=unpacked, check=True,
            )
            self.assertEqual(os.readlink(unpacked / "bin" / "sh"), "busybox")
            self.assertEqual((unpacked / "bin" / "busybox").read_bytes(), b"fixture busybox")
            self.assertIn("switch_root", (unpacked / "init").read_text())
            self.assertTrue(os.access(unpacked / "init", os.X_OK))


if __name__ == "__main__":
    unittest.main()
