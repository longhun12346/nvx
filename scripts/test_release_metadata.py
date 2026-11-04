"""Publication contract tests (standard library only)."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from release_metadata import generate


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.binaries = self.repo / "bin"
        self.guest = self.repo / "guest"
        self.revision = "a" * 40
        self.openvmm = "b" * 40
        for directory, name in [(self.binaries, "BUILD-INFO.txt"), (self.guest, "GUEST-INFO.txt")]:
            directory.mkdir()
            info = f"nvx_revision={self.revision}\nopenvmm_revision={self.openvmm}\n"
            (directory / name).write_text(info)
            (directory / "asset").write_bytes(b"artifact")
            (directory / "SHA256SUMS").write_text(hashlib.sha256(b"artifact").hexdigest() + "  asset\n")

    def git(self, args):
        if "ls-tree" in args:
            return f"160000 commit {self.openvmm}\topenvmm\n".encode()
        if "rev-parse" in args:
            return ("c" * 40 + "\n").encode()
        return {
            self.revision + ":VERSION": b"0.1.0\n",
            self.revision + ":tools/nvxd/Cargo.toml": b'[package]\nversion = "0.2.0"\n',
            self.revision + ":ubuntu/packages.lock.json": b"{}\n",
        }[args[-1]]

    def generate(self):
        with patch("release_metadata.subprocess.check_output", side_effect=self.git):
            return generate(self.repo, self.revision, self.binaries, self.guest)

    def test_records_versions_source_trees_and_all_artifact_files(self):
        metadata = self.generate()
        self.assertEqual(metadata["nvxdVersion"], "0.2.0")
        self.assertEqual(metadata["sources"]["openvmm"]["revision"], self.openvmm)
        self.assertIn("bin/BUILD-INFO.txt", metadata["files"])
        self.assertIn("guest/GUEST-INFO.txt", metadata["files"])
        self.assertNotIn(str(self.repo), json.dumps(metadata))
        self.assertEqual(metadata, self.generate())

    def test_rejects_artifact_corruption(self):
        (self.guest / "asset").write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.generate()

    def test_rejects_mixed_revisions(self):
        (self.binaries / "BUILD-INFO.txt").write_text("nvx_revision=" + "d" * 40)
        with self.assertRaisesRegex(ValueError, "revision mismatch"):
            self.generate()


if __name__ == "__main__":
    unittest.main()
