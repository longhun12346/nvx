"""Regression checks for strict workload profiles and dependency closure."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nvx_tools import workloads
from nvx_tools.common import ScriptError
from nvx_tools.workload_check import check


class WorkloadLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        paths = {}
        for name in ("LOCK", "REQUIREMENTS", "NODE_MANIFEST", "NODE_LOCK"):
            source = getattr(workloads, name)
            target = self.root / source.name
            target.write_bytes(source.read_bytes())
            paths[name] = target
        patcher = patch.multiple(workloads, **paths)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_declared_profile_is_locked(self):
        document = workloads.load_lock()
        self.assertEqual(len(document["requirements"]), 26)
        self.assertEqual(len(document["node"]["dependencies"]), 8)

    def test_python_requirement_drift_is_rejected(self):
        workloads.REQUIREMENTS.write_text("plotille>=6,<7\n")
        with self.assertRaisesRegex(ScriptError, "requirements differ"):
            workloads.load_lock()

    def test_extra_node_direct_dependency_is_rejected(self):
        document = json.loads(workloads.NODE_MANIFEST.read_text())
        document["dependencies"]["unrequested-package"] = "*"
        workloads.NODE_MANIFEST.write_text(json.dumps(document))
        with self.assertRaisesRegex(ScriptError, "manifest differs"):
            workloads.load_lock()

    def test_node_lock_content_change_is_rejected(self):
        document = json.loads(workloads.NODE_LOCK.read_text())
        document["packages"]["node_modules/sharp"]["version"] = "0.34.0"
        workloads.NODE_LOCK.write_text(json.dumps(document))
        with self.assertRaisesRegex(ScriptError, "manifest differs"):
            workloads.load_lock()


class InstalledClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.distribution("pip", "25.3")
        self.distribution("example", "1.0", ["leaf>=2,<3"])
        self.distribution("leaf", "2.0")

    def distribution(self, name, version, requires=()):
        path = self.root / f"{name}-{version}.dist-info"
        path.mkdir()
        (path / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            + "".join(f"Requires-Dist: {value}\n" for value in requires))

    def test_transitive_dependencies_are_allowed(self):
        self.assertEqual(set(check(self.root, ["example>=1,<2"])), {"pip", "example", "leaf"})

    def test_unrequested_package_is_rejected(self):
        self.distribution("unrequested", "1.0")
        with self.assertRaisesRegex(ValueError, "outside the workload dependency closure"):
            check(self.root, ["example>=1,<2"])

    def test_incompatible_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsatisfied workload requirement"):
            check(self.root, ["example>=2,<3"])


if __name__ == "__main__":
    unittest.main()
