"""P8 acceptance for group failure after an isolated VM disappears."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar, vmm_processes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-p8-faults-"))
    workspace_a = root / "workspace-a"
    workspace_b = root / "workspace-b"
    workspace_c = root / "workspace-c"
    for workspace in (workspace_a, workspace_b, workspace_c):
        workspace.mkdir()
    process = subprocess.Popen(
        [
            str(args.nvxd), "--hypervisor", "whp", "--repo", str(args.repo),
            "--initrd", str(args.initrd), "--cpu-profile", "host",
            "--max-running", "2", "--session-isolation",
            "--state-dir", str(root / "state"),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + args.timeout
    vm_handles = []
    try:
        opened_a = sidecar.ok({
            "id": 1, "op": "session.open", "session": "a",
            "workspace": str(workspace_a), "memoryMiB": 1024,
        }, deadline)
        vm_handles = vmm_processes(process.pid)
        sidecar.ok({
            "id": 2, "op": "session.open", "session": "b",
            "workspace": str(workspace_b), "memoryMiB": 1024,
        }, deadline)
        for index, name in enumerate(("a", "b")):
            sidecar.ok({
                "id": 30 + index, "op": "exec", "session": name, "execId": f"warm-{name}",
                "argv": ["true"],
            }, deadline)
            sidecar.succeeded([f"warm-{name}"], deadline)
        sidecar.ok({
            "id": 3, "op": "exec", "session": "a", "execId": "a-long",
            "argv": ["sh", "-c", "echo ready; sleep 60; echo late"],
            "cwd": str(workspace_a),
        }, deadline)
        sidecar.ok({
            "id": 4, "op": "exec", "session": "b", "execId": "b-long",
            "argv": ["sh", "-c", "echo ready; sleep 60; echo late"],
            "cwd": str(workspace_b),
        }, deadline)
        while any(b"ready" not in sidecar.stdout_of(key) for key in ("a-long", "b-long")):
            sidecar.pump(deadline)
        sidecar.ok({
            "id": 40, "op": "exec", "session": "a", "execId": "queued",
            "argv": ["sh", "-c", "echo must-not-run"],
        }, deadline)
        before = sidecar.ok({"id": 41, "op": "diagnostics"}, deadline)
        if before["queued"] != 1 or len(before["running"]) != 2:
            raise RuntimeError(f"fault did not reach the required running/queued state: {before}")
        for handle in vm_handles:
            handle.kill()
            handle.wait()
        exits = sidecar.await_exits(["a-long", "b-long", "queued"], deadline)
        for exec_id, terminal in exits.items():
            if terminal.get("outcome") not in ("failed", "signalled", "signaled"):
                raise RuntimeError(f"{exec_id} did not get a terminal group failure: {terminal}")
            if terminal.get("generation") != opened_a["vmGeneration"]:
                raise RuntimeError(f"failure attributed to a wrong generation: {terminal}")
        if sidecar.stdout_of("queued"):
            raise RuntimeError("queued task ran after the VM was lost")
        print("CASE p8.faults.vm_loss_group_failure PASS")

        reopened = sidecar.ok({
            "id": 5, "op": "session.open", "session": "c",
            "workspace": str(workspace_c), "memoryMiB": 1024,
        }, deadline)
        if reopened.get("runtimeId") == opened_a.get("runtimeId"):
            raise RuntimeError("the lost isolated runtime identity was reused")
        if reopened["vmGeneration"] <= opened_a["vmGeneration"]:
            raise RuntimeError("the lost generation number was reused")
        sidecar.refused({
            "id": 42, "op": "exec", "session": "c", "execId": "stale",
            "generation": opened_a["vmGeneration"], "argv": ["true"],
        }, deadline, "E_BACKEND_GENERATION_STALE")
        sidecar.ok({
            "id": 6, "op": "exec", "session": "c", "execId": "after-loss",
            "argv": ["sh", "-c", "echo recovered"],
            "cwd": str(workspace_c),
        }, deadline)
        sidecar.succeeded(["after-loss"], deadline)
        terminal = sidecar.exits["after-loss"]
        if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
            raise RuntimeError(f"rebuilt isolated VM did not accept work: {terminal}")
        print("CASE p8.faults.rebuild_generation PASS")
        clean = sidecar.ok({"id": 43, "op": "diagnostics"}, deadline)
        if clean["sessionCount"] != 1 or clean["cleanupPending"] or clean["queued"] or clean["running"]:
            raise RuntimeError(f"old group resources survived: {clean}")
        print(f"fault evidence: victims={exits}, rebuilt={reopened}, cleanup={clean}", flush=True)
        return 0
    finally:
        try:
            stop_sidecar(process)
        finally:
            for handle in vm_handles:
                handle.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit(f"nvxd isolated fault cases failed: {error!r}")
