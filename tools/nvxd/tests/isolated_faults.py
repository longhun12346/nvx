"""P8 acceptance for group failure after an isolated VM disappears."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile
import time

from shared_vm import Sidecar, read_frame


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
    sidecar = Sidecar(process)
    deadline = time.monotonic() + args.timeout
    try:
        ready = read_frame(process.stdout)
        if ready is None or ready[0].get("event") != "ready":
            raise RuntimeError(f"unexpected ready frame: {ready}")
        opened_a = sidecar.ok({
            "id": 1, "op": "session.open", "session": "a",
            "workspace": str(workspace_a), "memoryMiB": 1024,
        }, deadline)
        sidecar.ok({
            "id": 2, "op": "session.open", "session": "b",
            "workspace": str(workspace_b), "memoryMiB": 1024,
        }, deadline)
        sidecar.ok({
            "id": 3, "op": "exec", "session": "a", "execId": "a-long",
            "argv": ["sh", "-c", "sleep 60; echo late"],
            "cwd": str(workspace_a),
        }, deadline)
        sidecar.ok({
            "id": 4, "op": "exec", "session": "b", "execId": "b-long",
            "argv": ["sh", "-c", "sleep 60; echo late"],
            "cwd": str(workspace_b),
        }, deadline)
        time.sleep(1.5)
        subprocess.run(
            ["taskkill", "/F", "/IM", "openvmm.exe"],
            capture_output=True,
            check=False,
        )
        exits = sidecar.await_exits(["a-long", "b-long"], deadline)
        for exec_id, terminal in exits.items():
            if terminal.get("outcome") not in ("failed", "signalled", "signaled"):
                raise RuntimeError(f"{exec_id} did not get a terminal group failure: {terminal}")
        print("CASE p8.faults.vm_loss_group_failure PASS")

        reopened = sidecar.ok({
            "id": 5, "op": "session.open", "session": "c",
            "workspace": str(workspace_c), "memoryMiB": 1024,
        }, deadline)
        if reopened.get("runtimeId") == opened_a.get("runtimeId"):
            raise RuntimeError("the lost isolated runtime identity was reused")
        sidecar.ok({
            "id": 6, "op": "exec", "session": "c", "execId": "after-loss",
            "argv": ["sh", "-c", "echo recovered"],
            "cwd": str(workspace_c),
        }, deadline)
        sidecar.await_exits(["after-loss"], deadline)
        terminal = sidecar.exits["after-loss"]
        if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
            raise RuntimeError(f"rebuilt isolated VM did not accept work: {terminal}")
        print("CASE p8.faults.rebuild_generation PASS")
        return 0
    finally:
        try:
            sidecar.send({"op": "shutdown"})
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit(f"nvxd isolated fault cases failed: {error!r}")
