"""P8 acceptance for trusted-shared -> isolated mode migration.

The session isolation bit is immutable for a running sidecar. A mode change therefore has to
drain the old process/VM and construct a new one. This test exercises that boundary with real
WHP VMs:

* the trusted sidecar exposes shared state and does not advertise isolation;
* it is shut down cleanly before the isolated sidecar is started;
* the isolated sidecar advertises isolation, uses a new runtime identity, and does not inherit
  state from the trusted VM;
* two isolated sessions still have private state after the migration.
"""

from __future__ import annotations

from runtime_assets import artifact_args

import argparse
import pathlib
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar, vmm_processes


def start(nvxd: pathlib.Path, repo: pathlib.Path, initrd: pathlib.Path,
          state: pathlib.Path, isolated: bool):
    command = [
        str(nvxd),
        "--hypervisor", "whp",
        *artifact_args(repo, initrd),
        "--cpu-profile", "host",
        "--max-running", "2",
        "--state-dir", str(state),
    ]
    if isolated:
        command.append("--session-isolation")
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        return process, BoundedSidecar(process)
    except Exception:
        stop_sidecar(process)
        raise


def stop(process: subprocess.Popen) -> None:
    stop_sidecar(process)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    for path, label in (
        (args.nvxd, "sidecar"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")

    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-p8-migration-"))
    trusted = None
    isolated = None
    vm_handles = []
    try:
        trusted_ws_a = root / "trusted-a"
        trusted_ws_b = root / "trusted-b"
        isolated_ws_a = root / "isolated-a"
        isolated_ws_b = root / "isolated-b"
        for workspace in (trusted_ws_a, trusted_ws_b, isolated_ws_a, isolated_ws_b):
            workspace.mkdir()

        deadline = time.monotonic() + args.timeout
        trusted_process, trusted = start(
            args.nvxd, args.repo, args.initrd, root / "trusted-state", False
        )
        trusted_probe = trusted.ok({"id": 1, "op": "probe"}, deadline)
        if trusted_probe.get("capabilities", {}).get("sessionIsolation") is not False:
            raise RuntimeError(f"trusted mode advertised isolation: {trusted_probe}")
        trusted_a = trusted.ok({
            "id": 2, "op": "session.open", "session": "a",
            "workspace": str(trusted_ws_a), "memoryMiB": 1024,
        }, deadline)
        trusted_b = trusted.ok({
            "id": 3, "op": "session.open", "session": "b",
            "workspace": str(trusted_ws_b), "memoryMiB": 1024,
        }, deadline)
        if trusted_a.get("runtimeId") != trusted_b.get("runtimeId"):
            raise RuntimeError("trusted sessions did not share one runtime")
        vm_handles = vmm_processes(trusted_process.pid)
        trusted.ok({
            "id": 4, "op": "exec", "session": "a", "execId": "trusted-write",
            "argv": ["sh", "-ec", "echo inherited >/tmp/migration-marker; echo ready; "
                     "while [ ! -f /sessions/a/workspace/release ]; do sleep 0.05; done"],
            "cwd": str(trusted_ws_a),
        }, deadline)
        while b"ready" not in trusted.stdout_of("trusted-write"):
            trusted.pump(deadline)
        trusted.refused({
            "id": 40, "op": "session.open", "session": "forbidden",
            "workspace": str(isolated_ws_a), "memoryMiB": 1024, "sessionIsolation": True,
        }, deadline, "E_SESSION_MODE_MISMATCH")
        unchanged = trusted.ok({"id": 41, "op": "diagnostics"}, deadline)
        if unchanged["sessionCount"] != 2 or unchanged["vm"]["runtimeId"] != trusted_a["runtimeId"]:
            raise RuntimeError(f"refused migration changed the running group: {unchanged}")
        (trusted_ws_a / "release").write_text("release", encoding="utf-8")
        trusted.succeeded(["trusted-write"], deadline)
        print("CASE p8.migration.active_switch_refused PASS", flush=True)
        visible = trusted.ok({
            "id": 5, "op": "exec", "session": "b", "execId": "trusted-read",
            "argv": ["sh", "-c", "test \"$(cat /tmp/migration-marker)\" = inherited"],
            "cwd": str(trusted_ws_b),
        }, deadline)
        trusted.succeeded(["trusted-read"], deadline)
        if visible.get("state") != "queued":
            raise RuntimeError(f"trusted read was not accepted: {visible}")
        if trusted.exits["trusted-read"].get("outcome") != "exited" or \
                trusted.exits["trusted-read"].get("code") != 0:
            raise RuntimeError(f"trusted state was not shared: {trusted.exits['trusted-read']}")
        trusted.ok({"id": 6, "op": "session.close", "session": "a"}, deadline)
        trusted.ok({"id": 7, "op": "session.close", "session": "b"}, deadline)
        stop(trusted_process)
        for handle in vm_handles:
            handle.wait()
            handle.close()
        vm_handles.clear()
        trusted = None
        print("CASE p8.migration.trusted_drained PASS")

        isolated_process, isolated = start(
            args.nvxd, args.repo, args.initrd, root / "isolated-state", True
        )
        isolated_a = isolated.ok({
            "id": 11, "op": "session.open", "session": "a",
            "workspace": str(isolated_ws_a), "memoryMiB": 1024,
        }, deadline)
        isolated_b = isolated.ok({
            "id": 12, "op": "session.open", "session": "b",
            "workspace": str(isolated_ws_b), "memoryMiB": 1024,
        }, deadline)
        isolated_probe = isolated.ok({"id": 13, "op": "probe"}, deadline)
        if isolated_probe.get("capabilities", {}).get("sessionIsolation") is not True:
            raise RuntimeError(f"isolated mode did not advertise isolation: {isolated_probe}")
        if isolated_a.get("runtimeId") == trusted_a.get("runtimeId"):
            raise RuntimeError("mode migration reused the old runtime identity")
        if isolated_a.get("runtimeId") != isolated_b.get("runtimeId"):
            raise RuntimeError("isolated sessions did not share the rebuilt runtime")
        print("CASE p8.migration.drain_rebuild PASS")

        isolated.ok({
            "id": 14, "op": "exec", "session": "b", "execId": "isolated-read",
            "argv": ["sh", "-c", "test ! -e /tmp/migration-marker"],
            "cwd": str(isolated_ws_b),
        }, deadline)
        isolated.succeeded(["isolated-read"], deadline)
        terminal = isolated.exits["isolated-read"]
        if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
            raise RuntimeError(f"trusted state leaked into isolated VM: {terminal}")
        isolated.ok({
            "id": 15, "op": "exec", "session": "a", "execId": "isolated-write",
            "argv": ["sh", "-c", "echo private >/tmp/private-marker"],
            "cwd": str(isolated_ws_a),
        }, deadline)
        isolated.succeeded(["isolated-write"], deadline)
        isolated.ok({
            "id": 16, "op": "exec", "session": "b", "execId": "isolated-peer",
            "argv": ["sh", "-c", "test ! -e /tmp/private-marker"],
            "cwd": str(isolated_ws_b),
        }, deadline)
        isolated.succeeded(["isolated-write", "isolated-peer"], deadline)
        for exec_id in ("isolated-write", "isolated-peer"):
            terminal = isolated.exits[exec_id]
            if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
                raise RuntimeError(f"isolated state leaked between sessions: {exec_id}: {terminal}")
        print("CASE p8.migration.old_state_not_inherited PASS")
        isolated.ok({"id": 17, "op": "session.close", "session": "a"}, deadline)
        isolated.ok({"id": 18, "op": "session.close", "session": "b"}, deadline)
        rebuilt = isolated.ok({
            "id": 19, "op": "session.open", "session": "a",
            "workspace": str(isolated_ws_a), "memoryMiB": 1024,
        }, deadline)
        if rebuilt["vmGeneration"] <= isolated_a["vmGeneration"] or \
                rebuilt["runtimeId"] == isolated_a["runtimeId"]:
            raise RuntimeError(f"drained VM identity was reused: {isolated_a} -> {rebuilt}")
        isolated.ok({
            "id": 20, "op": "exec", "session": "a", "execId": "rebuilt-clean",
            "argv": ["sh", "-ec", "test ! -e /tmp/private-marker; test ! -e /tmp/migration-marker"],
        }, deadline)
        isolated.succeeded(["rebuilt-clean"], deadline)
        print(f"generation evidence: {trusted_a} -> {isolated_a} -> {rebuilt}", flush=True)
        print("CASE p8.migration.generation_replaced PASS", flush=True)
        stop(isolated_process)
        isolated = None
        return 0
    finally:
        for handle in vm_handles:
            handle.close()
        if trusted is not None:
            try:
                stop(trusted.process)
            except Exception:
                trusted.process.kill()
                trusted.process.wait()
        if isolated is not None:
            try:
                stop(isolated.process)
            except Exception:
                isolated.process.kill()
                isolated.process.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit(f"nvxd migration cases failed: {error!r}")
