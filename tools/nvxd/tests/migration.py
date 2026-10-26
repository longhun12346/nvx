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

import argparse
import pathlib
import subprocess
import tempfile
import time

from shared_vm import Sidecar, read_frame


def start(nvxd: pathlib.Path, repo: pathlib.Path, initrd: pathlib.Path,
          state: pathlib.Path, isolated: bool):
    command = [
        str(nvxd),
        "--hypervisor", "whp",
        "--repo", str(repo),
        "--initrd", str(initrd),
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
    ready = read_frame(process.stdout)
    if ready is None or ready[0].get("event") != "ready":
        process.kill()
        process.wait()
        raise RuntimeError(f"sidecar did not announce ready: {ready}")
    return process, Sidecar(process)


def stop(process: subprocess.Popen) -> None:
    try:
        process.stdin.write(b"")
        process.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    if process.returncode != 0:
        detail = process.stderr.read().decode(errors="replace")[-2000:]
        raise RuntimeError(f"sidecar exited with {process.returncode}: {detail}")


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
        trusted.ok({
            "id": 4, "op": "exec", "session": "a", "execId": "trusted-write",
            "argv": ["sh", "-c", "echo inherited >/tmp/migration-marker"],
            "cwd": str(trusted_ws_a),
        }, deadline)
        trusted.await_exits(["trusted-write"], deadline)
        visible = trusted.ok({
            "id": 5, "op": "exec", "session": "b", "execId": "trusted-read",
            "argv": ["sh", "-c", "test \"$(cat /tmp/migration-marker)\" = inherited"],
            "cwd": str(trusted_ws_b),
        }, deadline)
        trusted.await_exits(["trusted-read"], deadline)
        if visible.get("state") != "queued":
            raise RuntimeError(f"trusted read was not accepted: {visible}")
        if trusted.exits["trusted-read"].get("outcome") != "exited" or \
                trusted.exits["trusted-read"].get("code") != 0:
            raise RuntimeError(f"trusted state was not shared: {trusted.exits['trusted-read']}")
        trusted.ok({"id": 6, "op": "session.close", "session": "a"}, deadline)
        trusted.ok({"id": 7, "op": "session.close", "session": "b"}, deadline)
        stop(trusted_process)
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
        isolated.await_exits(["isolated-read"], deadline)
        terminal = isolated.exits["isolated-read"]
        if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
            raise RuntimeError(f"trusted state leaked into isolated VM: {terminal}")
        isolated.ok({
            "id": 15, "op": "exec", "session": "a", "execId": "isolated-write",
            "argv": ["sh", "-c", "echo private >/tmp/private-marker"],
            "cwd": str(isolated_ws_a),
        }, deadline)
        isolated.ok({
            "id": 16, "op": "exec", "session": "b", "execId": "isolated-peer",
            "argv": ["sh", "-c", "test ! -e /tmp/private-marker"],
            "cwd": str(isolated_ws_b),
        }, deadline)
        isolated.await_exits(["isolated-write", "isolated-peer"], deadline)
        for exec_id in ("isolated-write", "isolated-peer"):
            terminal = isolated.exits[exec_id]
            if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
                raise RuntimeError(f"isolated state leaked between sessions: {exec_id}: {terminal}")
        print("CASE p8.migration.old_state_not_inherited PASS")
        isolated.ok({"id": 17, "op": "session.close", "session": "a"}, deadline)
        isolated.ok({"id": 18, "op": "session.close", "session": "b"}, deadline)
        stop(isolated_process)
        isolated = None
        return 0
    finally:
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
