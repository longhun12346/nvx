"""P8 acceptance for sidecar session namespaces and scoped mounts."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile
import threading
import time

from shared_vm import Sidecar


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-p8-"))
    workspaces = {name: root / f"workspace-{name}" for name in ("a", "b")}
    mounts = {name: root / f"mount-{name}" for name in ("a", "b")}
    for path in [*workspaces.values(), *mounts.values()]:
        path.mkdir()
    state = root / "state"
    process = subprocess.Popen(
        [
            str(args.nvxd), "--hypervisor", "whp", "--repo", str(args.repo),
            "--initrd", str(args.initrd), "--cpu-profile", "host",
            "--max-running", "2", "--session-isolation", "--state-dir", str(state),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    sidecar = Sidecar(process)
    deadline = time.monotonic() + args.timeout
    stderr_lines: list[str] = []
    threading.Thread(
        target=lambda: [
            stderr_lines.append(line.decode(errors="replace").rstrip())
            for line in iter(process.stderr.readline, b"")
        ],
        daemon=True,
    ).start()
    try:
        ready, _ = __import__("shared_vm").read_frame(process.stdout)
        if ready.get("event") != "ready":
            raise RuntimeError(f"unexpected ready frame: {ready}")
        probe = sidecar.ok({"id": 1, "op": "probe"}, deadline)
        if probe.get("capabilities", {}).get("sessionIsolation") is not False:
            raise RuntimeError("isolation must stay unadvertised before a VM is booted")
        for request_id, name in ((2, "a"), (3, "b")):
            sidecar.ok({
                "id": request_id, "op": "session.open", "session": name,
                "workspace": str(workspaces[name]), "memoryMiB": 1024,
            }, deadline)
        active_probe = sidecar.ok({"id": 4, "op": "probe"}, deadline)
        if active_probe.get("capabilities", {}).get("sessionIsolation") is not True:
            raise RuntimeError(f"active VM did not report isolation: {active_probe}")
        print("CASE p8.sidecar.capability PASS")
        first = sidecar.ok({
            "id": 10, "op": "exec", "session": "a", "execId": "a1",
            "argv": ["sh", "-c", "echo secret >/tmp/private; echo a >/workspace/mounts/data/marker"],
            "cwd": str(workspaces["a"]),
            "mounts": [{"mountId": "data", "hostPath": str(mounts["a"]), "mode": "rw"}],
        }, deadline)
        if first.get("state") != "queued":
            raise RuntimeError(f"first isolated exec was not accepted: {first}")
        second = sidecar.ok({
            "id": 11, "op": "exec", "session": "b", "execId": "b1",
            "argv": ["sh", "-c", "test ! -e /tmp/private; test ! -e /workspace/mounts/data/marker"],
            "cwd": str(workspaces["b"]),
            "mounts": [{"mountId": "data", "hostPath": str(mounts["b"]), "mode": "rw"}],
        }, deadline)
        if second.get("state") != "queued":
            raise RuntimeError(f"second isolated exec was not accepted: {second}")
        exits = sidecar.await_exits(["a1", "b1"], deadline)
        for key in ("a1", "b1"):
            if exits[key].get("outcome") != "exited" or exits[key].get("code") != 0:
                print("events:", [
                    (head, payload.decode(errors="replace"))
                    for head, payload in sidecar.events
                    if (head.get("execId") or head.get("handle")) == key
                ])
                raise RuntimeError(f"{key} failed: {exits[key]}")
        if sidecar.stdout_of("a1") or sidecar.stdout_of("b1"):
            raise RuntimeError("unexpected diagnostic output")
        print("CASE p8.sidecar.cross_session_private_state PASS")
        # A second execution in A sees its private /tmp and its scoped mount; B cannot.
        sidecar.ok({
            "id": 12, "op": "exec", "session": "a", "execId": "a2",
            "argv": ["sh", "-c", "test \"$(cat /tmp/private)\" = secret; "
                     "test \"$(cat /workspace/mounts/data/marker)\" = a"],
            "cwd": str(workspaces["a"]),
        }, deadline)
        sidecar.await_exits(["a2"], deadline)
        print("CASE p8.sidecar.same_session_state PASS")
        sidecar.ok({"id": 13, "op": "session.close", "session": "a"}, deadline)
        sidecar.ok({
            "id": 14, "op": "exec", "session": "b", "execId": "b2",
            "argv": ["sh", "-c", "echo b >/tmp/alive; test \"$(cat /tmp/alive)\" = b"],
            "cwd": str(workspaces["b"]),
        }, deadline)
        sidecar.await_exits(["b2"], deadline)
        sidecar.ok({"id": 15, "op": "session.close", "session": "b"}, deadline)
        print("CASE p8.sidecar.close_preserves_peer PASS")
        return 0
    except Exception:
        print("\n".join(stderr_lines[-40:]))
        raise
    finally:
        try:
            process.stdin.write(b"")
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.returncode not in (0, None):
            tail = "\n".join(stderr_lines[-20:])
            print(tail)


if __name__ == "__main__":
    raise SystemExit(main())
