"""P8 acceptance for sidecar session namespaces and scoped mounts."""

from __future__ import annotations

from runtime_assets import artifact_args

import argparse
import pathlib
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-p8-"))
    workspaces = {name: root / f"workspace-{name}" for name in ("a", "b")}
    mounts = {name: root / f"mount-{name}" for name in ("a", "b")}
    for path in [*workspaces.values(), *mounts.values()]:
        path.mkdir()
    state = root / "state"
    process = subprocess.Popen(
        [
            str(args.nvxd), "--hypervisor", "whp", *artifact_args(args.repo, args.initrd), "--cpu-profile", "host",
            "--max-running", "2", "--session-isolation", "--state-dir", str(state),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + args.timeout
    stderr_lines = sidecar.stderr
    try:
        probe = sidecar.ok({"id": 1, "op": "probe"}, deadline)
        if probe.get("capabilities", {}).get("sessionIsolation") is not False:
            raise RuntimeError("isolation must stay unadvertised before a VM is booted")
        for index, (policy, reason) in enumerate((
            ({"sessionIsolation": False}, "E_SESSION_MODE_MISMATCH"),
            ({"networkPolicy": "allow"}, "E_SESSION_NETWORK_UNSUPPORTED"),
            ({"networkPolicy": {"allow": ["example.invalid"]}}, "E_SESSION_NETWORK_UNSUPPORTED"),
            ({"independentKernel": True}, "E_SESSION_KERNEL_UNSUPPORTED"),
        )):
            sidecar.refused({
                "id": 300 + index, "op": "session.open", "session": "refused",
                "workspace": str(workspaces["a"]), **policy,
            }, deadline, reason)
        refused_state = sidecar.ok({"id": 310, "op": "diagnostics"}, deadline)
        if refused_state["vm"] is not None or refused_state["sessionCount"]:
            raise RuntimeError(f"unsupported policy created resources: {refused_state}")
        print("CASE p8.sidecar.unsupported_policy_refused PASS", flush=True)
        for request_id, name in ((2, "a"), (3, "b")):
            sidecar.ok({
                "id": request_id, "op": "session.open", "session": name,
                "workspace": str(workspaces[name]), "memoryMiB": 1024,
                "sessionIsolation": True, "networkPolicy": "deny", "independentKernel": False,
            }, deadline)
        active_probe = sidecar.ok({"id": 4, "op": "probe"}, deadline)
        if active_probe.get("capabilities", {}).get("sessionIsolation") is not True:
            raise RuntimeError(f"active VM did not report isolation: {active_probe}")
        print("CASE p8.sidecar.capability PASS")
        first = sidecar.ok({
            "id": 10, "op": "exec", "session": "a", "execId": "a1",
            "argv": ["sh", "-ec", "echo secret >/tmp/private; echo a >/workspace/mounts/data/marker"],
            "cwd": str(workspaces["a"]),
            "mounts": [{"mountId": "data", "hostPath": str(mounts["a"]), "mode": "rw"}],
        }, deadline)
        if first.get("state") != "queued":
            raise RuntimeError(f"first isolated exec was not accepted: {first}")
        sidecar.succeeded(["a1"], deadline)
        second = sidecar.ok({
            "id": 11, "op": "exec", "session": "b", "execId": "b1",
            "argv": ["sh", "-ec", "test ! -e /tmp/private; test ! -e /workspace/mounts/data/marker"],
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
            "argv": ["sh", "-ec", "test \"$(cat /tmp/private)\" = secret; "
                     "test \"$(cat /workspace/mounts/data/marker)\" = a"],
            "cwd": str(workspaces["a"]),
            "mounts": [{"mountId": "data", "hostPath": str(mounts["a"]), "mode": "rw"}],
        }, deadline)
        sidecar.succeeded(["a2"], deadline)
        print("CASE p8.sidecar.same_session_state PASS")
        sidecar.ok({"id": 13, "op": "session.close", "session": "a"}, deadline)
        sidecar.ok({
            "id": 14, "op": "exec", "session": "b", "execId": "b2",
            "argv": ["sh", "-c", "echo b >/tmp/alive; test \"$(cat /tmp/alive)\" = b"],
            "cwd": str(workspaces["b"]),
        }, deadline)
        sidecar.succeeded(["b2"], deadline)
        sidecar.ok({
            "id": 50, "op": "session.open", "session": "a",
            "workspace": str(workspaces["a"]), "memoryMiB": 1024,
        }, deadline)
        sidecar.ok({
            "id": 51, "op": "exec", "session": "a", "execId": "a-new-instance",
            "argv": ["sh", "-ec", "test ! -e /tmp/private; "
                     "test \"$(cat /workspace/mounts/data/marker)\" = a"],
            "mounts": [{"mountId": "data", "hostPath": str(mounts["a"]), "mode": "rw"}],
        }, deadline)
        sidecar.succeeded(["a-new-instance"], deadline)
        sidecar.ok({"id": 52, "op": "session.close", "session": "a"}, deadline)
        print("CASE p8.sidecar.reopen_private_state_reset PASS", flush=True)
        # More than the guest's 64 live-session slots, with B keeping the same VM
        # alive throughout. Logical close without guest namespace destruction
        # exhausts that table; destroying the entire VM would lose B's marker.
        before = sidecar.ok({"id": 90, "op": "diagnostics"}, deadline)
        for index in range(66):
            name = f"reopen{index}"
            opened = sidecar.ok({
                "id": 100 + index * 2, "op": "session.open", "session": name,
                "workspace": str(workspaces["a"]), "memoryMiB": 1024,
            }, deadline)
            if opened["runtimeId"] != before["vm"]["runtimeId"]:
                raise RuntimeError("session close churn replaced the peer's VM")
            sidecar.ok({"id": 101 + index * 2, "op": "session.close", "session": name}, deadline)
            if index % 8 == 0:
                print(f"guest session close/reopen {index + 1}/66", flush=True)
        sidecar.ok({
            "id": 240, "op": "exec", "session": "b", "execId": "b-after-churn",
            "argv": ["sh", "-ec", "test \"$(cat /tmp/alive)\" = b"],
        }, deadline)
        sidecar.succeeded(["b-after-churn"], deadline)
        cleaned = sidecar.ok({"id": 241, "op": "diagnostics"}, deadline)
        if cleaned["sessionCount"] != 1 or cleaned["cleanupPending"]:
            raise RuntimeError(f"closed session resources were not reclaimed: {cleaned}")
        print("CASE p8.sidecar.guest_session_close_reclaims PASS", flush=True)
        sidecar.ok({"id": 15, "op": "session.close", "session": "b"}, deadline)
        print("CASE p8.sidecar.close_preserves_peer PASS")
        return 0
    except Exception:
        print("\n".join(stderr_lines[-40:]))
        raise
    finally:
        stop_sidecar(process)
        if process.returncode not in (0, None):
            tail = "\n".join(stderr_lines[-20:])
            print(tail)


if __name__ == "__main__":
    raise SystemExit(main())
