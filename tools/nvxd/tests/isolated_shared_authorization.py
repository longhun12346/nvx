"""Same host roots, separately authorized workspace and ro/rw mount lifetimes."""

from runtime_assets import artifact_args

import argparse
import json
import pathlib
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar


def main():
    parser = argparse.ArgumentParser()
    for key in ("nvxd", "repo", "initrd"):
        parser.add_argument("--" + key, required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvx-p8-shared-auth-"))
    workspace = root / "workspace"
    data = root / "data"
    workspace.mkdir()
    data.mkdir()
    (data / "marker").write_text("shared")
    process = subprocess.Popen([
        str(args.nvxd), *artifact_args(args.repo, args.initrd),
        "--hypervisor", "whp", "--cpu-profile", "host", "--session-isolation",
        "--state-dir", str(root / "state"),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + 180
    request_id = 0

    def call(op, **fields):
        nonlocal request_id
        request_id += 1
        return sidecar.ok(dict(id=request_id, op=op, **fields), deadline)

    def execute(name, key, script):
        return call("exec", session=name, execId=key, argv=["sh", "-ec", script],
                    mounts=[dict(mountId="data", hostPath=str(data),
                                 mode="ro" if name == "a" else "rw")], timeoutMs=60000)

    try:
        first = call("session.open", session="a", workspace=str(workspace), memoryMiB=1024)
        second = call("session.open", session="b", workspace=str(workspace), memoryMiB=1024)
        if first["runtimeId"] != second["runtimeId"]:
            raise RuntimeError("independently authorizing the same workspace replaced the VM")
        execute("a", "reader", "test \"$(cat /workspace/mounts/data/marker)\" = shared; "
                "! touch /workspace/mounts/data/forbidden 2>/dev/null; echo private >/tmp/a-only")
        sidecar.succeeded(["reader"], deadline)
        execute("b", "writer", "test ! -e /tmp/a-only; "
                "echo updated >/workspace/mounts/data/marker; echo host >/workspace/authorized")
        sidecar.succeeded(["writer"], deadline)
        # A host file at a directory mount target forces the private bind to
        # fail after its VMM export has already been created.
        blocked = workspace / "mounts/blocked"
        blocked.write_text("not a directory")
        extra = root / "extra"
        extra.mkdir()
        (extra / "marker").write_text("rollback recovered")
        requested = [
            dict(mountId="data", hostPath=str(data), mode="ro"),
            dict(mountId="blocked", hostPath=str(extra), mode="ro"),
        ]
        before_rollback = call("diagnostics")
        call("exec", session="a", execId="bind-refused", argv=["echo", "forbidden"],
             mounts=requested)
        refused = sidecar.await_exits(["bind-refused"], deadline)["bind-refused"]
        if refused["outcome"] != "failed" or "E_SESSION_MOUNT_FAILED" not in refused["detail"] \
                or sidecar.stdout_of("bind-refused"):
            raise RuntimeError(f"unsafe bind was not rejected: {refused}")
        after_rollback = call("diagnostics")
        if not after_rollback["vm"] or after_rollback["vm"]["runtimeId"] != first["runtimeId"]:
            raise RuntimeError("recoverable bind failure retired the peer's VM")
        if after_rollback["stats"]["sharesRemoved"] != before_rollback["stats"]["sharesRemoved"] + 1:
            raise RuntimeError(f"failed bind left an untracked source export: {after_rollback}")
        blocked.unlink()
        call("exec", session="a", execId="bind-recovered",
             argv=["cat", "/workspace/mounts/blocked/marker"], mounts=requested)
        sidecar.succeeded(["bind-recovered"], deadline)
        if sidecar.stdout_of("bind-recovered") != b"rollback recovered":
            raise RuntimeError("corrected authorization did not recover")
        print("CASE p8.mounts.bind_failure_rollback PASS", flush=True)
        execute("a", "reader-active", "test \"$(cat /workspace/mounts/data/marker)\" = updated; "
                "test \"$(cat /workspace/authorized)\" = host; "
                "! touch /workspace/mounts/data/forbidden 2>/dev/null; "
                "echo ready >/workspace/reader.ready; "
                "while [ ! -f /workspace/reader.release ]; do sleep 0.05; done; "
                "test \"$(cat /workspace/mounts/data/marker)\" = updated; "
                "! touch /workspace/mounts/data/still-forbidden 2>/dev/null")
        while not (workspace / "reader.ready").exists():
            if time.monotonic() >= deadline or "reader-active" in sidecar.exits:
                raise RuntimeError("reader never reached its live barrier")
            call("diagnostics")
            time.sleep(0.02)
        call("session.close", session="b")
        after = call("diagnostics")
        if after["vm"]["runtimeId"] != first["runtimeId"] or after["cleanupPending"] or \
                "reader-active" not in after["running"]:
            raise RuntimeError(f"writer close revoked reader's independent authorization: {after}")
        (workspace / "reader.release").write_text("go")
        sidecar.succeeded(["reader-active"], deadline)
        call("session.close", session="a")
        clean = call("diagnostics")
        if clean["vm"] or clean["sessionCount"] or clean["cleanupPending"]:
            raise RuntimeError(f"shared-root exports leaked: {clean}")
        print(json.dumps({"opened": [first, second], "afterWriterClose": after, "clean": clean}))
        print("CASE p8.mounts.explicit_shared_authorization PASS", flush=True)
    finally:
        stop_sidecar(process)


if __name__ == "__main__":
    main()
