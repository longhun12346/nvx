"""Exercise production sidecar/agent cleanup with an external guest observer.

The observer is a diagnostic guest agent built with the `fault-observer` feature
(`cargo build --features guest,fault-observer`, see tools/nvxd-guest/README.md); the product agent has
none. It injects each fault from outside the workload namespaces and cgroups.
"""

from runtime_assets import artifact_args

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import uuid

from p8_support import BoundedSidecar, stop_sidecar, vmm_processes


def sha256(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def check_fault(args, mode, output):
    root = output / mode
    root.mkdir()
    workspaces = {name: root / name for name in ("a", "b", "c")}
    for path in workspaces.values():
        path.mkdir()
    (workspaces["a"] / "p8-target").write_text(uuid.uuid4().hex)
    mount = root / "data"
    mount.mkdir()
    (mount / "marker").write_text("authorized")
    os.environ["NVX_GUEST_AGENT"] = str(args.diagnostic_agent)
    process = subprocess.Popen([
        str(args.nvxd), *artifact_args(args.repo, args.initrd),
        "--hypervisor", "whp", "--cpu-profile", "host", "--session-isolation",
        "--max-running", "2", "--state-dir", str(root / "state"),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + 150
    request_id = 0
    handles = []
    mounts = [{"mountId": "data", "hostPath": str(mount), "mode": "ro"}]

    def call(op, **fields):
        nonlocal request_id
        request_id += 1
        return sidecar.ok(dict(id=request_id, op=op, **fields), deadline)

    def wait_file(path):
        while not path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError(f"missing guest barrier: {path}; {sidecar.stderr[-20:]}")
            call("diagnostics")
            time.sleep(0.02)

    try:
        opened = {}
        for name in ("a", "b"):
            opened[name] = call("session.open", session=name,
                                workspace=str(workspaces[name]), memoryMiB=1024)
            call("exec", session=name, execId="warm-" + name, argv=["true"],
                 mounts=mounts if name == "a" else [])
            sidecar.succeeded(["warm-" + name], deadline)
        handles = vmm_processes(process.pid)
        # In revoke cases A must have no running work when its desired mounts
        # change. Two B tasks occupy both slots; the A request is queued.
        closing = mode in ("close-directory", "close-export")
        names = ("a", "b") if mode == "keeper" or closing else ("b", "b")
        keys = []
        for index, name in enumerate(names):
            key = f"held-{index}"
            keys.append(key)
            call("exec", session=name, execId=key, argv=["sh", "-ec",
                 f"echo ready >/workspace/{key}.ready; "
                 f"while [ ! -f /workspace/{key}.release ]; do sleep 0.05; done"],
                 mounts=mounts if name == "a" else [], timeoutMs=90000)
            wait_file(workspaces[name] / (key + ".ready"))
        call("exec", session="a", execId="queued", argv=["sh", "-c", "echo forbidden"],
             mounts=mounts if mode == "keeper" or closing else [])
        before = call("diagnostics")
        if before["queued"] != 1 or len(before["running"]) != 2:
            raise RuntimeError(f"fault fixture not established: {before}")
        (workspaces["a"] / "p8-fire").write_text(mode)
        # Keeper death may stop the VM before the host sees the observer ack.
        if mode != "keeper":
            wait_file(workspaces["a"] / "p8-injected")
        close_reply = None
        affected = list(keys) + ["queued"]
        if closing:
            request_id += 1
            close_reply = sidecar.request(
                dict(id=request_id, op="session.close", session="a"), deadline)
            if close_reply.get("ok") or close_reply.get("reasonCode") != "E_SESSION_CLOSE_FAILED":
                raise RuntimeError(f"dirty close reported success: {close_reply}")
        elif mode in ("strict-revoke", "source-unmap"):
            (workspaces["b"] / "held-0.release").write_text("go")
            sidecar.succeeded(["held-0"], deadline)
            affected.remove("held-0")
        exits = sidecar.await_exits(affected, deadline)
        for key, terminal in exits.items():
            cancelled_by_close = closing and key in ("held-0", "queued")
            allowed = ("cancelled",) if cancelled_by_close else ("failed", "signalled", "signaled")
            if terminal.get("outcome") not in allowed:
                raise RuntimeError(f"no attributable terminal for {key}: {terminal}")
            if terminal.get("generation") != opened["a"]["vmGeneration"]:
                raise RuntimeError(f"wrong failure generation: {terminal}")
        if sidecar.stdout_of("queued"):
            raise RuntimeError("workload ran after its isolation boundary failed")
        for handle in handles:
            handle.wait()
        clean = call("diagnostics")
        if any(clean[key] for key in ("vm", "sessionCount", "running", "queued",
                                      "cleanupPending", "closingGuestSessions")):
            raise RuntimeError(f"fault cleanup did not converge: {clean}")
        reopened = call("session.open", session="c", workspace=str(workspaces["c"]),
                        memoryMiB=1024)
        if reopened["vmGeneration"] <= opened["a"]["vmGeneration"]:
            raise RuntimeError("failed generation was reused")
        call("exec", session="c", execId="recovered", argv=["true"])
        sidecar.succeeded(["recovered"], deadline)
        call("session.close", session="c")
        (root / "result.json").write_text(json.dumps({
            "mode": mode, "before": before, "exits": exits,
            "closeReply": close_reply, "clean": clean, "reopened": reopened,
        }, indent=2))
        print(f"CASE p8.cleanup.{mode.replace('-', '_')} PASS", flush=True)
    finally:
        stop_sidecar(process)
        (root / "sidecar.log").write_text("\n".join(sidecar.stderr), encoding="utf-8")
        for handle in handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser()
    for key in ("nvxd", "repo", "initrd"):
        parser.add_argument("--" + key, required=True, type=pathlib.Path)
    parser.add_argument("--diagnostic-agent", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path)
    args = parser.parse_args()
    output = args.output_dir or pathlib.Path(tempfile.mkdtemp(prefix="nvx-p8-cleanup-"))
    output.mkdir(parents=True, exist_ok=True)
    inputs = [args.initrd, args.diagnostic_agent, args.nvxd]
    before = {str(path): sha256(path) for path in inputs}
    for mode in ("keeper", "strict-revoke", "source-unmap", "close-directory", "close-export"):
        check_fault(args, mode, output)
    if before != {str(path): sha256(path) for path in inputs}:
        raise RuntimeError("inputs changed while testing")
    (output / "assets.json").write_text(json.dumps({"inputs": before}, indent=2))


if __name__ == "__main__":
    main()
