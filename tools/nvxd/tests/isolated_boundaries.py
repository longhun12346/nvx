"""Product-sidecar checks for process/env/network isolation and active close."""

from runtime_assets import artifact_args

import argparse
import errno
import json
import pathlib
import subprocess
import tempfile
import time
import uuid

from p8_support import BoundedSidecar, stop_sidecar


def main():
    parser = argparse.ArgumentParser()
    for key in ("repo", "nvxd", "initrd"):
        parser.add_argument("--" + key, required=True, type=pathlib.Path)
    args = parser.parse_args()

    root = pathlib.Path(tempfile.mkdtemp(prefix="nvx-d6-process-close-"))
    workspaces = {name: root / name for name in ("a", "b")}
    for path in workspaces.values():
        path.mkdir()
    process = subprocess.Popen([
        str(args.nvxd), *artifact_args(args.repo, args.initrd),
        "--hypervisor", "whp", "--cpu-profile", "host", "--session-isolation",
        "--max-running", "2", "--state-dir", str(root / "state"),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + 150
    request = 0

    def call(op, **fields):
        nonlocal request
        request += 1
        return sidecar.ok(dict(id=request, op=op, **fields), deadline)

    def ready(name, key):
        while not (workspaces[name] / (key + ".ready")).exists():
            if time.monotonic() >= deadline or key in sidecar.exits:
                raise RuntimeError(f"{key} failed to reach its workload barrier")
            call("diagnostics")
            time.sleep(0.02)

    def held(name, key, **extra):
        call("exec", session=name, execId=key, argv=["sh", "-ec",
             f"echo ready >/workspace/{key}.ready; "
             f"while [ ! -f /workspace/{key}.release ]; do sleep 0.05; done; echo survived"],
             timeoutMs=60000, **extra)

    try:
        for name, path in workspaces.items():
            call("session.open", session=name, workspace=str(path), memoryMiB=1024)
            call("exec", session=name, execId="warm-" + name, argv=["true"])
            sidecar.succeeded(["warm-" + name], deadline)
        secret = uuid.uuid4().hex
        held("a", "secret-holder", env={"D6_PRIVATE_TOKEN": secret})
        ready("a", "secret-holder")
        script = f"""
import errno,os,pathlib,signal,socket
assert "D6_PRIVATE_TOKEN" not in os.environ
for path in pathlib.Path('/proc').glob('[0-9]*/environ'):
    try:
        data=path.read_bytes()
    except (PermissionError,FileNotFoundError,ProcessLookupError):
        continue
    assert {secret.encode()!r} not in data, str(path)
try:
    os.kill(-1, signal.SIGUSR1)
except OSError as error:
    assert error.errno in (errno.ESRCH,errno.EPERM), error
assert [name for _,name in socket.if_nameindex()]==['lo']
with socket.socket() as connection:
    connection.settimeout(1)
    assert connection.connect_ex(('198.51.100.1',443))==errno.ENETUNREACH
assert not pathlib.Path('/run/nvx').exists()
assert not list(pathlib.Path('/sessions').iterdir())
print('boundaries-held')
"""
        call("exec", session="b", execId="negative", argv=["python3", "-c", script],
             timeoutMs=10000)
        sidecar.succeeded(["negative"], deadline)
        (workspaces["a"] / "secret-holder.release").write_text("go", encoding="utf-8")
        sidecar.succeeded(["secret-holder"], deadline)
        if sidecar.stdout_of("secret-holder").strip() != b"survived":
            raise RuntimeError("peer process did not survive the cross-session signal")
        print("CASE p8.boundary.process_environment_network PASS", flush=True)

        held("a", "closing")
        held("b", "peer")
        ready("a", "closing")
        ready("b", "peer")
        call("exec", session="a", execId="queued-on-close", argv=["sh", "-c", "echo forbidden"])
        before = call("diagnostics")
        if len(before["running"]) != 2 or before["queued"] != 1:
            raise RuntimeError(f"active-close fixture not established: {before}")
        call("session.close", session="a")
        terminals = sidecar.await_exits(["closing", "queued-on-close"], deadline)
        if any(item["outcome"] != "cancelled" for item in terminals.values()):
            raise RuntimeError(f"close did not cancel all A work: {terminals}")
        if sidecar.stdout_of("queued-on-close"):
            raise RuntimeError("queued task ran after its session was closed")
        after = call("diagnostics")
        if after["sessionCount"] != 1 or after["closingGuestSessions"] or \
                after["vm"]["runtimeId"] != before["vm"]["runtimeId"] or "peer" not in after["running"]:
            raise RuntimeError(f"A close disturbed B or left a guest close pending: {after}")
        if after["cleanupPending"]:
            raise RuntimeError(f"isolated close retained source exports while a peer ran: {after}")
        reopened = call("session.open", session="a", workspace=str(workspaces["a"]), memoryMiB=1024)
        if reopened["runtimeId"] != before["vm"]["runtimeId"]:
            raise RuntimeError(f"immediate reopen retired the busy peer's VM: {reopened}")
        call("session.close", session="a")
        (workspaces["b"] / "peer.release").write_text("go", encoding="utf-8")
        sidecar.succeeded(["peer"], deadline)
        call("session.close", session="b")
        clean = call("diagnostics")
        if clean["vm"] or clean["sessionCount"] or clean["cleanupPending"]:
            raise RuntimeError(f"all-close left resources: {clean}")
        print(json.dumps({"before": before, "after": after, "terminals": terminals}), flush=True)
        print("CASE p8.lifecycle.active_close_preserves_peer PASS", flush=True)
    finally:
        stop_sidecar(process)


if __name__ == "__main__":
    main()

