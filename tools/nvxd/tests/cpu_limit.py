"""A request-level cpuPercent limit is enforced: a busy loop limited to 50% gets about half a CPU.

Needs a guest kernel with CONFIG_CFS_BANDWIDTH (the fork's kernel build has it; upstream's prebuilt
kernel does not, and the start is then refused with a launch failure).
"""

from __future__ import annotations

import argparse
import pathlib
import tempfile
import time

import mixed_parallel as mp

BUSY = (
    "import time\n"
    "t0 = time.time(); c0 = time.process_time()\n"
    "while time.time() - t0 < 4: pass\n"
    "print('%.3f' % ((time.process_time() - c0) / (time.time() - t0)))\n"
)


def measured(sidecar, session, exec_id, limits):
    request = {
        "id": hash(exec_id) % 100000 + 10,
        "op": "exec",
        "session": session,
        "execId": exec_id,
        "argv": ["python3", "-c", BUSY],
    }
    if limits:
        request["limits"] = limits
    sidecar.ok(request, 60)
    sidecar.await_exits([exec_id], time.monotonic() + 60)
    exit_event = sidecar.exits[exec_id]
    if exit_event.get("outcome") != "exited":
        raise RuntimeError(f"{exec_id} did not exit cleanly: {exit_event}")
    return float(sidecar.stdout_of(exec_id).decode().strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-cpu-"))
    workspace = root / "ws"
    workspace.mkdir()
    process = mp.start(args.nvxd, args.repo, args.initrd, root / "state", 2)
    try:
        sidecar = mp.Sidecar(process)
        sidecar.ok({"id": 1, "op": "probe"}, 120)
        sidecar.ok(
            {"id": 2, "op": "session.open", "session": "C", "workspace": str(workspace), "memoryMiB": 1024},
            120,
        )
        free = measured(sidecar, "C", "FREE", None)
        half = measured(sidecar, "C", "HALF", {"cpuPercent": 50})
        print(f"unlimited busy loop got {free:.2f} CPU, limited to 50% got {half:.2f} CPU")
        if not 0.35 <= half <= 0.65:
            raise RuntimeError(f"a 50% cpu limit gave {half:.2f} of a CPU")
        if free < 0.85:
            raise RuntimeError(f"an unlimited busy loop got only {free:.2f} of a CPU")
        print("CASE p7.limits.cpu_percent PASS")
    finally:
        mp.stop(process)


if __name__ == "__main__":
    main()
