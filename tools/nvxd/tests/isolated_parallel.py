"""Real guest execution barriers for the P7 matrix in P8 namespace mode."""

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
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvx-p8-parallel-"))
    workspaces = {name: root / name for name in ("a", "b")}
    for path in workspaces.values():
        path.mkdir()
    process = subprocess.Popen([
        str(args.nvxd), "--repo", str(args.repo), "--initrd", str(args.initrd),
        "--hypervisor", "whp", "--cpu-profile", "host", "--session-isolation",
        "--max-running", "8", "--state-dir", str(root / "state"),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sidecar = BoundedSidecar(process)
    deadline = time.monotonic() + 180
    request_id = 0

    def call(op, **body):
        nonlocal request_id
        request_id += 1
        return sidecar.ok(dict(id=request_id, op=op, **body), deadline)

    def submit(name, key, script, **extra):
        return call("exec", session=name, execId=key, argv=["sh", "-ec", script],
                    timeoutMs=60000, **extra)

    def wait_ready(members):
        while not all((workspaces[name] / (key + ".ready")).exists() for name, key in members):
            if time.monotonic() > deadline or any(key in sidecar.exits for _, key in members):
                raise RuntimeError(f"guest tasks did not reach the barrier: {members}")
            # A request pumps events and makes sidecar failure immediately observable.
            call("diagnostics")
            time.sleep(0.02)

    def release(members):
        for name, key in members:
            (workspaces[name] / (key + ".release")).write_text("go", encoding="utf-8")

    def held(name, key):
        submit(name, key, f"echo ready >/workspace/{key}.ready; "
               f"while [ ! -f /workspace/{key}.release ]; do sleep 0.02; done; echo {key}")

    try:
        opened = [call("session.open", session=name, workspace=str(path), memoryMiB=1024)
                  for name, path in workspaces.items()]
        if opened[0]["runtimeId"] != opened[1]["runtimeId"]:
            raise RuntimeError("isolated sessions use different VMs")
        for name in workspaces:
            submit(name, "warm-" + name, "true")
            sidecar.succeeded(["warm-" + name], deadline)
        for label, names in (
            ("one_by_two", ("a", "a")),
            ("two_by_one", ("a", "b")),
            ("two_by_two", ("a", "a", "b", "b")),
            ("eight_at_once", ("a",) * 4 + ("b",) * 4),
        ):
            members = [(name, f"{label}-{index}") for index, name in enumerate(names)]
            for name, key in members:
                held(name, key)
            wait_ready(members)
            diag = call("diagnostics")
            if len(diag["running"]) != len(members) or diag["vm"]["runtimeId"] != opened[0]["runtimeId"]:
                raise RuntimeError(f"barrier did not preserve the shared parallel VM: {diag}")
            print(json.dumps({"barrier": label, "members": members, "diagnostics": diag}), flush=True)
            release(members)
            sidecar.succeeded([key for _, key in members], deadline)
            for _, key in members:
                if sidecar.stdout_of(key).strip() != key.encode():
                    raise RuntimeError(f"output routed to a wrong task: {key}")
            print(f"CASE p8.parallel.{label} PASS", flush=True)

        members = [("a", "cancel-victim"), ("a", "same-peer"), ("b", "other-peer")]
        for name, key in members:
            held(name, key)
        wait_ready(members)
        call("signal", session="a", execId="cancel-victim")
        victim = sidecar.await_exits(["cancel-victim"], deadline)["cancel-victim"]
        if victim["outcome"] != "cancelled":
            raise RuntimeError(f"cancelled execution has wrong outcome: {victim}")
        release(members[1:])
        sidecar.succeeded(["same-peer", "other-peer"], deadline)
        print("CASE p8.parallel.cancel_isolation PASS", flush=True)

        blockers = [("a", f"block-{index}") for index in range(8)]
        for name, key in blockers:
            held(name, key)
        wait_ready(blockers)
        burst = [("a", f"burst-{index}") for index in range(8)]
        peer = ("b", "fair-peer")
        for name, key in [*burst, peer]:
            held(name, key)
        queued = call("diagnostics")
        if queued["queued"] != 9:
            raise RuntimeError(f"fairness test did not fill the waiting queue: {queued}")
        release(blockers[:1])
        first_wave = []
        while not (workspaces["b"] / "fair-peer.ready").exists():
            for name, key in burst:
                if key not in first_wave and (workspaces[name] / (key + ".ready")).exists():
                    first_wave.append(key)
                    release([(name, key)])
            if len(first_wave) > 1 or time.monotonic() > deadline:
                raise RuntimeError(f"B starved behind A's burst: {first_wave}")
            call("diagnostics")
            time.sleep(0.02)
        release([*blockers, *burst, peer])
        sidecar.succeeded([key for _, key in [*blockers, *burst, peer]], deadline)
        print(f"fairness: B admitted after {first_wave} with seven occupied slots", flush=True)
        print("CASE p8.parallel.fairness PASS", flush=True)

        # Keep a peer alive during A's request-limited OOM.
        held("b", "oom-peer")
        wait_ready([("b", "oom-peer")])
        submit("a", "oom-victim", "exec python3 -c 'x=bytearray(256*1024*1024)'",
               limits={"memMb": 96})
        victim = sidecar.await_exits(["oom-victim"], deadline)["oom-victim"]
        if victim.get("outcome") != "signaled" or victim.get("detail") != "oom":
            raise RuntimeError(f"request OOM attribution missing: {victim}")
        release([("b", "oom-peer")])
        sidecar.succeeded(["oom-peer"], deadline)
        submit("a", "oom-recovered", "echo recovered")
        sidecar.succeeded(["oom-recovered"], deadline)
        if call("diagnostics")["vm"]["runtimeId"] != opened[0]["runtimeId"]:
            raise RuntimeError("local OOM replaced the shared VM")
        print("CASE p8.parallel.oom_isolation PASS", flush=True)

        for name in workspaces:
            call("session.close", session=name)
        final = call("diagnostics")
        if final["vm"] is not None or final["sessionCount"] or final["cleanupPending"]:
            raise RuntimeError(f"group resources survived all closes: {final}")
    finally:
        stop_sidecar(process)


if __name__ == "__main__":
    main()
