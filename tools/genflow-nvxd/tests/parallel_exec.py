"""P6 acceptance: several executions run at the same time inside one session.

The proof is a rendezvous, not a stopwatch: each execution writes its marker and then waits for
the other's, so the pair can only finish if both are running at once. A serialized implementation
deadlocks until the deadline, which is exactly the failure this entry must report. The second case
cancels one execution and requires the other to finish normally.

Like the other acceptance entries it fails when a required input is missing rather than shrinking
itself to a smoke test.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import subprocess
import tempfile
import threading
import time


def read_frame(stream):
    header = stream.read(8)
    if len(header) != 8:
        raise RuntimeError("sidecar closed before a complete frame")
    json_size, payload_size = struct.unpack("<II", header)
    return json.loads(stream.read(json_size)), stream.read(payload_size)


def send_frame(stream, body):
    encoded = json.dumps(body, separators=(",", ":")).encode()
    stream.write(struct.pack("<II", len(encoded), 0) + encoded)
    stream.flush()


class Sidecar:
    """Frames, demultiplexed: replies answer a request id, events belong to an execution."""

    def __init__(self, process):
        self.process = process
        self.events = []
        self.exits = {}
        self.replies = {}
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self):
        while True:
            try:
                head, payload = read_frame(self.process.stdout)
            except Exception:
                return
            if "event" in head:
                self.events.append((head, payload))
                if head.get("event") == "exec.exit":
                    key = head.get("execId") or head.get("handle")
                    if key in self.exits:
                        raise RuntimeError(f"duplicate exit event for {key}: {head}")
                    self.exits[key] = head
            else:
                self.replies[head.get("id")] = head

    def send(self, body):
        send_frame(self.process.stdin, body)

    def reply(self, request_id, deadline):
        while request_id not in self.replies:
            if time.monotonic() > deadline:
                raise RuntimeError(f"no reply for request {request_id}")
            time.sleep(0.02)
        return self.replies.pop(request_id)

    def request(self, body, timeout):
        self.send(body)
        return self.reply(body["id"], time.monotonic() + timeout)

    def ok(self, body, timeout):
        reply = self.request(body, timeout)
        if not reply.get("ok"):
            raise RuntimeError(f"{body.get('op')} was refused: {reply}")
        return reply

    def refused(self, body, timeout):
        reply = self.request(body, timeout)
        if reply.get("ok"):
            raise RuntimeError(f"{body.get('op')} was accepted but had to be refused: {reply}")
        return reply

    def await_exits(self, ids, deadline):
        while not all(one in self.exits for one in ids):
            if time.monotonic() > deadline:
                missing = [one for one in ids if one not in self.exits]
                raise RuntimeError(f"no exit event for {missing}; events={len(self.events)}")
            for key in [k for k in ids if k in self.exits]:
                pass
            time.sleep(0.02)

    def stdout_of(self, exec_id):
        chunks = [
            payload
            for head, payload in self.events
            if head.get("event") == "exec.stdout" and head.get("execId") == exec_id
        ]
        return b"".join(chunks)


def start(nvxd, repo, initrd, state, extra=(), max_running=2):
    process = subprocess.Popen(
        [
            str(nvxd),
            "--hypervisor",
            "whp",
            "--repo",
            str(repo),
            "--initrd",
            str(initrd),
            "--cpu-profile",
            "host",
            "--max-running",
            str(max_running),
            "--state-dir",
            str(state),
            *extra,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    threading.Thread(target=_drain, args=(process.stderr,), daemon=True).start()
    ready = read_frame(process.stdout)
    if ready is None or ready[0].get("event") != "ready":
        raise RuntimeError(f"the sidecar did not announce itself: {ready}")
    return process


def _drain(stream):
    try:
        for _ in stream:
            pass
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the concurrent-execution acceptance")
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    for path, label in (
        (args.nvxd, "sidecar executable"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")

    with tempfile.TemporaryDirectory(prefix="genflow-nvxd-parallel-") as root_name:
        root = pathlib.Path(root_name)
        workspace = root / "workspace"
        workspace.mkdir()
        process = start(args.nvxd, args.repo, args.initrd, root / "state")
        try:
            sidecar = Sidecar(process)

            probe = sidecar.ok({"id": 1, "op": "probe"}, 120)
            capabilities = probe.get("capabilities") or {}
            if capabilities.get("parallelExec") is not True:
                raise RuntimeError(f"parallelExec was not announced: {capabilities}")
            if capabilities.get("sessionIsolation") is not False:
                raise RuntimeError(f"sessionIsolation must stay false: {capabilities}")

            sidecar.ok(
                {
                    "id": 2,
                    "op": "session.open",
                    "session": "A",
                    "workspace": str(workspace),
                    "memoryMiB": 1024,
                },
                180,
            )

            # A rendezvous in the guest: each execution writes its marker, then waits for the
            # other's. Only two executions that are actually running at once can both finish.
            deadline = 60
            for exec_id, mine, theirs in (
                ("P1", "one", "two"),
                ("P2", "two", "one"),
            ):
                sidecar.ok(
                    {
                        "id": 10 + int(mine == "two"),
                        "op": "exec",
                        "session": "A",
                        "execId": exec_id,
                        "argv": [
                            "sh",
                            "-c",
                            f"touch {mine}; for i in $(seq 1 {deadline * 10}); do "
                            f"[ -f {theirs} ] && break; sleep 0.1; done; "
                            f"if [ -f {theirs} ]; then echo met; else echo missed; fi",
                        ],
                        "cwd": str(workspace),
                    },
                    60,
                )
            sidecar.await_exits(["P1", "P2"], time.monotonic() + deadline + 60)
            outputs = {one: sidecar.stdout_of(one) for one in ("P1", "P2")}
            if any(b"met" not in output for output in outputs.values()):
                raise RuntimeError(
                    f"the executions did not overlap; outputs were {outputs}"
                )
            for one in ("P1", "P2"):
                if sidecar.exits[one].get("outcome") != "exited":
                    raise RuntimeError(f"{one} did not exit cleanly: {sidecar.exits[one]}")
            print("two executions of one session met each other")

            # Cancelling one execution must leave its sibling alone.
            sidecar.ok(
                {
                    "id": 20,
                    "op": "exec",
                    "session": "A",
                    "execId": "C1",
                    "argv": ["sh", "-c", "sleep 30; echo finished"],
                },
                60,
            )
            sidecar.ok(
                {
                    "id": 21,
                    "op": "exec",
                    "session": "A",
                    "execId": "C2",
                    "argv": ["sh", "-c", "sleep 2; echo sibling"],
                },
                60,
            )
            time.sleep(0.5)
            sidecar.ok({"id": 22, "op": "signal", "execId": "C1"}, 60)
            sidecar.await_exits(["C1", "C2"], time.monotonic() + 60)
            if sidecar.exits["C1"].get("outcome") != "cancelled":
                raise RuntimeError(f"C1 was not cancelled: {sidecar.exits['C1']}")
            if sidecar.exits["C2"].get("outcome") != "exited":
                raise RuntimeError(f"C2 did not finish: {sidecar.exits['C2']}")
            if b"sibling" not in sidecar.stdout_of("C2"):
                raise RuntimeError("the sibling's output was lost")
            print("cancelling one execution left its sibling running")

            # A timeout belongs to one execution: the one that runs out of time ends as timedOut
            # while its sibling finishes normally.
            sidecar.ok(
                {
                    "id": 25,
                    "op": "exec",
                    "session": "A",
                    "execId": "T1",
                    "argv": ["sh", "-c", "sleep 30; echo late"],
                    "timeoutMs": 1500,
                },
                60,
            )
            sidecar.ok(
                {
                    "id": 26,
                    "op": "exec",
                    "session": "A",
                    "execId": "T2",
                    "argv": ["sh", "-c", "sleep 3; echo fast"],
                },
                60,
            )
            sidecar.await_exits(["T1", "T2"], time.monotonic() + 60)
            if sidecar.exits["T1"].get("outcome") != "timedOut":
                raise RuntimeError(f"the timed execution did not time out: {sidecar.exits['T1']}")
            if sidecar.exits["T2"].get("outcome") != "exited":
                raise RuntimeError(f"the sibling of a timed execution failed: {sidecar.exits['T2']}")
            if b"fast" not in sidecar.stdout_of("T2"):
                raise RuntimeError("the sibling's output was lost when its partner timed out")
            print("a timeout hit only the execution that ran out of time")

            # What an execution leaves behind must not survive it: the agent kills the execution's
            # cgroup after its own process exits.
            sidecar.ok(
                {
                    "id": 27,
                    "op": "exec",
                    "session": "A",
                    "execId": "D1",
                    "argv": ["sh", "-c", "sleep 300 & echo spawned"],
                },
                60,
            )
            sidecar.await_exits(["D1"], time.monotonic() + 60)
            sidecar.ok(
                {
                    "id": 28,
                    "op": "exec",
                    "session": "A",
                    "execId": "D2",
                    "argv": ["sh", "-c", "pgrep -x sleep | wc -l"],
                },
                60,
            )
            sidecar.await_exits(["D2"], time.monotonic() + 60)
            left_behind = sidecar.stdout_of("D2").strip()
            if left_behind != b"0":
                raise RuntimeError(
                    f"the execution left {left_behind!r} background processes behind"
                )
            print("an execution's descendants were cleaned up with it")

            # Interleaved output stays separated and ordered inside each stream.
            for order, (exec_id, tag) in enumerate((("L1", "a"), ("L2", "b"))):
                sidecar.ok(
                    {
                        "id": 40 + order,
                        "op": "exec",
                        "session": "A",
                        "execId": exec_id,
                        "argv": [
                            "sh",
                            "-c",
                            f"for i in $(seq 1 200); do echo {tag}$i; done",
                        ],
                    },
                    60,
                )
            sidecar.await_exits(["L1", "L2"], time.monotonic() + 60)
            for exec_id, tag, other in (("L1", "a", "b"), ("L2", "b", "a")):
                lines = sidecar.stdout_of(exec_id).decode().split()
                expected = [f"{tag}{index}" for index in range(1, 201)]
                if lines != expected:
                    raise RuntimeError(
                        f"{exec_id} output was not its own ordered stream: {lines[:5]}..."
                    )
                if any(line.startswith(other) for line in lines):
                    raise RuntimeError(f"{exec_id} received output of another execution")
            print("interleaved output stayed separated and ordered per execution")

            # Mounts are per-request snapshots. An execution that asks for the set already
            # applied reuses it instead of reconciling every bind mount again, which is what
            # keeps several executions from re-mounting each other's paths.
            refs = root / "refs"
            refs.mkdir()
            (refs / "r.txt").write_text("from-refs", encoding="utf-8")
            mount = {"mountId": "refs", "hostPath": str(refs), "mode": "ro"}
            before = sidecar.ok({"id": 49, "op": "diagnostics"}, 60).get("stats") or {}
            for order, exec_id in enumerate(("M1", "M2")):
                sidecar.ok(
                    {
                        "id": 50 + order,
                        "op": "exec",
                        "session": "A",
                        "execId": exec_id,
                        "argv": ["sh", "-c", "cat /workspace/mounts/refs/r.txt"],
                        "mounts": [mount],
                    },
                    120,
                )
                sidecar.await_exits([exec_id], time.monotonic() + 120)
                if b"from-refs" not in sidecar.stdout_of(exec_id):
                    raise RuntimeError(f"{exec_id} did not see the mounted path")
            stats = (sidecar.ok({"id": 52, "op": "diagnostics"}, 60).get("stats") or {})
            applied = (stats.get("mountsApplied") or 0) - (before.get("mountsApplied") or 0)
            skipped = (stats.get("mountsSkipped") or 0) - (before.get("mountsSkipped") or 0)
            if applied != 1:
                raise RuntimeError(f"the same mount set was reconciled {applied} times: {stats}")
            if skipped < 1:
                raise RuntimeError(f"the second execution did not reuse the mount set: {stats}")
            print("the same mount set was applied once and reused")

            # A mount change cannot happen under a running execution of the same session: the
            # caller is told clearly instead of having paths move under its work.
            sidecar.ok(
                {
                    "id": 53,
                    "op": "exec",
                    "session": "A",
                    "execId": "B1",
                    "argv": ["sh", "-c", "sleep 5; echo done"],
                },
                60,
            )
            time.sleep(0.3)
            other = root / "other"
            other.mkdir()
            refused = sidecar.refused(
                {
                    "id": 54,
                    "op": "exec",
                    "session": "A",
                    "execId": "B2",
                    "argv": ["sh", "-c", "echo changed"],
                    "mounts": [{"mountId": "other", "hostPath": str(other), "mode": "ro"}],
                },
                60,
            )
            if refused.get("reasonCode") != "E_BACKEND_BUSY":
                raise RuntimeError(f"a mount change under a running task was not refused: {refused}")
            sidecar.await_exits(["B1"], time.monotonic() + 60)
            print("a mount change under a running execution was refused with E_BACKEND_BUSY")

            sidecar.ok({"id": 30, "op": "session.close", "session": "A"}, 120)

            # The configured per-execution limits come from the sidecar, not from the request:
            # a deployment bounds executions without trusting each caller.
            limit_root = root / "state-limit"
            limit_workspace = root / "workspace-limit"
            limit_workspace.mkdir()
            limited = start(
                args.nvxd,
                args.repo,
                args.initrd,
                limit_root,
                extra=[
                    "--exec-memory-mb",
                    "96",
                    "--exec-cpu-percent",
                    "50",
                    "--exec-pids",
                    "32",
                ],
                max_running=1,
            )
            try:
                bounded = Sidecar(limited)
                bounded.ok(
                    {
                        "id": 1,
                        "op": "session.open",
                        "session": "L",
                        "workspace": str(limit_workspace),
                        "memoryMiB": 1024,
                    },
                    180,
                )
                # 256 MiB inside a 96 MiB cgroup: the execution must die, and only it.
                bounded.ok(
                    {
                        "id": 2,
                        "op": "exec",
                        "session": "L",
                        "execId": "BIG",
                        "argv": [
                            "python3",
                            "-c",
                            "x = bytearray(256 * 1024 * 1024); print(len(x))",
                        ],
                    },
                    120,
                )
                bounded.await_exits(["BIG"], time.monotonic() + 120)
                terminal = bounded.exits["BIG"]
                if terminal.get("outcome") not in ("signaled", "failed"):
                    raise RuntimeError(
                        f"an execution over its memory limit was not stopped: {terminal}"
                    )
                print(
                    "an execution over its memory limit was stopped: "
                    f"{terminal.get('outcome')} {terminal.get('code')}"
                )
                # The VM must still accept work: the limit applies to the execution, not the VM.
                bounded.ok(
                    {
                        "id": 3,
                        "op": "exec",
                        "session": "L",
                        "execId": "AFTER",
                        "argv": ["sh", "-c", "echo alive"],
                    },
                    60,
                )
                bounded.await_exits(["AFTER"], time.monotonic() + 60)
                if bounded.exits["AFTER"].get("outcome") != "exited":
                    raise RuntimeError(
                        f"the VM did not survive its execution's limit: {bounded.exits['AFTER']}"
                    )
                if b"alive" not in bounded.stdout_of("AFTER"):
                    raise RuntimeError("the work after the limited execution produced nothing")
                print("the VM kept running work after a limited execution died")

                # The cgroup files are the agent's management entry, not the workload's: the
                # workload runs as an unprivileged user and must not be able to rewrite its own
                # limits.
                bounded.ok(
                    {
                        "id": 5,
                        "op": "exec",
                        "session": "L",
                        "execId": "ESCAPE",
                        "argv": [
                            "sh",
                            "-c",
                            "echo +cpu > /sys/fs/cgroup/cgroup.subtree_control "
                            "2>/dev/null && echo WROTE || echo DENIED",
                        ],
                    },
                    60,
                )
                bounded.await_exits(["ESCAPE"], time.monotonic() + 60)
                if b"DENIED" not in bounded.stdout_of("ESCAPE"):
                    raise RuntimeError(
                        "the workload could write to the cgroup management files: "
                        f"{bounded.stdout_of('ESCAPE')!r}"
                    )
                print("a workload could not rewrite its own cgroup limits")
                bounded.ok({"id": 4, "op": "session.close", "session": "L"}, 120)
            finally:
                try:
                    send_frame(limited.stdin, {"op": "shutdown"})
                    limited.stdin.close()
                except OSError:
                    pass
                try:
                    limited.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    limited.kill()
            print("genflow-nvxd parallel execution passed")
        finally:
            try:
                send_frame(process.stdin, {"op": "shutdown"})
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
