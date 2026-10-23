"""P7 acceptance: executions of *different* sessions run at the same time on one VM.

`parallel_exec.py` proves one session can run several executions at once. The P7 matrix also
needs the cross-session direction (2x1) and both at once (2x2), because those decide whether the
VM's run slots are really shared instead of handed to whichever session started first.

Every overlap here is a rendezvous in the guest, never a stopwatch: each execution writes its own
marker and then waits for the markers of the executions it must overlap with. A serialized
implementation cannot satisfy that and fails on its deadline, which is the failure this entry is
meant to report.

Case ids (`p7.*`) are the contract with `verify-nvx-vm.ps1 -Stage P7`: it requires exactly these
ids to be reported as passed, so adding a case here means adding it to the stage list too.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import subprocess
import threading
import time

CASES = (
    "p7.cross_session.two_by_one",
    "p7.cross_session.two_by_two",
    "p7.fairness.a_burst_does_not_starve_another_session",
    "p7.limits.cross_session_isolation",
)

_reported: list[str] = []


def case(case_id: str) -> None:
    """Records one passed acceptance case, in a form the stage entry can parse."""
    if case_id not in CASES:
        raise RuntimeError(f"{case_id} is not in this entry's case list")
    _reported.append(case_id)
    print(f"CASE {case_id} PASS", flush=True)


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
        self.exit_order = []
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
                    self.exit_order.append(key)
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

    def await_exits(self, ids, deadline):
        while not all(one in self.exits for one in ids):
            if time.monotonic() > deadline:
                missing = [one for one in ids if one not in self.exits]
                raise RuntimeError(f"no exit event for {missing}; events={len(self.events)}")
            time.sleep(0.02)

    def stdout_of(self, exec_id):
        return b"".join(
            payload
            for head, payload in self.events
            if head.get("event") == "exec.stdout" and head.get("execId") == exec_id
        )

    def stderr_of(self, exec_id):
        return b"".join(
            payload
            for head, payload in self.events
            if head.get("event") == "exec.stderr" and head.get("execId") == exec_id
        )

    def diagnostics(self):
        return self.ok({"id": 900, "op": "diagnostics"}, 60)


def start(nvxd, repo, initrd, state, max_running):
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


def rendezvous(need_markers):
    """A guest-side barrier over `need_markers` executions.

    Each execution touches its own marker, then waits until every marker exists. Only executions
    that are all running at the same time can get past it, and the wait is bounded so a serialized
    implementation reports `missed` instead of hanging the suite.

    Markers live in the guest's `/tmp`, not in a session workspace: the sessions of one VM do not
    share a workspace directory, and the point of the barrier is the VM's process and file space,
    which they do share.
    """
    template = (
        "touch /tmp/{mine}; for i in $(seq 1 600); do "
        "missing=0; for one in {others}; do [ -f \"/tmp/$one\" ] || missing=1; done; "
        "[ $missing -eq 0 ] && break; sleep 0.1; done; "
        "missing=0; for one in {others}; do [ -f \"/tmp/$one\" ] || missing=1; done; "
        "if [ $missing -eq 0 ]; then echo met; else echo missed; fi"
    )
    return template


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the cross-session parallel acceptance"
    )
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument(
        "--report",
        type=pathlib.Path,
        help="write a JSON report of this run (the stage entry reads it)",
    )
    parser.add_argument("--max-running", type=int, default=4)
    args = parser.parse_args()
    for path, label in (
        (args.nvxd, "sidecar executable"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")

    root = pathlib.Path(__import__("tempfile").mkdtemp(prefix="nvxd-mixed-"))
    workspace_a = root / "session-a"
    workspace_b = root / "session-b"
    for workspace in (workspace_a, workspace_b):
        workspace.mkdir()
    process = start(args.nvxd, args.repo, args.initrd, root / "state", args.max_running)
    sidecar = Sidecar(process)
    environment = {}
    try:
        probe = sidecar.ok({"id": 1, "op": "probe"}, 120)
        capabilities = probe.get("capabilities") or {}
        if capabilities.get("parallelExec") is not True:
            raise RuntimeError(f"parallelExec was not announced: {capabilities}")
        if capabilities.get("sessionIsolation") is not False:
            raise RuntimeError(f"sessionIsolation must stay false: {capabilities}")
        # Slots are counted per VM: a session's ceiling is the VM's ceiling, not a share of it.
        if capabilities.get("maxRunningPerSession") != capabilities.get("maxRunningPerVm"):
            raise RuntimeError(f"the per-session ceiling is not the VM's: {capabilities}")
        environment["capabilities"] = capabilities

        for index, (name, workspace) in enumerate(
            (("A", workspace_a), ("B", workspace_b))
        ):
            sidecar.ok(
                {
                    "id": 2 + index,
                    "op": "session.open",
                    "session": name,
                    "workspace": str(workspace),
                    "memoryMiB": 1024,
                },
                300,
            )

        # --- 2x1: one execution per session, two sessions, one VM -------------------------
        # Each waits for the other's marker, so both must be running at the same time.
        requests = [
            ("A1", "A", "one", ("two",), workspace_a),
            ("B1", "B", "two", ("one",), workspace_b),
        ]
        for index, (exec_id, session, mine, others, workspace) in enumerate(requests):
            sidecar.ok(
                {
                    "id": 10 + index,
                    "op": "exec",
                    "session": session,
                    "execId": exec_id,
                    "argv": ["sh", "-c", rendezvous(len(others) + 1).format(
                        mine=mine, others=" ".join(others))],
                    "cwd": str(workspace),
                },
                120,
            )
        sidecar.await_exits(["A1", "B1"], time.monotonic() + 120)
        for exec_id in ("A1", "B1"):
            if b"met" not in sidecar.stdout_of(exec_id):
                raise RuntimeError(
                    f"{exec_id} did not overlap with the other session: "
                    f"{sidecar.stdout_of(exec_id)!r} {sidecar.stderr_of(exec_id)!r}"
                )
            if sidecar.exits[exec_id].get("outcome") != "exited":
                raise RuntimeError(f"{exec_id} did not exit cleanly: {sidecar.exits[exec_id]}")
        case("p7.cross_session.two_by_one")

        # --- 2x2: two executions in each of two sessions, all four at once -----------------
        members = [("A2", "A", "m-a2", workspace_a), ("A3", "A", "m-a3", workspace_a),
                   ("B2", "B", "m-b2", workspace_b), ("B3", "B", "m-b3", workspace_b)]
        for index, (exec_id, session, mine, workspace) in enumerate(members):
            others = tuple(marker for _, _, marker, _ in members if marker != mine)
            sidecar.ok(
                {
                    "id": 30 + index,
                    "op": "exec",
                    "session": session,
                    "execId": exec_id,
                    "argv": ["sh", "-c", rendezvous(4).format(
                        mine=mine, others=" ".join(others))],
                    "cwd": str(workspace),
                },
                120,
            )
        ids = [exec_id for exec_id, _, _, _ in members]
        sidecar.await_exits(ids, time.monotonic() + 120)
        running_seen = None
        for exec_id in ids:
            if b"met" not in sidecar.stdout_of(exec_id):
                raise RuntimeError(
                    f"{exec_id} did not overlap the other three: "
                    f"{sidecar.stdout_of(exec_id)!r} {sidecar.stderr_of(exec_id)!r}"
                )
        # The four of them were running in the same VM instance, not in four instances.
        diagnostics = sidecar.diagnostics()
        environment["runtimeId"] = (diagnostics.get("vm") or {}).get("runtimeId")
        environment["generation"] = (diagnostics.get("vm") or {}).get("generation")
        running_seen = [
            entry for entry in (diagnostics.get("execs") or [])
            if entry.get("phase") == "running"
        ]
        if running_seen:
            raise RuntimeError(f"executions were still running after their exits: {running_seen}")
        case("p7.cross_session.two_by_two")

        # --- fairness: one session's burst must not keep the other waiting ------------------
        # A queues six long executions (four fill the slots), then B queues one short one. With a
        # per-VM round robin B is admitted as soon as the first slot frees, so it finishes about
        # one wave later. A dispatcher that drains the burst first would only admit B two waves
        # later. The bound is measured from submission, and the margin (one wave) is wide enough
        # that guest start-up jitter inside a wave cannot decide the result -- comparing the exit
        # order of tasks admitted in the same wave would measure that jitter, not fairness.
        wave = 4
        queued_at = time.monotonic()
        for index in range(6):
            sidecar.ok(
                {
                    "id": 50 + index,
                    "op": "exec",
                    "session": "A",
                    "execId": f"F{index + 1}",
                    "argv": ["sh", "-c", f"sleep {wave}; echo done"],
                    "cwd": str(workspace_a),
                },
                120,
            )
        sidecar.ok(
            {
                "id": 60,
                "op": "exec",
                "session": "B",
                "execId": "FB1",
                "argv": ["sh", "-c", "echo quick"],
                "cwd": str(workspace_b),
            },
            120,
        )
        burst = [f"F{index + 1}" for index in range(6)] + ["FB1"]
        # Only B's execution is timed: waiting for the burst too would measure A's second wave.
        sidecar.await_exits(["FB1"], time.monotonic() + 120)
        waited = time.monotonic() - queued_at
        if "FB1" not in sidecar.exit_order:
            raise RuntimeError(f"the other session's execution never finished: {sidecar.exit_order}")
        # Two waves is what a first-come-first-served dispatcher costs; fair service is one.
        if waited > wave * 2:
            raise RuntimeError(
                f"the other session waited {waited:.1f}s, about two waves: exit order "
                f"{sidecar.exit_order}"
            )
        sidecar.await_exits(burst, time.monotonic() + 300)
        case("p7.fairness.a_burst_does_not_starve_another_session")

        # --- per-execution limits, scoped to the execution that asked for them --------------
        # A asks for 96 MiB and allocates 256 MiB, so its own execution is stopped. B runs
        # alongside without a limit and must finish normally: the limit is per execution, not
        # per session or per VM.
        sidecar.ok(
            {
                "id": 70,
                "op": "exec",
                "session": "A",
                "execId": "L1",
                "argv": ["sh", "-c", "python3 -c 'x=bytearray(256*1024*1024); print(len(x))'"],
                "cwd": str(workspace_a),
                "limits": {"memMb": 96},
            },
            120,
        )
        sidecar.ok(
            {
                "id": 71,
                "op": "exec",
                "session": "B",
                "execId": "L2",
                "argv": ["sh", "-c", "sleep 3; echo survived"],
                "cwd": str(workspace_b),
            },
            120,
        )
        sidecar.await_exits(["L1", "L2"], time.monotonic() + 180)
        limited = sidecar.exits["L1"]
        if limited.get("outcome") != "signaled" or limited.get("code") != 9:
            raise RuntimeError(f"the limited execution was not stopped: {limited}")
        if sidecar.exits["L2"].get("outcome") != "exited" or sidecar.exits["L2"].get("code") != 0:
            raise RuntimeError(f"the sibling session was affected: {sidecar.exits['L2']}")
        if b"survived" not in sidecar.stdout_of("L2"):
            raise RuntimeError("the unlimited execution produced no output")
        case("p7.limits.cross_session_isolation")

        missing = [case_id for case_id in CASES if case_id not in _reported]
        if missing:
            raise RuntimeError(f"cases did not run: {missing}")
        print("nvxd mixed parallel acceptance passed", flush=True)
        return 0
    finally:
        report = {
            "suite": "mixed_parallel",
            "cases": list(_reported),
            "expected": list(CASES),
            "environment": environment,
            "maxRunning": args.max_running,
        }
        if args.report:
            args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        try:
            process.kill()
            process.wait(timeout=60)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
