"""P5 acceptance: several logical sessions share one VM, each holding several executions.

This is the test that the old "one session == one VM, one `busy` flag" model cannot pass:

* two sessions must be served by the *same* VM (same runtime id and generation), booted once;
* a second execution on a session must be **queued**, not refused;
* executions run one at a time in submission order, with their own output and exit code;
* cancelling a queued execution must leave the running one and other sessions alone;
* closing a session must not stop the VM the other session is still using.

It fails when a required input is missing, like `e2e.py`: it is an acceptance entry, not a
best-effort smoke test.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
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

    def send(self, body):
        send_frame(self.process.stdin, body)

    def pump(self, deadline):
        """Reads one frame and files it. Blocks until a frame arrives."""
        if time.monotonic() > deadline:
            raise RuntimeError("deadline passed while waiting for a frame")
        head, payload = read_frame(self.process.stdout)
        if "event" in head:
            if head["event"] == "exec.exit":
                key = head.get("execId") or head.get("handle")
                if key in self.exits:
                    raise RuntimeError(f"duplicate exit event for {key}: {head}")
                self.exits[key] = head
            self.events.append((head, payload))
            return
        self.replies[head.get("id")] = head

    def reply(self, request_id, deadline):
        while request_id not in self.replies:
            self.pump(deadline)
        return self.replies.pop(request_id)

    def request(self, body, deadline):
        self.send(body)
        return self.reply(body.get("id"), deadline)

    def ok(self, body, deadline):
        head = self.request(body, deadline)
        if not head.get("ok"):
            raise RuntimeError(
                f"{body.get('op')} failed: {head.get('reasonCode')} {head.get('message', '')}"
            )
        return head

    def refused(self, body, deadline, reason):
        """Asserts that a request is refused for a specific reason and returns the frame."""
        head = self.request(body, deadline)
        if head.get("ok"):
            raise RuntimeError(f"{body.get('op')} was accepted; expected {reason}: {head}")
        if head.get("reasonCode") != reason:
            raise RuntimeError(
                f"{body.get('op')} was refused with {head.get('reasonCode')}; expected {reason}"
            )
        return head

    def await_exits(self, expected, deadline):
        while any(key not in self.exits for key in expected):
            self.pump(deadline)
        return {key: self.exits[key] for key in expected}

    def stdout_of(self, exec_id):
        return b"".join(
            payload
            for head, payload in self.events
            if head.get("event") == "exec.stdout"
            and (head.get("execId") or head.get("handle")) == exec_id
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--memory-mib", type=int, default=1024)
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="seconds before the sidecar is killed; a blocked read otherwise never returns",
    )
    args = parser.parse_args()
    for path, label in (
        (args.nvxd, "sidecar"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")

    stage = "startup"
    deadline = time.monotonic() + 600
    # A plain directory rather than a context manager: the VM keeps the workspace open, so a
    # strict cleanup raises and would mask whatever actually failed first.
    root = pathlib.Path(tempfile.mkdtemp(prefix="genflow-nvxd-shared-"))
    try:
        workspace_a = root / "session-a"
        workspace_b = root / "session-b"
        workspace_c = root / "session-c"
        workspace_d = root / "session-d"
        for workspace in (workspace_a, workspace_b, workspace_c, workspace_d):
            workspace.mkdir()
        state = root / "state"
        process = subprocess.Popen(
            [
                str(args.nvxd),
                "--hypervisor",
                "whp",
                "--repo",
                str(args.repo),
                "--initrd",
                str(args.initrd),
                "--cpu-profile",
                "host",
                "--state-dir",
                str(state),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        sidecar = Sidecar(process)
        # A frame read blocks indefinitely, so a stalled sidecar would hang the test rather
        # than fail it. The watchdog turns that into a failure with the stderr tail attached.
        watchdog = threading.Timer(args.timeout, process.kill)
        watchdog.daemon = True
        watchdog.start()
        # Drained continuously: a piped stderr nobody reads fills up and stops the sidecar.
        log = []
        threading.Thread(
            target=lambda: [
                log.append(line.decode(errors="replace").rstrip())
                for line in iter(process.stderr.readline, b"")
            ],
            daemon=True,
        ).start()
        try:
            ready, _ = read_frame(process.stdout)
            if ready.get("event") != "ready":
                raise RuntimeError(f"unexpected ready frame: {ready}")

            stage = "probe"
            probe = sidecar.ok({"id": 1, "op": "probe"}, deadline)
            capabilities = probe.get("capabilities") or {}
            if capabilities.get("sharedVm") is not True:
                raise RuntimeError(f"the sidecar does not report a shared VM: {probe}")
            if capabilities.get("parallelExec") is not False:
                raise RuntimeError(
                    f"P5 must report parallelExec=false until P7: {capabilities}"
                )
            if capabilities.get("sessionIsolation") is not False:
                raise RuntimeError(f"P5 must report sessionIsolation=false: {capabilities}")

            stage = "open two sessions"
            opened_a = sidecar.ok(
                {
                    "id": 2,
                    "op": "session.open",
                    "session": "A",
                    "workspace": str(workspace_a),
                    "memoryMiB": args.memory_mib,
                },
                deadline,
            )
            opened_b = sidecar.ok(
                {
                    "id": 3,
                    "op": "session.open",
                    "session": "B",
                    "workspace": str(workspace_b),
                    "memoryMiB": args.memory_mib,
                },
                deadline,
            )
            if opened_a["runtimeId"] != opened_b["runtimeId"]:
                raise RuntimeError(
                    f"two sessions got different VMs: {opened_a} vs {opened_b}"
                )
            if opened_a["vmGeneration"] != opened_b["vmGeneration"]:
                raise RuntimeError(
                    f"two sessions got different generations: {opened_a} vs {opened_b}"
                )
            print(f"shared VM: runtimeId={opened_a['runtimeId']} "
                  f"generation={opened_a['vmGeneration']}")

            # A1 runs; A2 and B1 must be *queued* behind it, not refused. That alone is the
            # regression the old per-session `busy` flag could not express.
            stage = "queue three executions"
            a1 = sidecar.ok(
                {
                    "id": 10,
                    "op": "exec",
                    "session": "A",
                    "execId": "A1",
                    "argv": ["sh", "-c", "sleep 2; echo A1"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if a1.get("state") != "queued":
                raise RuntimeError(f"the first execution was not accepted: {a1}")
            a2 = sidecar.ok(
                {
                    "id": 11,
                    "op": "exec",
                    "session": "A",
                    "execId": "A2",
                    "argv": ["sh", "-c", "echo A2"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if a2.get("state") != "queued":
                raise RuntimeError(f"a second execution on the same session was not queued: {a2}")
            b1 = sidecar.ok(
                {
                    "id": 12,
                    "op": "exec",
                    "session": "B",
                    "execId": "B1",
                    "argv": ["sh", "-c", "echo B1"],
                    "cwd": str(workspace_b),
                },
                deadline,
            )
            if b1.get("state") != "queued":
                raise RuntimeError(f"the other session's execution was not queued: {b1}")
            if not (a2.get("queuePosition", 0) < b1.get("queuePosition", 0)):
                raise RuntimeError(f"queue positions are not in submission order: {a2} {b1}")

            stage = "run in order"
            exits = sidecar.await_exits(["A1", "A2", "B1"], deadline)
            order = [
                head.get("execId")
                for head, _ in sidecar.events
                if head.get("event") == "exec.exit"
            ]
            if order != ["A1", "A2", "B1"]:
                raise RuntimeError(f"executions did not run in submission order: {order}")
            for exec_id, marker in (("A1", b"A1\n"), ("A2", b"A2\n"), ("B1", b"B1\n")):
                if sidecar.stdout_of(exec_id) != marker:
                    raise RuntimeError(
                        f"{exec_id} got the wrong output: {sidecar.stdout_of(exec_id)!r}"
                    )
                if exits[exec_id].get("outcome") != "exited":
                    raise RuntimeError(f"{exec_id} did not exit normally: {exits[exec_id]}")
            for exec_id in ("A1", "A2", "B1"):
                session = exits[exec_id].get("session")
                expected = "B" if exec_id == "B1" else "A"
                if session != expected:
                    raise RuntimeError(f"{exec_id} was attributed to {session}, not {expected}")
            print("order and output routing: A1 -> A2 -> B1")

            stage = "cancel a queued execution"
            long_run = sidecar.ok(
                {
                    "id": 20,
                    "op": "exec",
                    "session": "A",
                    "execId": "A3",
                    "argv": ["sh", "-c", "sleep 3; echo A3"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if long_run.get("state") != "queued":
                raise RuntimeError(f"A3 was not accepted: {long_run}")
            doomed = sidecar.ok(
                {
                    "id": 21,
                    "op": "exec",
                    "session": "A",
                    "execId": "A4",
                    "argv": ["sh", "-c", "echo A4-must-not-run"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if doomed.get("state") != "queued":
                raise RuntimeError(f"A4 was not accepted: {doomed}")
            cancelled = sidecar.ok(
                {"id": 22, "op": "signal", "session": "A", "execId": "A4"}, deadline
            )
            if cancelled.get("state") != "cancelled":
                raise RuntimeError(f"a queued execution was not cancelled: {cancelled}")
            exits = sidecar.await_exits(["A3", "A4"], deadline)
            if exits["A4"].get("outcome") != "cancelled":
                raise RuntimeError(f"A4 did not end cancelled: {exits['A4']}")
            if sidecar.stdout_of("A4"):
                raise RuntimeError("A4 produced output although it was cancelled while queued")
            if exits["A3"].get("outcome") != "exited" or exits["A3"].get("code") != 0:
                raise RuntimeError(f"cancelling A4 disturbed A3: {exits['A3']}")
            print("cancel while queued: A4 cancelled, A3 completed")

            stage = "status reconciles an execution"
            status = sidecar.ok(
                {"id": 30, "op": "exec.status", "execId": "A1"}, deadline
            )
            if status.get("state") != "finished":
                raise RuntimeError(f"a finished execution was reported as {status}")
            missing = sidecar.ok(
                {"id": 31, "op": "exec.status", "execId": "never-sent"}, deadline
            )
            if missing.get("state") != "unknown":
                raise RuntimeError(f"an unknown id was reported as {missing}")

            stage = "duplicate ids"
            duplicate = sidecar.ok(
                {
                    "id": 32,
                    "op": "exec",
                    "session": "A",
                    "execId": "A1",
                    "argv": ["sh", "-c", "sleep 2; echo A1"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if not duplicate.get("deduplicated"):
                raise RuntimeError(f"a repeated exec id started a second run: {duplicate}")
            if duplicate.get("state") != "finished" or duplicate.get("outcome") != "exited":
                raise RuntimeError(
                    f"the repeated id did not report the original result: {duplicate}"
                )
            sidecar.refused(
                {
                    "id": 33,
                    "op": "exec",
                    "session": "A",
                    "execId": "A2",
                    "argv": ["sh", "-c", "echo something-else"],
                    "cwd": str(workspace_a),
                },
                deadline,
                "E_BACKEND_EXEC_ID_CONFLICT",
            )
            print("duplicate ids: same arguments answered, different arguments refused")

            stage = "cancel before accept"
            recorded = sidecar.ok({"id": 34, "op": "signal", "execId": "A9"}, deadline)
            if recorded.get("state") != "recorded":
                raise RuntimeError(f"a cancel for an unknown id was not recorded: {recorded}")
            late = sidecar.ok(
                {
                    "id": 35,
                    "op": "exec",
                    "session": "A",
                    "execId": "A9",
                    "argv": ["sh", "-c", "echo A9-must-not-run"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if late.get("state") != "cancelled":
                raise RuntimeError(f"a late start ran despite an earlier cancel: {late}")
            status_a9 = sidecar.ok(
                {"id": 36, "op": "exec.status", "execId": "A9"}, deadline
            )
            if status_a9.get("state") != "unknown":
                raise RuntimeError(f"a refused start was registered anyway: {status_a9}")
            print("cancel before accept: the late start never ran")

            stage = "four sessions on one VM"
            for index, (session, workspace) in enumerate(
                (("C", workspace_c), ("D", workspace_d)), start=37
            ):
                opened = sidecar.ok(
                    {
                        "id": index,
                        "op": "session.open",
                        "session": session,
                        "workspace": str(workspace),
                        "memoryMiB": args.memory_mib,
                    },
                    deadline,
                )
                if opened["runtimeId"] != opened_a["runtimeId"]:
                    raise RuntimeError(f"session {session} got another VM: {opened}")
                if opened["vmGeneration"] != opened_a["vmGeneration"]:
                    raise RuntimeError(f"session {session} got another generation: {opened}")
            four = [
                ("A", "A8", workspace_a),
                ("B", "B3", workspace_b),
                ("C", "C1", workspace_c),
                ("D", "D1", workspace_d),
            ]
            for index, (session, exec_id, workspace) in enumerate(four, start=120):
                reply = sidecar.ok(
                    {
                        "id": index,
                        "op": "exec",
                        "session": session,
                        "execId": exec_id,
                        "argv": ["sh", "-c", f"echo {exec_id}"],
                        "cwd": str(workspace),
                    },
                    deadline,
                )
                if reply.get("state") != "queued":
                    raise RuntimeError(f"{exec_id} was not accepted: {reply}")
            exits = sidecar.await_exits([exec_id for _, exec_id, _ in four], deadline)
            four_order = [
                head.get("execId")
                for head, _ in sidecar.events
                if head.get("event") == "exec.exit"
                and head.get("execId") in {exec_id for _, exec_id, _ in four}
            ]
            expected_order = [exec_id for _, exec_id, _ in four]
            if four_order != expected_order:
                raise RuntimeError(f"four sessions did not queue in order: {four_order}")
            for _, exec_id, _ in four:
                if sidecar.stdout_of(exec_id) != f"{exec_id}\n".encode():
                    raise RuntimeError(
                        f"{exec_id} got the wrong output: {sidecar.stdout_of(exec_id)!r}"
                    )
                if exits[exec_id].get("generation") != opened_a["vmGeneration"]:
                    raise RuntimeError(
                        f"{exec_id} was reported against another generation: {exits[exec_id]}"
                    )
            print(f"four sessions, one VM: {' -> '.join(expected_order)}")

            stage = "the same mount id in two sessions does not collide"
            mount_c = root / "mount-c"
            mount_d = root / "mount-d"
            for directory, text in ((mount_c, b"from-c\n"), (mount_d, b"from-d\n")):
                directory.mkdir(exist_ok=True)
                # Bytes, not text: Windows text mode writes CRLF, and the guest would then
                # echo back something this assertion never asked for.
                (directory / "who.txt").write_bytes(text)
            read_c = sidecar.ok(
                {
                    "id": 50,
                    "op": "exec",
                    "session": "C",
                    "execId": "C2",
                    "argv": ["sh", "-c", "cat /workspace/mounts/same/who.txt"],
                    "cwd": str(workspace_c),
                    "mounts": [
                        {"mountId": "same", "hostPath": str(mount_c), "mode": "ro"}
                    ],
                },
                deadline,
            )
            read_d = sidecar.ok(
                {
                    "id": 51,
                    "op": "exec",
                    "session": "D",
                    "execId": "D2",
                    "argv": ["sh", "-c", "cat /sessions/D/mounts/same/who.txt"],
                    "cwd": str(workspace_d),
                    "mounts": [
                        {"mountId": "same", "hostPath": str(mount_d), "mode": "ro"}
                    ],
                },
                deadline,
            )
            if read_c.get("state") != "queued" or read_d.get("state") != "queued":
                raise RuntimeError(f"a mount under a shared id was refused: {read_c} {read_d}")
            sidecar.await_exits(["C2", "D2"], deadline)
            if sidecar.stdout_of("C2") != b"from-c\n":
                raise RuntimeError(f"C read the wrong directory: {sidecar.stdout_of('C2')!r}")
            if sidecar.stdout_of("D2") != b"from-d\n":
                raise RuntimeError(
                    f"the second session with the same mount id read {sidecar.stdout_of('D2')!r}"
                )
            print("same mount id: each session reads its own directory")

            stage = "queue deadline and a mount applied in the idle gap"
            long_run = sidecar.ok(
                {
                    "id": 52,
                    "op": "exec",
                    "session": "A",
                    "execId": "A6",
                    "argv": ["sh", "-c", "sleep 4; echo A6"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if long_run.get("state") != "queued":
                raise RuntimeError(f"A6 was not accepted: {long_run}")
            parked = sidecar.ok(
                {
                    "id": 53,
                    "op": "exec",
                    "session": "A",
                    "execId": "A7",
                    "argv": ["sh", "-c", "echo A7-should-not-run"],
                    "cwd": str(workspace_a),
                    "queueDeadlineMs": 300,
                },
                deadline,
            )
            if parked.get("state") != "queued":
                raise RuntimeError(f"A7 was not accepted: {parked}")
            mount_b = root / "mount-b"
            mount_b.mkdir(exist_ok=True)
            (mount_b / "who.txt").write_bytes(b"from-b\n")
            # A mount must not be refused because another session is busy: it waits for the
            # dispatcher's idle gap instead. Refusing here would couple sessions that the
            # queue exists to keep apart.
            mounted = sidecar.ok(
                {
                    "id": 54,
                    "op": "exec",
                    "session": "B",
                    "execId": "B9",
                    "argv": ["sh", "-c", "cat /workspace/mounts/late/who.txt"],
                    "cwd": str(workspace_b),
                    "mounts": [
                        {"mountId": "late", "hostPath": str(mount_b), "mode": "ro"}
                    ],
                },
                deadline,
            )
            if mounted.get("state") != "queued":
                raise RuntimeError(f"a mount under load was not queued: {mounted}")
            exits = sidecar.await_exits(["A6", "A7", "B9"], deadline)
            if exits["A7"].get("outcome") != "timedOut":
                raise RuntimeError(f"a queued deadline did not expire: {exits['A7']}")
            if sidecar.stdout_of("A7"):
                raise RuntimeError("an expired queue entry still ran")
            if exits["A6"].get("outcome") != "exited":
                raise RuntimeError(f"the long run was disturbed: {exits['A6']}")
            if exits["B9"].get("outcome") != "exited" or sidecar.stdout_of("B9") != b"from-b\n":
                raise RuntimeError(
                    f"the deferred mount did not reach the guest: {exits['B9']} "
                    f"{sidecar.stdout_of('B9')!r}"
                )
            print("queue deadline expired; a mount requested under load ran in the idle gap")

            stage = "revoking a mount removes it from the guest"
            mount_e = root / "mount-e"
            mount_e.mkdir(exist_ok=True)
            (mount_e / "who.txt").write_bytes(b"from-e\n")
            sidecar.ok(
                {
                    "id": 130,
                    "op": "exec",
                    "session": "B",
                    "execId": "E1",
                    "argv": ["sh", "-c", "cat /workspace/mounts/gone/who.txt"],
                    "cwd": str(workspace_b),
                    "mounts": [
                        {"mountId": "gone", "hostPath": str(mount_e), "mode": "ro"}
                    ],
                },
                deadline,
            )
            sidecar.await_exits(["E1"], deadline)
            if sidecar.stdout_of("E1") != b"from-e\n":
                raise RuntimeError(f"the mount was not usable first: {sidecar.stdout_of('E1')!r}")
            # The next command drops it from the snapshot: the path must be gone from the guest,
            # not merely absent from the request. That is what "revoked" has to mean.
            sidecar.ok(
                {
                    "id": 131,
                    "op": "exec",
                    "session": "B",
                    "execId": "E2",
                    "argv": ["sh", "-c",
                             "test -e /workspace/mounts/gone/who.txt && echo STILL-THERE || echo GONE"],
                    "cwd": str(workspace_b),
                },
                deadline,
            )
            sidecar.await_exits(["E2"], deadline)
            if sidecar.stdout_of("E2") != b"GONE\n":
                raise RuntimeError(
                    f"a revoked mount is still visible in the guest: {sidecar.stdout_of('E2')!r}"
                )
            cleanup = sidecar.ok({"id": 132, "op": "diagnostics"}, deadline)
            if cleanup.get("cleanupPending") != 0:
                raise RuntimeError(
                    f"the revoked mount was not cleaned up: {cleanup.get('cleanupPending')}"
                )
            if (cleanup.get("vm") or {}).get("generation") != opened_a["vmGeneration"]:
                raise RuntimeError("revoking a mount replaced the VM")
            print("mount revocation: the path is gone from the guest, VM unchanged")

            stage = "closing a session revokes its workspace"
            # A marker the closed session could read: revocation has to make the *content*
            # unreachable. The empty mount-point directory stays behind by design (the guest
            # creates it before binding), so asserting on the directory would test the wrong
            # thing.
            (workspace_c / "marker.txt").write_bytes(b"secret\n")
            sidecar.ok(
                {
                    "id": 133,
                    "op": "exec",
                    "session": "C",
                    "execId": "C3",
                    "argv": ["sh", "-c", "cat /sessions/C/workspace/marker.txt"],
                    "cwd": str(workspace_c),
                },
                deadline,
            )
            sidecar.await_exits(["C3"], deadline)
            if sidecar.stdout_of("C3") != b"secret\n":
                raise RuntimeError("the marker was not readable before the close")
            sidecar.ok({"id": 134, "op": "session.close", "session": "C"}, deadline)
            sidecar.ok(
                {
                    "id": 135,
                    "op": "exec",
                    "session": "D",
                    "execId": "D3",
                    "argv": ["sh", "-c",
                             "cat /sessions/C/workspace/marker.txt 2>/dev/null "
                             "&& echo STILL-THERE || echo GONE"],
                    "cwd": str(workspace_d),
                },
                deadline,
            )
            sidecar.await_exits(["D3"], deadline)
            if sidecar.stdout_of("D3") != b"GONE\n":
                raise RuntimeError(
                    f"a closed session's workspace content is still reachable: "
                    f"{sidecar.stdout_of('D3')!r}"
                )
            after_close = sidecar.ok({"id": 136, "op": "diagnostics"}, deadline)
            if (after_close.get("vm") or {}).get("generation") != opened_a["vmGeneration"]:
                raise RuntimeError("closing one session replaced the shared VM")
            if after_close.get("sessionCount") != 3:
                raise RuntimeError(f"the closed session is still counted: {after_close}")
            print("session revocation: its workspace is gone, the VM keeps running")

            stage = "close one session while the other keeps working"
            b_long = sidecar.ok(
                {
                    "id": 40,
                    "op": "exec",
                    "session": "B",
                    "execId": "B2",
                    "argv": ["sh", "-c", "sleep 3; echo B2-done"],
                    "cwd": str(workspace_b),
                },
                deadline,
            )
            if b_long.get("state") != "queued":
                raise RuntimeError(f"B2 was not accepted: {b_long}")
            a_idle = sidecar.ok(
                {
                    "id": 41,
                    "op": "diagnostics",
                },
                deadline,
            )
            if len(a_idle.get("sessions") or []) != 3:
                raise RuntimeError(f"diagnostics did not show the expected sessions: {a_idle}")
            if a_idle.get("sessionCount") != 3:
                raise RuntimeError(f"the session count disagrees with the list: {a_idle}")
            busy_b = [
                entry for entry in a_idle["sessions"] if entry.get("session") == "B"
            ]
            if not busy_b or not busy_b[0].get("busy"):
                raise RuntimeError(
                    f"the session running a command is not visible as busy: {a_idle['sessions']}"
                )
            a_busy = sidecar.ok(
                {
                    "id": 42,
                    "op": "exec",
                    "session": "A",
                    "execId": "A5",
                    "argv": ["sh", "-c", "echo A5"],
                    "cwd": str(workspace_a),
                },
                deadline,
            )
            if a_busy.get("state") != "queued":
                raise RuntimeError(f"A5 was not queued behind B2: {a_busy}")
            closed = sidecar.ok(
                {"id": 43, "op": "session.close", "session": "A"}, deadline
            )
            if not closed.get("closed"):
                raise RuntimeError(f"closing A did not close it: {closed}")
            if closed.get("state") not in ("closed", "closing"):
                raise RuntimeError(f"unexpected close state: {closed}")
            exits = sidecar.await_exits(["A5", "B2"], deadline)
            if exits["A5"].get("outcome") != "cancelled":
                raise RuntimeError(f"A's queued work survived its close: {exits['A5']}")
            if exits["B2"].get("outcome") != "exited":
                raise RuntimeError(f"closing A broke B's work: {exits['B2']}")
            if sidecar.stdout_of("B2") != b"B2-done\n":
                raise RuntimeError(f"B2 output was wrong: {sidecar.stdout_of('B2')!r}")
            print("close A: A5 cancelled, B2 completed on the same VM")

            stage = "diagnostics after close"
            final = sidecar.ok({"id": 70, "op": "diagnostics"}, deadline)
            sessions = final.get("sessions") or []
            if sorted(entry.get("session") for entry in sessions) != ["B", "D"]:
                raise RuntimeError(f"the closed session is still listed: {sessions}")
            vm = final.get("vm") or {}
            if vm.get("generation") != opened_a["vmGeneration"]:
                raise RuntimeError(f"the VM was replaced by closing A: {final.get('vm')}")
            if vm.get("runtimeId") != opened_a["runtimeId"]:
                raise RuntimeError(f"the VM changed identity: {final.get('vm')}")
            if final.get("queued") != 0 or final.get("running") is not None:
                raise RuntimeError(f"the VM is not idle after the work finished: {final}")
            idle_sessions = sum(
                1 for entry in sessions if not entry.get("busy") and entry.get("execs") == 0
            )
            if idle_sessions != 2:
                raise RuntimeError(f"a session still owns work: {sessions}")
            print(
                f"diagnostics: sessions={len(sessions)} queued={final.get('queued')} "
                f"generation={vm.get('generation')}"
            )

            stage = "closing the last sessions retires the VM"
            for index, session in enumerate(("B", "D"), start=80):
                closed = sidecar.ok(
                    {"id": index, "op": "session.close", "session": session}, deadline
                )
                if not closed.get("closed"):
                    raise RuntimeError(f"closing {session} failed: {closed}")
            after = sidecar.ok({"id": 90, "op": "diagnostics"}, deadline)
            if after.get("vm") is not None:
                raise RuntimeError(f"the VM outlived its last session: {after.get('vm')}")
            if after.get("sessionCount") != 0:
                raise RuntimeError(f"a session outlived its close: {after}")
            print("genflow-nvxd shared-VM e2e passed")
        except Exception as error:
            for head, payload in sidecar.events:
                print(
                    "EVENT",
                    head.get("event"),
                    head.get("execId") or head.get("handle"),
                    head.get("session"),
                    repr(payload[:80]),
                )
            for line in log[-25:]:
                print("SIDECAR:", line)
            raise RuntimeError(f"stage {stage}: {error}") from error
        finally:
            watchdog.cancel()
            try:
                send_frame(process.stdin, {"op": "shutdown"})
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if process.returncode != 0:
                raise RuntimeError(
                    f"sidecar exited with {process.returncode}: {' | '.join(log[-15:])}"
                )
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"genflow-nvxd shared-VM e2e failed: {error!r}")
