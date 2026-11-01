"""End-to-end check of the scaffold sidecar: probe, session.open, large output, a failing command,
session.close, shutdown. Prints the timings next to the old baselines.

    python scaffold_e2e.py --nvxd nvxd.exe --artifacts DIR --guest-agent nvxd-guest
"""

import argparse
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import threading
import time


def read_frame(stream):
    header = stream.read(8)
    if len(header) != 8:
        return None
    json_size, payload_size = struct.unpack("<II", header)
    return json.loads(stream.read(json_size)), stream.read(payload_size)


def send_frame(stream, body):
    encoded = json.dumps(body, separators=(",", ":")).encode()
    stream.write(struct.pack("<II", len(encoded), 0) + encoded)
    stream.flush()


class Sidecar:
    def __init__(self, process):
        self.process = process
        self.replies = {}
        self.exits = {}
        self.output = {}
        self.lock = threading.Condition()
        self.next_id = 0
        self.dead = False
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            frame = read_frame(self.process.stdout)
            if frame is None:
                break
            head, payload = frame
            with self.lock:
                if "id" in head:
                    self.replies[head["id"]] = head
                elif head.get("event") == "exec.exit":
                    self.exits[head["execId"]] = head
                elif head.get("event") in ("exec.stdout", "exec.stderr"):
                    key = (head["execId"], head["event"])
                    self.output[key] = self.output.get(key, 0) + len(payload)
                self.lock.notify_all()
        with self.lock:
            self.dead = True
            self.lock.notify_all()

    def call(self, op, timeout=180, **fields):
        self.next_id += 1
        request_id = self.next_id
        send_frame(self.process.stdin, {"id": request_id, "op": op, **fields})
        end = time.monotonic() + timeout
        with self.lock:
            while request_id not in self.replies:
                if self.dead or time.monotonic() > end:
                    raise RuntimeError(f"{op}: no reply")
                self.lock.wait(0.2)
            return self.replies.pop(request_id)

    def wait_exit(self, exec_id, timeout=120):
        end = time.monotonic() + timeout
        with self.lock:
            while exec_id not in self.exits:
                if self.dead or time.monotonic() > end:
                    raise RuntimeError(f"{exec_id}: no exit")
                self.lock.wait(0.2)
            return self.exits[exec_id]


def timed(label, function, results):
    start = time.monotonic()
    value = function()
    results[label] = time.monotonic() - start
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--artifacts", required=True, type=pathlib.Path)
    parser.add_argument("--guest-agent", required=True, type=pathlib.Path)
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args()
    state = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-scaffold-"))
    command = [
        str(args.nvxd), "--artifacts", str(args.artifacts), "--guest-agent", str(args.guest_agent),
        "--cpu-profile", "host", "--state-dir", str(state / "state"),
    ]
    if args.no_cache:
        command += ["--capability-cache", "none"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threading.Thread(target=lambda: [None for _ in process.stderr], daemon=True).start()
    ready = read_frame(process.stdout)
    assert ready and ready[0].get("event") == "ready", ready
    sidecar = Sidecar(process)
    times = {}
    workspace = state / "ws"
    workspace.mkdir()
    probe = timed("probe", lambda: sidecar.call("probe"), times)
    assert probe.get("ok"), probe
    opened = timed("session.open", lambda: sidecar.call("session.open", session="S", workspace=str(workspace), memoryMiB=1024), times)
    assert opened.get("ok"), opened

    def run(exec_id, argv):
        started = sidecar.call("exec", session="S", execId=exec_id, argv=argv)
        assert started.get("ok"), started
        return sidecar.wait_exit(exec_id)

    quick = timed("exec true", lambda: run("E1", ["true"]), times)
    assert quick["outcome"] == "exited" and quick["code"] == 0, quick
    big = timed("exec 3 MiB stdout", lambda: run("E2", ["sh", "-c", "head -c 3145728 /dev/zero | tr '\\000' x"]), times)
    got = sidecar.output.get(("E2", "exec.stdout"), 0)
    assert big["outcome"] == "exited" and big["code"] == 0, big
    assert got == 3145728, f"3 MiB expected, got {got} bytes"
    failing = timed("exec exit 7", lambda: run("E3", ["sh", "-c", "echo oops >&2; exit 7"]), times)
    assert failing["outcome"] == "exited" and failing["code"] == 7, failing
    assert sidecar.output.get(("E3", "exec.stderr"), 0) == 5, sidecar.output
    unsupported = sidecar.call("port.allocate")
    assert not unsupported.get("ok") and unsupported["reasonCode"] in ("E_NVX_NOT_YET_SUPPORTED", "E_NVX_INBOUND_DISABLED"), unsupported
    closed = timed("session.close", lambda: sidecar.call("session.close", session="S"), times)
    assert closed.get("ok"), closed
    send_frame(process.stdin, {"op": "shutdown"})
    process.stdin.close()
    process.wait(timeout=60)
    baselines = {"session.open": 0.19, "exec true": 0.08, "session.close": 0.14}
    for label, seconds in times.items():
        note = f"  (old baseline {baselines[label]:.2f} s)" if label in baselines else ""
        print(f"{label:>20}: {seconds:7.2f} s{note}")
    print("3 MiB stdout received:", got, "bytes; exit codes ok; sidecar exit:", process.returncode)
    print("scaffold e2e passed")


if __name__ == "__main__":
    sys.exit(main())
