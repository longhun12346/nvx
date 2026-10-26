"""P5 fault cases: the sidecar must not leak a VM when its caller disappears or repeats itself.

Two things are asserted, both of which are cheap to get wrong and expensive in production:

* **Closing twice is idempotent.** A caller whose close reply was lost repeats the request; it
  must learn "the session is closed", not an error that says nothing about whether it ever
  existed.
* **A caller that disconnects mid-command does not leave a VM behind.** The sidecar owes the
  host a stopped VM and a clean exit even when nobody is listening any more.

Run with the same three inputs as `e2e.py`; the last check (no leftover VMM) is done by the
caller, because counting another process's children is not portable from here.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import subprocess
import tempfile
import time

from p8_support import vmm_processes


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


def start(nvxd, repo, initrd, state):
    process = subprocess.Popen(
        [
            str(nvxd), "--hypervisor", "whp", "--repo", str(repo),
            "--initrd", str(initrd), "--cpu-profile", "host", "--state-dir", str(state),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    ready = read_frame(process.stdout)
    if ready is None or ready[0].get("event") != "ready":
        raise RuntimeError(f"the sidecar did not announce itself: {ready}")
    return process


def request(process, body, expect=60):
    send_frame(process.stdin, body)
    deadline = time.monotonic() + expect
    while time.monotonic() < deadline:
        frame = read_frame(process.stdout)
        if frame is None:
            raise RuntimeError(f"{body.get('op')}: the sidecar closed the stream")
        head, _ = frame
        if "event" in head:
            continue
        if head.get("id") == body.get("id"):
            return head
    raise RuntimeError(f"{body.get('op')}: no reply within {expect}s")


def case_duplicate_close(nvxd, repo, initrd, root):
    process = start(nvxd, repo, initrd, root / "state-close")
    try:
        workspace = root / "ws-close"
        workspace.mkdir(exist_ok=True)
        opened = request(process, {
            "id": 1, "op": "session.open", "session": "S",
            "workspace": str(workspace), "memoryMiB": 1024,
        }, 180)
        if not opened.get("ok"):
            raise RuntimeError(f"the session did not open: {opened}")
        first = request(process, {"id": 2, "op": "session.close", "session": "S"}, 120)
        second = request(process, {"id": 3, "op": "session.close", "session": "S"}, 120)
        if not first.get("ok") or not second.get("ok"):
            raise RuntimeError(f"a repeated close was refused: {first} {second}")
        if not second.get("alreadyClosed"):
            raise RuntimeError(f"the repeated close was not reported as a repeat: {second}")
        print("duplicate close: idempotent")
    finally:
        try:
            send_frame(process.stdin, {"op": "shutdown"})
            process.stdin.close()
        except OSError:
            pass
        process.wait(timeout=90)


def case_disconnect_while_running(nvxd, repo, initrd, root):
    process = start(nvxd, repo, initrd, root / "state-drop")
    workspace = root / "ws-drop"
    workspace.mkdir(exist_ok=True)
    opened = request(process, {
        "id": 1, "op": "session.open", "session": "S",
        "workspace": str(workspace), "memoryMiB": 1024,
    }, 180)
    if not opened.get("ok"):
        raise RuntimeError(f"the session did not open: {opened}")
    request(process, {
        "id": 2, "op": "exec", "session": "S", "execId": "LONG",
        "argv": ["sh", "-c", "sleep 30; echo late"],
    }, 120)
    # Walk away mid-command, exactly as a crashed host would.
    try:
        process.stdin.close()
    except OSError:
        pass
    started = time.monotonic()
    try:
        process.wait(timeout=90)
    except subprocess.TimeoutExpired:
        process.kill()
        raise RuntimeError("the sidecar outlived its caller")
    elapsed = time.monotonic() - started
    if process.returncode != 0:
        detail = process.stderr.read().decode(errors="replace")[-400:]
        raise RuntimeError(f"the sidecar exited with {process.returncode}: {detail}")
    # Nobody can receive the command's output any more, so shutdown must not wait for it: the
    # 30 s task is the clock this assertion is about. Waiting for it is how a crashed caller
    # used to keep the VM (and the host's memory) alive for as long as its command ran.
    if elapsed > 10:
        raise RuntimeError(
            f"the sidecar took {elapsed:.1f}s to exit while a 30s command was running"
        )
    print(f"disconnect while running: clean exit in {elapsed:.1f}s")


def case_burst_while_booting(nvxd, repo, initrd, root):
    """A burst that arrives while a session is still booting must be refused, not queued forever.

    The work queue is bounded on purpose: the caller is told to retry instead of the sidecar
    growing a thread (and a handle) per message. Every request must be answered, and a refused
    one must carry a code that says "not now", never a handle that would make it look accepted.
    """
    process = subprocess.Popen(
        [
            str(nvxd), "--hypervisor", "whp", "--repo", str(repo),
            "--initrd", str(initrd), "--cpu-profile", "host",
            "--max-pending", "2", "--work-workers", "1",
            "--state-dir", str(root / "state-burst"),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        if read_frame(process.stdout) is None:
            raise RuntimeError("the sidecar did not announce itself")
        workspace = root / "ws-burst"
        workspace.mkdir(exist_ok=True)
        # The open blocks the only work worker while the VM boots, so the rest of the burst
        # meets a full queue.
        send_frame(process.stdin, {
            "id": 1, "op": "session.open", "session": "S",
            "workspace": str(workspace), "memoryMiB": 1024,
        })
        for index in range(16):
            send_frame(process.stdin, {
                "id": 100 + index, "op": "exec", "session": "S",
                "execId": f"B{index}", "argv": ["sh", "-c", f"echo {index}"],
            })
        answers = {}
        deadline = time.monotonic() + 240
        while len(answers) < 17 and time.monotonic() < deadline:
            frame = read_frame(process.stdout)
            if frame is None:
                raise RuntimeError("the sidecar closed the stream during the burst")
            head, _ = frame
            if "event" in head:
                continue
            answers[head.get("id")] = head
        if len(answers) != 17:
            raise RuntimeError(f"only {len(answers)} of 17 requests were answered")
        refused = [
            head for head in answers.values()
            if head.get("reasonCode") == "E_BACKEND_OVERLOAD"
        ]
        if not refused:
            raise RuntimeError("the burst was never refused: nothing bounded the queue")
        for head in refused:
            if head.get("ok") or head.get("handle") or head.get("execId"):
                raise RuntimeError(f"a refused request looked accepted: {head}")
        opened = answers.get(1, {})
        if not opened.get("ok"):
            raise RuntimeError(f"the session did not open: {opened}")
        print(f"burst while booting: {len(refused)} of 16 refused with E_BACKEND_OVERLOAD")
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


def case_vm_lost(nvxd, repo, initrd, root):
    """Killing the VMM must end the work visibly and let the next session rebuild.

    The failure that matters here is not the crash itself but what is left behind: a VM that
    still looks present makes the next `session.open` export into a corpse, burn the export
    timeout and report the problem as a mount failure.
    """
    process = start(nvxd, repo, initrd, root / "state-lost")
    try:
        workspace = root / "ws-lost"
        workspace.mkdir(exist_ok=True)
        opened = request(process, {
            "id": 1, "op": "session.open", "session": "S",
            "workspace": str(workspace), "memoryMiB": 1024,
        }, 180)
        if not opened.get("ok"):
            raise RuntimeError(f"the session did not open: {opened}")
        first_generation = opened.get("vmGeneration")
        request(process, {
            "id": 2, "op": "exec", "session": "S", "execId": "LONG",
            "argv": ["sh", "-c", "sleep 60; echo late"],
        }, 60)
        time.sleep(1.5)
        handles = vmm_processes(process.pid)
        try:
            for handle in handles:
                handle.kill()
                handle.wait()
        finally:
            for handle in handles:
                handle.close()
        deadline = time.monotonic() + 60
        terminal = None
        while time.monotonic() < deadline:
            frame = read_frame(process.stdout)
            if frame is None:
                raise RuntimeError("the sidecar closed the stream after the VM died")
            head, _ = frame
            if head.get("event") == "exec.exit" and head.get("execId") == "LONG":
                terminal = head
                break
        if terminal is None:
            raise RuntimeError("a command on a dead VM never reached a terminal state")
        if terminal.get("outcome") not in ("failed", "signalled"):
            raise RuntimeError(f"unexpected terminal state: {terminal}")
        print(f"vm killed: the running command ended {terminal.get('outcome')}")

        # The dead VM must not stay admissible: reopening has to boot a new instance, not
        # export into the one that is gone.
        reopened = request(process, {
            "id": 3, "op": "session.open", "session": "T",
            "workspace": str(workspace), "memoryMiB": 1024,
        }, 120)
        if not reopened.get("ok"):
            raise RuntimeError(f"the VM was not rebuilt after the crash: {reopened}")
        if reopened.get("vmGeneration") == first_generation:
            raise RuntimeError(
                f"the old generation was reused after the crash: {reopened}"
            )
        print(f"vm lost: rebuilt as generation {reopened.get('vmGeneration')}")
        ran = request(process, {
            "id": 4, "op": "exec", "session": "T", "execId": "AFTER",
            "argv": ["sh", "-c", "echo alive"],
        }, 60)
        if not ran.get("ok"):
            raise RuntimeError(f"the rebuilt VM refused work: {ran}")
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


def case_guest_oom(nvxd, repo, initrd, root):
    """Exhausting guest memory must end the command, not wedge the VM.

    P5 does not promise that an OOM only kills one session (there are no per-exec limits yet),
    but it does promise the failure is observable and that the VM stays either usable or
    rebuildable. In practice the guest OOM killer takes the workload process, so this asserts
    the strict half: a terminal state arrives, and the same VM still runs the next command.
    """
    process = start(nvxd, repo, initrd, root / "state-oom")
    try:
        workspace = root / "ws-oom"
        workspace.mkdir(exist_ok=True)
        opened = request(process, {
            "id": 1, "op": "session.open", "session": "S",
            "workspace": str(workspace), "memoryMiB": 1024,
        }, 180)
        if not opened.get("ok"):
            raise RuntimeError(f"the session did not open: {opened}")
        request(process, {
            "id": 2, "op": "exec", "session": "S", "execId": "HOG",
            "argv": ["python3", "-c",
                     "b=[]\nfor i in range(8):\n b.append(bytearray(256<<20))\nprint('survived')"],
            "timeoutMs": 90000,
        }, 120)
        deadline = time.monotonic() + 180
        terminal = None
        while time.monotonic() < deadline:
            frame = read_frame(process.stdout)
            if frame is None:
                raise RuntimeError("the sidecar closed the stream during the OOM")
            head, _ = frame
            if head.get("event") == "exec.exit" and head.get("execId") == "HOG":
                terminal = head
                break
        if terminal is None:
            raise RuntimeError("an out-of-memory command never reached a terminal state")
        if terminal.get("outcome") not in ("signaled", "failed"):
            raise RuntimeError(f"an OOM command reported {terminal.get('outcome')}")
        print(
            f"guest oom: command ended {terminal.get('outcome')} "
            f"code={terminal.get('code')}"
        )
        # Whatever the guest killed, the VM must not be left half-alive: the next command has
        # to run (or the VM has to be reported gone and rebuilt, which `case_vm_lost` covers).
        after = request(process, {
            "id": 3, "op": "exec", "session": "S", "execId": "AFTER",
            "argv": ["sh", "-c", "echo still-alive"],
        }, 120)
        if not after.get("ok"):
            raise RuntimeError(f"the VM stopped accepting work after an OOM: {after}")
        print("guest oom: the VM still runs work afterwards")
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


def case_stalled_reader(nvxd, repo, initrd, root):
    """A caller that stops reading must cost bounded memory, and must not wedge the sidecar.

    The outbound queue is deliberately tiny here so the property is reachable in a test: with
    a command producing output nobody reads, frames are refused, the counters say so, and once
    the caller reads again the control plane still answers.
    """
    process = subprocess.Popen(
        [
            str(nvxd), "--hypervisor", "whp", "--repo", str(repo),
            "--initrd", str(initrd), "--cpu-profile", "host",
            "--outbound-capacity", "4", "--state-dir", str(root / "state-stall"),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        if read_frame(process.stdout) is None:
            raise RuntimeError("the sidecar did not announce itself")
        workspace = root / "ws-stall"
        workspace.mkdir(exist_ok=True)
        send_frame(process.stdin, {
            "id": 1, "op": "session.open", "session": "S",
            "workspace": str(workspace), "memoryMiB": 1024,
        })
        opened = None
        while opened is None:
            frame = read_frame(process.stdout)
            if frame is None:
                raise RuntimeError("the sidecar closed the stream while opening")
            if frame[0].get("id") == 1:
                opened = frame[0]
        if not opened.get("ok"):
            raise RuntimeError(f"the session did not open: {opened}")

        # Produce far more output than the queue (and the OS pipe buffer) can absorb, then read
        # nothing: 8 MiB is well past both, so the bounded path is actually exercised.
        send_frame(process.stdin, {
            "id": 2, "op": "exec", "session": "S", "execId": "CHATTY",
            "argv": ["python3", "-c",
                     "import sys\nchunk='x'*32768\nfor _ in range(256): sys.stdout.write(chunk)\nsys.stdout.flush()"],
        })
        time.sleep(3)
        # Reading resumes: whatever was dropped, the sidecar must still be here and answering.
        send_frame(process.stdin, {"id": 3, "op": "diagnostics"})
        deadline = time.monotonic() + 120
        diagnostics = None
        while time.monotonic() < deadline:
            frame = read_frame(process.stdout)
            if frame is None:
                raise RuntimeError("the sidecar died while its reader was stalled")
            head, _ = frame
            if head.get("id") == 3:
                diagnostics = head
                break
        if diagnostics is None:
            raise RuntimeError("the sidecar stopped answering after a stalled reader")
        if not diagnostics.get("ok"):
            raise RuntimeError(f"diagnostics was refused: {diagnostics}")
        outbound = diagnostics.get("outbound") or {}
        print(
            f"stalled reader: frames={outbound.get('frames')} "
            f"refused={outbound.get('refused')} broken={outbound.get('broken')}"
        )
        if not outbound.get("refused"):
            raise RuntimeError(
                "a stalled reader cost nothing: the queue was never refused"
            )
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    for path, label in (
        (args.nvxd, "sidecar"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")
    root = pathlib.Path(tempfile.mkdtemp(prefix="nvxd-faults-"))
    case_duplicate_close(args.nvxd, args.repo, args.initrd, root)
    case_disconnect_while_running(args.nvxd, args.repo, args.initrd, root)
    case_burst_while_booting(args.nvxd, args.repo, args.initrd, root)
    case_vm_lost(args.nvxd, args.repo, args.initrd, root)
    case_guest_oom(args.nvxd, args.repo, args.initrd, root)
    case_stalled_reader(args.nvxd, args.repo, args.initrd, root)
    print("CASE p8.regression.fault_matrix PASS", flush=True)
    print("nvxd fault cases passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"nvxd faults failed: {error!r}")
