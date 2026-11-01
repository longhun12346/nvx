"""Backpressure check of the scaffold sidecar: a caller that does not read for 6 s still receives all
64 MiB of a command's output afterwards, and diagnostics answer while the output is held back.
Arguments: --nvxd, --artifacts, --guest-agent as for scaffold_e2e.py."""
import argparse, os, pathlib, sys, tempfile, subprocess, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scaffold_e2e as e

parser = argparse.ArgumentParser()
parser.add_argument("--nvxd", required=True)
parser.add_argument("--artifacts", required=True)
parser.add_argument("--guest-agent", required=True)
args = parser.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix="stall-"))
p = subprocess.Popen([args.nvxd, "--artifacts", args.artifacts, "--guest-agent", args.guest_agent, "--cpu-profile", "host", "--outbound-capacity", "4", "--state-dir", str(root / "s")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
e.read_frame(p.stdout)
(root / "w").mkdir()
def call(i, **f):
    e.send_frame(p.stdin, {"id": i, **f})
    while True:
        h, _ = e.read_frame(p.stdout)
        if h.get("id") == i: return h
print("probe", call(1, op="probe").get("ok"))
print("open", call(2, op="session.open", session="S", workspace=str(root/"w"), memoryMiB=1024).get("ok"))
e.send_frame(p.stdin, {"id": 3, "op": "exec", "session": "S", "execId": "BIG", "argv": ["sh", "-c", "yes | head -c 67108864"]})
time.sleep(6)   # the caller is not reading
e.send_frame(p.stdin, {"id": 4, "op": "diagnostics"})
t = time.monotonic(); total = 0; exit_event = None; diag = None
while exit_event is None:
    h, payload = e.read_frame(p.stdout)
    if h.get("event") == "exec.stdout": total += len(payload)
    elif h.get("event") == "exec.exit": exit_event = h
    elif h.get("id") == 4: diag = h
print("after the stall: received", total, "of 67108864 bytes in %.2f s;" % (time.monotonic() - t), "exit", exit_event["outcome"], exit_event["code"], "truncated", exit_event["truncated"])
print("diagnostics answered while stalled:", diag is not None, (diag or {}).get("outbound"))
e.send_frame(p.stdin, {"op": "shutdown"}); p.stdin.close(); p.wait(60)
